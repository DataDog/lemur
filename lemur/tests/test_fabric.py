import sys
from types import ModuleType
from unittest.mock import Mock, patch

import grpc
import pytest
from google.protobuf import json_format

from lemur.sources import fabric


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("DD_DATACENTER", "us1.staging.dog")
    auth = ModuleType("dd_internal_authentication.client")
    auth.JWTInternalServiceAuthClientTokenManager = Mock()
    auth.JWTInternalServiceAuthClientTokenManager.return_value.get_token.return_value = (
        "test-token"
    )
    monkeypatch.setitem(sys.modules, "dd_internal_authentication.client", auth)
    with patch.object(fabric.grpc, "secure_channel") as connect:
        channel = connect.return_value.__enter__.return_value
        request_type, response_type = fabric._messages()
        response = json_format.ParseDict(
            {
                "objects": {
                    "test-zone": {
                        "objects": [
                            {
                                "envoyRouteConfiguration": {
                                    "spec": {
                                        "virtualHosts": [
                                            {
                                                "domains": ["envoy.us1.staging.dog"],
                                            }
                                        ]
                                    }
                                },
                            }
                        ]
                    }
                },
            },
            response_type(),
        )
        channel.unary_unary.return_value.return_value = response
        yield auth.JWTInternalServiceAuthClientTokenManager, connect, channel


def test_cross_dc_read_uses_gateway(client):
    manager, connect, channel = client
    with patch.object(fabric, "_direct_credentials") as direct:
        inventory = fabric.read_routes("eu1.staging.dog")
    direct.assert_not_called()
    assert connect.call_args.args[0] == (
        "source-crossdc-gateway.service-discovery.all-clusters.local-dc.fabric.dog:8081"
    )
    manager.assert_called_once_with(issuer="sycamore", timeout=10)
    manager.return_value.get_token.assert_called_once_with("service-discovery")
    assert channel.unary_unary.call_args.args == (
        "/fabric.api.v1.FabricManagement/ListObjects",
    )
    call = channel.unary_unary.return_value.call_args
    assert json_format.MessageToDict(call.args[0]) == {
        "type": "envoy_route_configuration",
        "id": {"namespace": "fabric-gateway", "name": "internal-services-proxy"},
    }
    assert call.kwargs == {
        "timeout": 30,
        "metadata": [
            (
                "fabric-destination-fqdn",
                "fabric-management.service-discovery.all.eu1.staging.dog.fabric.dog",
            ),
            ("authorization", "Bearer test-token"),
        ],
    }
    # Exercise the actual bundled wire schema, not mocked protobuf classes.
    wire = channel.unary_unary.call_args.kwargs
    request_type, _ = fabric._messages()
    assert (
        request_type.FromString(wire["request_serializer"](call.args[0]))
        == call.args[0]
    )
    response = channel.unary_unary.return_value.return_value
    assert wire["response_deserializer"](response.SerializeToString()) == response
    assert inventory["objects"]["test-zone"]["objects"][0]["envoyRouteConfiguration"]
    connect.return_value.__exit__.assert_called_once()


def test_local_read_uses_mtls_and_closes_channel(client):
    _, connect, channel = client
    sentinel = object()
    with patch.object(fabric, "_direct_credentials", return_value=sentinel) as tls:
        fabric.read_routes("us1.staging.dog")
        fabric.read_routes("us1.staging.dog")
    assert tls.call_count == 2
    assert connect.call_args.args == (
        "fabric-management.service-discovery.all-clusters.local-dc.fabric.dog:8443",
        sentinel,
    )
    assert channel.unary_unary.return_value.call_args.kwargs["metadata"] == [
        ("authorization", "Bearer test-token")
    ]
    assert connect.return_value.__exit__.call_count == 2


def test_missing_datacenter_fails_before_connecting(client, monkeypatch):
    _, connect, _ = client
    monkeypatch.delenv("DD_DATACENTER")
    with pytest.raises(fabric.FabricError, match="requires DD_DATACENTER"):
        fabric.read_routes("us1.staging.dog")
    connect.assert_not_called()


def test_auth_failure_is_redacted(client):
    manager, connect, _ = client
    manager.return_value.get_token.side_effect = RuntimeError("secret-token")
    with pytest.raises(fabric.FabricError) as error:
        fabric.read_routes("eu1.staging.dog")
    assert "secret-token" not in str(error.value)
    connect.assert_not_called()


@pytest.mark.parametrize(
    "status", [grpc.StatusCode.PERMISSION_DENIED, grpc.StatusCode.DEADLINE_EXCEEDED]
)
def test_rpc_failure_closes_channel_and_reports_only_status(client, status):
    _, connect, channel = client
    error = grpc.RpcError("secret response")
    error.code = lambda: status
    channel.unary_unary.return_value.side_effect = error
    with pytest.raises(fabric.FabricError, match=status.name) as failure:
        fabric.read_routes("eu1.staging.dog")
    assert "secret response" not in str(failure.value)
    connect.return_value.__exit__.assert_called_once()


def test_direct_credentials_use_configured_files_and_reload(tmp_path, monkeypatch):
    for env, value in (
        ("GRPC_CLIENT_KEY_PATH", b"key"),
        ("GRPC_CLIENT_CERT_PATH", b"cert"),
        ("GRPC_SERVER_CA_PATH", b"ca"),
    ):
        path = tmp_path / env
        path.write_bytes(value)
        monkeypatch.setenv(env, str(path))
    with patch.object(fabric.grpc, "ssl_channel_credentials") as tls:
        fabric._direct_credentials()
        tls.assert_called_with(
            root_certificates=b"ca", private_key=b"key", certificate_chain=b"cert"
        )
        (tmp_path / "GRPC_CLIENT_CERT_PATH").write_bytes(b"rotated")
        fabric._direct_credentials()
        assert tls.call_args.kwargs["certificate_chain"] == b"rotated"


@pytest.mark.parametrize("contents", [None, b""])
def test_missing_or_empty_credentials_never_fall_back(
    client, tmp_path, monkeypatch, contents
):
    _, connect, _ = client
    path = tmp_path / "key.pem"
    if contents is not None:
        path.write_bytes(contents)
    monkeypatch.setenv("GRPC_CLIENT_KEY_PATH", str(path))
    for env in ("GRPC_CLIENT_CERT_PATH", "GRPC_SERVER_CA_PATH"):
        other = tmp_path / env
        other.write_bytes(b"present")
        monkeypatch.setenv(env, str(other))
    with pytest.raises(fabric.FabricError, match="Emissary TLS credentials"):
        fabric.read_routes("us1.staging.dog")
    connect.assert_not_called()
