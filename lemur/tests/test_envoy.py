import base64
import copy
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask

from lemur.sources import envoy, service
from lemur.deployment import service as deployment
from lemur.certificates import cli, service as certificates
from lemur.plugins.lemur_fabric.plugin import FabricSourcePlugin


@pytest.fixture
def context():
    with Flask(__name__).app_context() as ctx:
        yield ctx.app


@pytest.fixture
def source():
    return SimpleNamespace(
        label="test-fabric",
        plugin_name="fabric-source",
        options=[
            {"name": "datacenter", "value": "us1.staging.dog"},
            {"name": "namespace", "value": "edge-backend"},
        ],
    )


@pytest.fixture
def proxy():
    return {
        "name": "isp",
        "url": "https://envoy.test:8086",
    }


@pytest.fixture
def snapshot():
    tls = {
        "transport_socket": {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
                "common_tls_context": {
                    "tls_certificate_sds_secret_configs": [
                        {"name": "rsa"},
                        {"name": "ecc"},
                    ]
                }
            },
        }
    }
    listeners = [
        {
            "@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump.DynamicListener",
            "active_state": {
                "listener": {
                    "name": "public",
                    "address": {
                        "socket_address": {"address": "127.0.0.1", "port_value": 443}
                    },
                    "filter_chains": [tls],
                }
            },
        }
    ]
    secrets = [
        {
            "@type": "type.googleapis.com/envoy.admin.v3.SecretsConfigDump.DynamicSecret",
            "name": name,
        }
        for name in ("rsa", "ecc")
    ]
    return listeners, secrets


def test_associations_and_stable_source_scoped_identity(source, proxy, snapshot):
    listeners, secrets = snapshot

    def resolve(item):
        return item["name"]

    endpoint = envoy._parse(source, proxy, listeners, secrets, resolve)[0]
    assert endpoint["type"] == "fabric-envoy"
    assert endpoint["registry_type"] == "fabric-envoy"
    assert endpoint["name"].startswith("fabric-envoy:")
    assert endpoint["primary_certificate"] == {"certificate": "rsa", "path": ""}
    assert endpoint["sni_certificates"] == [{"certificate": "ecc", "path": ""}]
    assert len(endpoint["name"]) <= 128
    source.label = "other-source"
    assert (
        envoy._parse(source, proxy, listeners, secrets, resolve)[0]["name"]
        != endpoint["name"]
    )
    source.label = "test-fabric"
    proxy["name"] = "replica-2"
    assert (
        envoy._parse(source, proxy, listeners, secrets, resolve)[0]["name"]
        != endpoint["name"]
    )


def test_filter_chains_are_separate(source, proxy, snapshot):
    listeners, secrets = snapshot
    chains = listeners[0]["active_state"]["listener"]["filter_chains"]
    chains.append(copy.deepcopy(chains[0]))
    chains[1]["filter_chain_match"] = {"server_names": ["other.test"]}
    endpoints = envoy._parse(source, proxy, listeners, secrets, lambda s: s["name"])
    assert len({e["name"] for e in endpoints}) == 2


def test_endpoint_name_fits_database_column(source, proxy, snapshot):
    proxy["name"] = "long-admin-destination-" * 10
    endpoint = envoy._parse(source, proxy, *snapshot, lambda s: s["name"])[0]
    assert endpoint["name"].startswith("fabric-envoy:")
    assert len(endpoint["name"]) == 128


@pytest.mark.parametrize(
    "damage", ["warming", "missing_secret", "empty", "inline", "ambiguous"]
)
def test_incomplete_discovery_fails(source, proxy, snapshot, damage):
    listeners, secrets = snapshot
    if damage == "warming":
        listeners[0]["warming_state"] = listeners[0].pop("active_state")
    elif damage == "missing_secret":
        secrets.pop()
    elif damage == "empty":
        listeners.clear()
    elif damage == "inline":
        listeners[0]["active_state"]["listener"]["filter_chains"][0][
            "transport_socket"
        ]["typed_config"]["common_tls_context"]["tls_certificates"] = [{}]
    else:
        chains = listeners[0]["active_state"]["listener"]["filter_chains"]
        chains.append(copy.deepcopy(chains[0]))
    with pytest.raises(envoy.DiscoveryError):
        envoy._parse(source, proxy, listeners, secrets, lambda s: s["name"])


def make_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "same.test")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(42)
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=1))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )


@pytest.mark.parametrize("encoding", ["inline_string", "inline_bytes"])
def test_exact_fingerprint_not_serial_or_name(encoding):
    pem = make_certificate()
    right = SimpleNamespace(body=pem, name="right")
    wrong = SimpleNamespace(body=make_certificate(), name="wrong")
    value = (
        pem if encoding == "inline_string" else base64.b64encode(pem.encode()).decode()
    )
    secret = {"secret": {"tls_certificate": {"certificate_chain": {encoding: value}}}}
    with patch.object(
        certificates, "get_by_serial", return_value=[wrong, right]
    ) as lookup:
        assert envoy._resolve(secret) is right
        lookup.assert_called_once_with("42")
    with patch.object(certificates, "get_by_serial", return_value=[wrong]):
        assert envoy._resolve(secret) is None
    for candidates in ([right, right],):
        with patch.object(certificates, "get_by_serial", return_value=candidates):
            with pytest.raises(envoy.DiscoveryError):
                envoy._resolve(secret)


def test_file_reference_is_not_mistaken_for_certificate():
    with pytest.raises(envoy.DiscoveryError):
        envoy._leaf(
            {
                "secret": {
                    "tls_certificate": {"certificate_chain": {"filename": "/cert.pem"}}
                }
            }
        )


def config_dump(snapshot):
    listeners, secrets = copy.deepcopy(snapshot)
    for item in listeners + secrets:
        item.pop("@type", None)
    return {
        "configs": [
            {
                "@type": "type.googleapis.com/envoy.admin.v3.ListenersConfigDump",
                "dynamic_listeners": listeners,
            },
            {
                "@type": "type.googleapis.com/envoy.admin.v3.SecretsConfigDump",
                "dynamic_active_secrets": secrets,
            },
        ]
    }


def test_http_get_only_and_no_redirects(proxy, snapshot):
    session = Mock()
    session.get.return_value.status_code = 200
    session.get.return_value.json.return_value = config_dump(snapshot)
    listeners, secrets = envoy._read(session, proxy)
    assert len(listeners) == 1
    assert len(secrets) == 2
    session.get.assert_called_once()
    assert "params" not in session.get.call_args.kwargs
    assert session.get.call_args.kwargs["allow_redirects"] is False
    assert session.get.call_args.kwargs["verify"] is True
    session.get.return_value.status_code = 302
    with pytest.raises(envoy.DiscoveryError):
        envoy._read(session, proxy)


def test_failure_before_writes(context, source, proxy):
    with patch.object(
        envoy, "get_endpoints", side_effect=envoy.DiscoveryError("failed")
    ), patch.object(service.endpoint_service, "create") as create, patch.object(
        service.endpoint_service, "update"
    ) as update:
        with pytest.raises(envoy.DiscoveryError):
            service.sync_endpoints(source)
        create.assert_not_called()
        update.assert_not_called()


def test_sync_uses_source_identity(context, source, proxy, snapshot):
    endpoints = envoy._parse(source, proxy, *snapshot, lambda s: s["name"])
    with patch.object(envoy, "get_endpoints", return_value=endpoints), patch.object(
        service.endpoint_service, "get_by_name_and_source", return_value=None
    ) as lookup, patch.object(
        service.endpoint_service, "get_or_create_policy"
    ), patch.object(
        service.endpoint_service, "create"
    ) as create:
        assert service.sync_endpoints(source) == (1, 0, 0)
        lookup.assert_called_once_with(endpoints[0]["name"], source.label)
        assert create.call_args.kwargs["primary_certificate"]["certificate"] == "rsa"


def test_rotation_does_not_mutate_or_report_success(context):
    endpoint = SimpleNamespace(type="fabric-envoy")
    with patch.object(deployment.database, "update") as update, patch.object(
        cli, "send_rotation_notification"
    ) as notify, patch.object(cli.metrics, "send") as metric:
        deployment.rotate_certificate(endpoint, object(), object())
        cli.request_rotation(endpoint, object(), object(), True, True)
        update.assert_not_called()
        notify.assert_not_called()
        metric.assert_not_called()


def test_sync_failure_does_not_expire_endpoints(context, source):
    with patch.object(
        service, "sync_certificates", return_value=(0, 0, 0)
    ), patch.object(service, "expire_endpoints") as expire, patch.object(
        service.metrics, "send"
    ), patch.object(
        envoy, "get_endpoints", side_effect=envoy.DiscoveryError("unreachable")
    ):
        with pytest.raises(envoy.DiscoveryError):
            service.sync(source, None)
        expire.assert_not_called()


def test_unconfigured_sources_keep_plugin_discovery(context, source):
    source.plugin_name = "coa-source"
    plugin = Mock()
    plugin.get_endpoints.return_value = []
    with patch.object(service.plugins, "get", return_value=plugin):
        source.options = []
        assert service.sync_endpoints(source) == (0, 0, 0)
        plugin.get_endpoints.assert_called_once_with([])


def test_live_revocation_check_uses_discovery(context, source):
    endpoint = SimpleNamespace(type="fabric-envoy", source=source, name="observed")
    observed = {
        "name": "observed",
        "primary_certificate": {"certificate": SimpleNamespace(name="loaded")},
        "sni_certificates": [],
    }
    with patch.object(
        certificates.endpoint_service, "get_by_name", return_value=endpoint
    ), patch.object(envoy, "get_endpoints", return_value=[observed]) as discover:
        assert certificates.is_attached_to_endpoint("loaded", "observed")
        assert not certificates.is_attached_to_endpoint("old", "observed")
        discover.return_value = []
        with pytest.raises(envoy.DiscoveryError):
            certificates.is_attached_to_endpoint("loaded", "observed")


def test_all_proxies_must_succeed(context, source, proxy, snapshot):
    with patch.object(
        envoy, "discover_proxies", return_value=[proxy, {**proxy, "name": "replica-2"}]
    ), patch.object(
        envoy, "_read", side_effect=[snapshot, envoy.DiscoveryError("unreachable")]
    ), patch.object(
        envoy, "_resolve", side_effect=lambda s: s["name"]
    ):
        with pytest.raises(envoy.DiscoveryError):
            envoy.get_endpoints(source)


def test_fabric_source_does_not_import_certificates():
    plugin = FabricSourcePlugin()
    assert plugin.type == "source"
    assert plugin.slug == "fabric-source"
    assert plugin.get_certificates([]) == []
    assert [option["name"] for option in plugin.options] == [
        "datacenter",
        "namespace",
        "destination",
    ]


def test_coa_cannot_be_used_for_envoy_discovery(source):
    source.plugin_name = "coa-source"
    with pytest.raises(envoy.DiscoveryError, match="requires a Fabric source"):
        envoy.get_endpoints(source)


def test_inventory_receives_source_datacenter(source):
    with patch.object(envoy, "discover_proxies", return_value=[]) as discover:
        with pytest.raises(envoy.DiscoveryError, match="No Envoy proxies discovered"):
            envoy.get_endpoints(source)
        discover.assert_called_once_with("us1.staging.dog", "edge-backend", None)


def test_all_active_listeners_discovered_without_allowlist(source, proxy, snapshot):
    listeners, secrets = snapshot
    other = copy.deepcopy(listeners[0])
    other["active_state"]["listener"]["name"] = "another"
    plaintext = copy.deepcopy(other)
    plaintext["active_state"]["listener"].update(name="plaintext", filter_chains=[{}])
    endpoints = envoy._parse(
        source, proxy, listeners + [other, plaintext], secrets, lambda s: s["name"]
    )
    assert len(endpoints) == 2


def route_inventory():
    host = {
        "domains": ["envoy-api.us1.staging.dog", "*.us1.staging.dog", "other.example"],
        "routes": [
            {
                "action": {
                    "routeDestination": {
                        "namespace": "edge-backend",
                        "name": "ingress-haproxy-api",
                    }
                }
            }
        ],
    }
    obj = {"envoyRouteConfiguration": {"spec": {"virtualHosts": [host]}}}
    return {"objects": {"zone-a": {"objects": [obj]}, "zone-b": {"objects": [obj]}}}


def test_route_discovery_filters_and_deduplicates():
    with patch.object(envoy, "read_routes", return_value=route_inventory()) as read:
        assert envoy.discover_proxies("us1.staging.dog", "edge-backend") == [
            {
                "name": "edge-backend/ingress-haproxy-api/envoy-api.us1.staging.dog",
                "url": "https://envoy-api.us1.staging.dog",
            }
        ]
        assert envoy.discover_proxies("us1.staging.dog", "fabric-gateway") == []
        assert envoy.discover_proxies("us1.staging.dog", "edge-backend", "other") == []
        read.assert_called_with("us1.staging.dog")


def test_route_discovery_failure():
    with patch.object(
        envoy, "read_routes", side_effect=envoy.FabricError("UNAVAILABLE")
    ):
        with pytest.raises(envoy.DiscoveryError, match="UNAVAILABLE"):
            envoy.discover_proxies("us1.staging.dog", "edge-backend")


@pytest.mark.parametrize(
    "dc", [None, "", "https://example.dog", "dc.dog/path", "dc.dog@other"]
)
def test_invalid_datacenter(dc):
    with pytest.raises(envoy.DiscoveryError, match="Invalid Fabric datacenter"):
        envoy.discover_proxies(dc, "edge-backend")


def test_one_request_per_logical_route(source, snapshot):
    session = Mock()
    session.get.return_value.status_code = 200
    session.get.return_value.json.return_value = config_dump(snapshot)
    with patch.object(envoy.requests, "Session") as factory, patch.object(
        envoy, "_resolve", side_effect=lambda s: s["name"]
    ), patch.object(
        envoy,
        "discover_proxies",
        return_value=[{"name": "isp", "url": "https://isp.us1.staging.dog"}],
    ):
        factory.return_value.__enter__.return_value = session
        first = envoy.get_endpoints(source)
        session.get.assert_called_once()
        session.get.assert_called_with(
            "https://isp.us1.staging.dog/config_dump",
            timeout=(5, 20),
            allow_redirects=False,
            verify=True,
            cert=None,
        )
        assert envoy.get_endpoints(source) == first


def test_duplicate_secret_names_must_have_same_leaf(source, proxy, snapshot):
    listeners, secrets = snapshot
    for secret in secrets:
        secret["secret"] = {
            "tls_certificate": {
                "certificate_chain": {"inline_string": make_certificate()}
            }
        }
    secrets.append(copy.deepcopy(secrets[0]))
    assert (
        len(envoy._parse(source, proxy, listeners, secrets, lambda s: s["name"])) == 1
    )
    secrets[-1]["secret"]["tls_certificate"]["certificate_chain"][
        "inline_string"
    ] = make_certificate()
    with pytest.raises(envoy.DiscoveryError, match="Conflicting"):
        envoy._parse(source, proxy, listeners, secrets, lambda s: s["name"])


def test_missing_snapshot_section_fails(proxy, snapshot):
    session = Mock()
    session.get.return_value.status_code = 200
    payload = config_dump(snapshot)
    payload["configs"].pop()
    session.get.return_value.json.return_value = payload
    with pytest.raises(envoy.DiscoveryError):
        envoy._read(session, proxy)


def test_unmanaged_certificates_are_not_imported(source, proxy, snapshot):
    assert envoy._parse(source, proxy, *snapshot, lambda s: None) == []
    endpoints = envoy._parse(
        source, proxy, *snapshot, lambda s: "known" if s["name"] == "ecc" else None
    )
    assert endpoints[0]["primary_certificate"]["certificate"] == "known"
