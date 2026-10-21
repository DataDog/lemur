"""Authenticated, read-only access to the Fabric management API."""

import os
from functools import lru_cache
from pathlib import Path

import grpc
from google.protobuf import (
    descriptor_pb2,
    descriptor_pool,
    json_format,
    message_factory,
)


class FabricError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def _messages():
    # Private pool avoids collisions with the protobufs bundled in the COA wheel.
    pool = descriptor_pool.DescriptorPool()
    schema = descriptor_pb2.FileDescriptorSet.FromString(
        Path(__file__).with_name("fabric.pb").read_bytes()
    )
    for file in schema.file:
        pool.Add(file)
    return tuple(
        message_factory.GetMessageClass(
            pool.FindMessageTypeByName("fabric.api.v1." + name)
        )
        for name in ("ListRequest", "ListResponse")
    )


def _direct_credentials():
    # Read on every sync so new channels pick up Emissary certificate rotations.
    try:
        key = Path(
            os.environ.get("GRPC_CLIENT_KEY_PATH", "/etc/emissary/certs/client/key.pem")
        ).read_bytes()
        cert = Path(
            os.environ.get(
                "GRPC_CLIENT_CERT_PATH", "/etc/emissary/certs/client/cert.pem"
            )
        ).read_bytes()
        ca = Path(
            os.environ.get("GRPC_SERVER_CA_PATH", "/etc/emissary/certs/server/ca.pem")
        ).read_bytes()
        if not key or not cert or not ca:
            raise ValueError("Empty Emissary credentials")
    except (OSError, ValueError):
        raise FabricError(
            "Fabric discovery requires readable Emissary TLS credentials"
        ) from None
    return grpc.ssl_channel_credentials(
        root_certificates=ca, private_key=key, certificate_chain=cert
    )


def read_routes(datacenter):
    local_dc = os.environ.get("DD_DATACENTER")
    if not local_dc:
        raise FabricError("Fabric discovery requires DD_DATACENTER")
    try:
        # Imported lazily: this internal dependency is installed separately in the image.
        from dd_internal_authentication.client import (
            JWTInternalServiceAuthClientTokenManager,
        )

        request_type, response_type = _messages()
        request = json_format.ParseDict(
            {
                "type": "envoy_route_configuration",
                "id": {
                    "namespace": "fabric-gateway",
                    "name": "internal-services-proxy",
                },
            },
            request_type(),
        )
        metadata = []
        if datacenter == local_dc:
            target = "fabric-management.service-discovery.all-clusters.local-dc.fabric.dog:8443"
            credentials = _direct_credentials()
        else:
            target = "source-crossdc-gateway.service-discovery.all-clusters.local-dc.fabric.dog:8081"
            credentials = grpc.ssl_channel_credentials()
            metadata.append(
                (
                    "fabric-destination-fqdn",
                    "fabric-management.service-discovery.all."
                    + datacenter
                    + ".fabric.dog",
                )
            )
        manager = JWTInternalServiceAuthClientTokenManager(
            issuer="sycamore", timeout=10
        )
        metadata.append(
            ("authorization", "Bearer " + manager.get_token("service-discovery"))
        )
        with grpc.secure_channel(
            target,
            credentials,
            options=[("grpc.max_receive_message_length", 64 * 1024 * 1024)],
        ) as channel:
            read = channel.unary_unary(
                "/fabric.api.v1.FabricManagement/ListObjects",
                request_serializer=request_type.SerializeToString,
                response_deserializer=response_type.FromString,
            )
            response = read(request, metadata=metadata, timeout=30)
        return json_format.MessageToDict(response)
    except FabricError:
        raise
    except grpc.RpcError as error:
        # Surface the status, not response details which can contain credentials.
        raise FabricError(
            "Fabric route discovery failed: " + error.code().name
        ) from None
    except Exception:
        raise FabricError("Unable to authenticate or read Fabric routes") from None
