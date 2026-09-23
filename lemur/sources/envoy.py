"""Read-only discovery of certificates loaded by explicitly configured Envoy proxies."""

import base64
import hashlib
import json
from urllib.parse import urlsplit

import requests
from cryptography import x509
from flask import current_app


class DiscoveryError(RuntimeError):
    pass


def configured(source):
    return source.label in current_app.config.get("ENVOY_ADMIN_SOURCES", {})


def _read(session, proxy, resource):
    # Do not log responses: admin dumps can contain private key material.
    url = proxy["url"].rstrip("/")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
        or parsed.username
    ):
        raise DiscoveryError("Invalid Envoy admin URL")
    try:
        response = session.get(
            url + "/config_dump",
            params={"resource": resource},
            timeout=(5, 20),
            allow_redirects=False,
            verify=proxy.get("ca_bundle", True),
            cert=proxy.get("client_cert"),
        )
        if response.status_code != 200:
            raise DiscoveryError("Envoy admin did not return HTTP 200")
        payload = response.json()
        configs = payload["configs"]
        if not isinstance(configs, list):
            raise ValueError()
        return configs
    except (requests.RequestException, ValueError, KeyError, TypeError):
        raise DiscoveryError("Unable to read Envoy admin configuration") from None


def _leaf(secret):
    try:
        chain = secret["secret"]["tls_certificate"]["certificate_chain"]
        if "inline_string" in chain:
            pem = chain["inline_string"].encode("ascii")
        else:
            pem = base64.b64decode(chain["inline_bytes"], validate=True)
        return x509.load_pem_x509_certificate(pem)
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise DiscoveryError(
            "Active SDS secret must contain an inline PEM certificate chain"
        ) from None


def _resolve(secret):
    from lemur.certificates import service
    from lemur.common.utils import find_matching_certificates_by_hash

    leaf = _leaf(secret)
    matches = find_matching_certificates_by_hash(
        leaf, service.get_by_serial(str(leaf.serial_number))
    )
    if len(matches) != 1:
        raise DiscoveryError(
            "Loaded Envoy certificate must match exactly one Lemur certificate by SHA-256"
        )
    return matches[0]


def _parse(source, proxy, listeners, secrets, resolve):
    active = {}
    for item in listeners:
        if not item.get("@type", "").endswith("ListenersConfigDump.DynamicListener"):
            raise DiscoveryError("Unexpected Envoy listener response type")
        listener = item.get("active_state", {}).get("listener")
        if listener:
            if listener["name"] in active:
                raise DiscoveryError("Duplicate active listener")
            active[listener["name"]] = listener
    selected = proxy["listeners"]
    if (
        not selected
        or len(set(selected)) != len(selected)
        or not set(selected).issubset(active)
    ):
        raise DiscoveryError("Configured Envoy listeners are missing or duplicated")
    secret_map = {}
    for item in secrets:
        if not item.get("@type", "").endswith("SecretsConfigDump.DynamicSecret"):
            raise DiscoveryError("Unexpected Envoy secret response type")
        name = item["name"]
        if name in secret_map:
            raise DiscoveryError("Duplicate active SDS secret")
        secret_map[name] = item

    endpoints = []
    for name in selected:
        listener = active[name]
        socket = listener["address"]["socket_address"]
        chains = list(listener.get("filter_chains", []))
        if listener.get("default_filter_chain"):
            chains.append(listener["default_filter_chain"])
        found = False
        identities = set()
        for chain in chains:
            transport = chain.get("transport_socket", {})
            if transport.get("name") != "envoy.transport_sockets.tls":
                continue
            tls = transport["typed_config"]["common_tls_context"]
            refs = tls.get("tls_certificate_sds_secret_configs", [])
            if (
                not refs
                or tls.get("tls_certificates")
                or tls.get("tls_certificate_provider_instance")
            ):
                raise DiscoveryError(
                    "Only SDS-backed TLS listener certificates are supported"
                )
            # Keep filter chains separate. Their certificate choices are not a global SNI order.
            identity = chain.get("name") or json.dumps(
                chain.get("filter_chain_match", {}), sort_keys=True
            )
            if identity in identities:
                raise DiscoveryError("Ambiguous Envoy filter chain identity")
            identities.add(identity)
            identity = json.dumps([source.label, proxy["name"], name, identity])
            digest = hashlib.sha256(identity.encode()).hexdigest()
            certs = []
            for ref in refs:
                if ref["name"] not in secret_map:
                    raise DiscoveryError(
                        "Listener references an unavailable active SDS secret"
                    )
                cert = resolve(secret_map[ref["name"]])
                if cert not in certs:
                    certs.append(cert)
            # Primary is a storage convention, not a claim about Envoy's selection algorithm.
            associations = [dict(certificate=cert, path="") for cert in certs]
            endpoints.append(
                dict(
                    name="envoy:" + (proxy["name"] + ":" + name)[:55] + ":" + digest,
                    dnsname=socket["address"],
                    port=int(socket["port_value"]),
                    type="envoy",
                    registry_type="envoy",
                    primary_certificate=associations[0],
                    sni_certificates=associations[1:],
                    policy={"name": "Envoy (observed, read-only)", "ciphers": []},
                )
            )
            found = True
        if not found:
            raise DiscoveryError(
                "Configured listener has no supported TLS filter chain"
            )
    return endpoints


def get_endpoints(source):
    """Resolve the entire snapshot before callers write associations or expire endpoints."""
    if source.plugin_name != "coa-source":
        raise DiscoveryError("Envoy discovery must be configured on a COA source")
    proxies = current_app.config.get("ENVOY_ADMIN_SOURCES", {}).get(source.label)
    if not proxies:
        raise DiscoveryError("No Envoy proxies configured for source")
    endpoints = []
    names = set()
    with requests.Session() as session:
        for proxy in proxies:
            verify = proxy.get("ca_bundle", True)
            if proxy["name"] in names or not (
                verify is True or isinstance(verify, str) and verify
            ):
                raise DiscoveryError(
                    "Duplicate proxy identity or disabled TLS verification"
                )
            names.add(proxy["name"])
            try:
                endpoints.extend(
                    _parse(
                        source,
                        proxy,
                        _read(session, proxy, "dynamic_listeners"),
                        _read(session, proxy, "dynamic_active_secrets"),
                        _resolve,
                    )
                )
            except (KeyError, TypeError, ValueError):
                raise DiscoveryError(
                    "Malformed Envoy discovery configuration or response"
                ) from None
    return endpoints
