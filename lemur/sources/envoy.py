"""Read-only discovery of certificates loaded by Fabric's Envoy proxies."""

import base64
import hashlib
import json
import re
import subprocess
from urllib.parse import urlsplit

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes


class DiscoveryError(RuntimeError):
    pass


def discover_proxies(datacenter, namespace, destination=None):
    if not isinstance(datacenter, str) or not re.fullmatch(
        r"[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]+", datacenter
    ):
        raise DiscoveryError("Invalid Fabric datacenter")
    if not namespace or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", namespace):
        raise DiscoveryError("Invalid Fabric destination namespace")
    try:
        result = subprocess.run(
            [
                "fabric",
                "-d",
                datacenter,
                "-n",
                "fabric-gateway",
                "envoy-route-configuration",
                "get",
                "internal-services-proxy",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        inventory = json.loads(result.stdout)
        proxies = {}
        for group in inventory["objects"].values():
            for obj in group["objects"]:
                for host in obj["envoyRouteConfiguration"]["spec"].get(
                    "virtualHosts", []
                ):
                    for route in host.get("routes", []):
                        target = route.get("action", {}).get("routeDestination", {})
                        name = target.get("name")
                        if target.get("namespace") != namespace or not name:
                            continue
                        if destination and name != destination:
                            continue
                        for domain in host["domains"]:
                            # Only explicit DNS hosts in the selected DC, never wildcard routes.
                            if not re.fullmatch(r"[a-z0-9.-]+", domain):
                                continue
                            if not domain.endswith("." + datacenter):
                                continue
                            identity = namespace + "/" + name + "/" + domain
                            proxies[identity] = {
                                "name": identity,
                                "url": "https://" + domain,
                            }
        return [proxies[name] for name in sorted(proxies)]
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        # CLI output may include credentials or internal response data.
        raise DiscoveryError(
            "Unable to discover Envoy admin routes through Fabric"
        ) from None


def _read(session, proxy):
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
        # Envoy cannot apply a field mask spanning different config types. Fetch
        # once so listeners and secrets come from the same load-balanced replica.
        sections = {}
        for config in configs:
            kind = config.get("@type", "").rsplit(".", 1)[-1]
            if kind in ("ListenersConfigDump", "SecretsConfigDump"):
                if kind in sections:
                    raise DiscoveryError("Duplicate Envoy configuration section")
                sections[kind] = config
        listeners = sections["ListenersConfigDump"]["dynamic_listeners"]
        secrets = sections["SecretsConfigDump"]["dynamic_active_secrets"]
        if not isinstance(listeners, list) or not isinstance(secrets, list):
            raise ValueError()
        return listeners, secrets
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
    if not matches:
        # Internal Fabric identities are not necessarily managed by Lemur.
        return None
    if len(matches) != 1:
        raise DiscoveryError(
            "Loaded Envoy certificate must match exactly one Lemur certificate by SHA-256"
        )
    return matches[0]


def _parse(source, proxy, listeners, secrets, resolve):
    active = {}
    for item in listeners:
        listener = item.get("active_state", {}).get("listener")
        if listener:
            if listener["name"] in active:
                raise DiscoveryError("Duplicate active listener")
            active[listener["name"]] = listener
    if not active:
        raise DiscoveryError("No active Envoy listeners were discovered")
    secret_map = {}
    for item in secrets:
        name = item["name"]
        if name in secret_map:
            if _leaf(item).fingerprint(hashes.SHA256()) != _leaf(
                secret_map[name]
            ).fingerprint(hashes.SHA256()):
                raise DiscoveryError("Conflicting active SDS secrets")
            continue
        secret_map[name] = item

    endpoints = []
    for name in sorted(active):
        listener = active[name]
        socket = listener["address"]["socket_address"]
        chains = list(listener.get("filter_chains", []))
        if listener.get("default_filter_chain"):
            chains.append(listener["default_filter_chain"])
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
                if cert is not None and cert not in certs:
                    certs.append(cert)
            if not certs:
                continue
            # Primary is a storage convention, not a claim about Envoy's selection algorithm.
            associations = [dict(certificate=cert, path="") for cert in certs]
            endpoints.append(
                dict(
                    name="fabric-envoy:"
                    + (proxy["name"] + ":" + name)[:50]
                    + ":"
                    + digest,
                    dnsname=socket["address"],
                    port=int(socket["port_value"]),
                    type="fabric-envoy",
                    registry_type="fabric-envoy",
                    primary_certificate=associations[0],
                    sni_certificates=associations[1:],
                    policy={"name": "Envoy (observed, read-only)", "ciphers": []},
                )
            )
    return endpoints


def get_endpoints(source):
    """Resolve the entire snapshot before callers write associations or expire endpoints."""
    if source.plugin_name != "fabric-source":
        raise DiscoveryError("Envoy discovery requires a Fabric source")
    from lemur.plugins.utils import get_plugin_option

    datacenter = get_plugin_option("datacenter", source.options)
    if not datacenter:
        raise DiscoveryError("Fabric source requires a datacenter")
    proxies = discover_proxies(
        datacenter,
        get_plugin_option("namespace", source.options),
        get_plugin_option("destination", source.options),
    )
    if not proxies:
        raise DiscoveryError("No Envoy proxies discovered for Fabric source")
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
                        *_read(session, proxy),
                        _resolve,
                    )
                )
            except (KeyError, TypeError, ValueError):
                raise DiscoveryError(
                    "Malformed Envoy discovery configuration or response"
                ) from None
    return endpoints
