"""
.. module: lemur.plugins.lemur_vault_dest.plugin
    :platform: Unix
    :copyright: (c) 2019
    :license: Apache, see LICENCE for more details.

    Plugin for uploading certificates and private key as secret to hashi vault
     that can be pulled down by end point nodes.

.. moduleauthor:: Christopher Jolley <chris@alwaysjolley.com>
"""

import os
import re
import time
import hvac
from flask import current_app

from lemur.common.defaults import (
    common_name,
    country,
    state,
    location,
    organizational_unit,
    organization,
)
from lemur.common.utils import parse_certificate, check_validation
from lemur.extensions import metrics
from lemur.plugins.bases import DestinationPlugin
from lemur.plugins.bases import SourcePlugin

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from validators.url import url

try:
    import grpc
    from cert_orchestration_adapter.plugin import create_coa_connection, parse_ca_vendor
    from cert_orchestration_adapter.plugin import (
        parse_certificate as coa_parse_certificate,
        common_name as coa_common_name,
        get_key_type_from_certificate,
    )
    from domains.cert_orchestration.libs.pb.cert_orchestration_adapter import (
        service_pb2 as _coa_adapter_pb2,
    )
    _COA_AVAILABLE = True
except ImportError:
    _COA_AVAILABLE = False
    grpc = None
    _coa_adapter_pb2 = None

# ---------------------------------------------------------------------------
# Retry helpers for gRPC UNAVAILABLE errors
# ---------------------------------------------------------------------------

# gRPC status codes that indicate the upstream is not yet reachable and the
# call is safe to retry without risk of duplicate side-effects.
_RETRIABLE_STATUS_CODES = {grpc.StatusCode.UNAVAILABLE} if grpc is not None else set()

# Substrings in the gRPC error detail that confirm a "no healthy upstream"
# condition.  If any of these appear we know COA simply isn't deployed yet
# and retrying is the right behaviour.
_RETRIABLE_DETAIL_SUBSTRINGS = (
    "no healthy upstream",
    "upstream connect error",
    "connection refused",
    "failed to connect",
)


def _is_retriable_grpc_error(exc):
    """Return True if *exc* is a gRPC error that should be retried.

    Only retries on UNAVAILABLE status where the detail string indicates that
    the upstream is unreachable (e.g. COA not yet deployed).  All other gRPC
    errors – including UNAUTHENTICATED, PERMISSION_DENIED, INVALID_ARGUMENT,
    and INTERNAL – propagate immediately so mis-configuration is surfaced fast.
    """
    if grpc is None:
        return False
    if not isinstance(exc, grpc.RpcError):
        return False
    try:
        code = exc.code()
    except Exception:
        return False
    if code not in _RETRIABLE_STATUS_CODES:
        return False
    try:
        detail = exc.details() or ""
    except Exception:
        detail = ""
    detail_lower = detail.lower()
    return any(sub in detail_lower for sub in _RETRIABLE_DETAIL_SUBSTRINGS)


def _upload_with_retry(stub, request, auth_token, retry_timeout_seconds, initial_wait_seconds, endpoint="unknown"):
    """Call stub.Upload(request) with exponential back-off on retriable errors.

    Args:
        stub: gRPC stub with an Upload method.
        request: The CertificateUploadRequest protobuf message.
        auth_token: (key, value) tuple for the gRPC call metadata.
        retry_timeout_seconds (float): Wall-clock deadline for the entire retry
            loop.  Zero or negative means retry forever.
        initial_wait_seconds (float): Wait time before the first retry.
            Each subsequent wait is doubled, capped at 60 s.
        endpoint (str): Human-readable endpoint label for logs and metrics.
            Defaults to "unknown".

    Raises:
        grpc.RpcError: Re-raises the last gRPC error when the deadline is
            exceeded or when the error is not retriable.
    """
    start = time.monotonic()
    deadline = start + retry_timeout_seconds if retry_timeout_seconds > 0 else None
    wait = max(initial_wait_seconds, 1.0)
    attempt = 0

    while True:
        try:
            stub.Upload(request=request, metadata=[auth_token])
            if attempt > 0:
                current_app.logger.info(
                    {
                        "message": "COA upload succeeded after retries",
                        "attempt_count": attempt,
                        "endpoint": endpoint,
                        "total_elapsed_seconds": round(time.monotonic() - start, 2),
                    }
                )
                try:
                    metrics.send(
                        "lemur.plugins.coa.retry_success",
                        "counter",
                        1,
                        metric_tags={"host": endpoint},
                    )
                except Exception:
                    pass
            return
        except grpc.RpcError as exc:
            if not _is_retriable_grpc_error(exc):
                raise

            attempt += 1
            elapsed = time.monotonic() - start
            if deadline is not None and time.monotonic() >= deadline:
                current_app.logger.error(
                    "COA upload retry deadline exceeded after %d attempt(s): %s",
                    attempt,
                    exc.details(),
                )
                raise

            current_app.logger.warning(
                {
                    "message": "COA gRPC UNAVAILABLE — will retry",
                    "attempt": attempt,
                    "wait_seconds": round(wait, 1),
                    "total_elapsed_seconds": round(elapsed, 2),
                    "endpoint": endpoint,
                    "grpc_detail": exc.details(),
                }
            )
            try:
                metrics.send(
                    "lemur.plugins.coa.retry_attempt",
                    "counter",
                    1,
                    metric_tags={"host": endpoint},
                )
            except Exception:
                pass
            time.sleep(wait)
            wait = min(wait * 2, 60.0)


class VaultSourcePlugin(SourcePlugin):
    """Class for importing certificates from Hashicorp Vault"""

    title = "Vault"
    slug = "vault-source"
    description = "Discovers all certificates in a given path"

    author = "Christopher Jolley"
    author_url = "https://github.com/alwaysjolley/lemur"

    options = [
        {
            "name": "vaultUrl",
            "type": "str",
            "required": True,
            "validation": bool(url),
            "helpMessage": "Valid URL to Hashi Vault instance",
        },
        {
            "name": "vaultKvApiVersion",
            "type": "select",
            "value": "2",
            "available": ["1", "2"],
            "required": True,
            "helpMessage": "Version of the Vault KV API to use",
        },
        {
            "name": "authenticationMethod",
            "type": "select",
            "value": "token",
            "available": ["token", "kubernetes"],
            "required": True,
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "tokenFileOrVaultRole",
            "type": "str",
            "required": True,
            "validation": check_validation("^([a-zA-Z0-9/._-]+/?)+$"),
            "helpMessage": "Must be vaild file path for token based auth and valid role if k8s based auth",
        },
        {
            "name": "vaultMount",
            "type": "str",
            "required": True,
            "validation": check_validation(r"^\S+$"),
            "helpMessage": "Must be a valid Vault secrets mount name!",
        },
        {
            "name": "vaultPath",
            "type": "str",
            "required": True,
            "validation": check_validation("^([a-zA-Z0-9._-]+/?)+$"),
            "helpMessage": "Must be a valid Vault secrets path",
        },
        {
            "name": "objectName",
            "type": "str",
            "required": True,
            "validation": check_validation("[0-9a-zA-Z.:_-]+"),
            "helpMessage": "Object Name to search",
        },
    ]

    def get_certificates(self, options, **kwargs):
        """Pull certificates from objects in Hashicorp Vault"""
        data = []
        cert = []
        body = ""
        url = self.get_option("vaultUrl", options)
        auth_method = self.get_option("authenticationMethod", options)
        auth_key = self.get_option("tokenFileOrVaultRole", options)
        mount = self.get_option("vaultMount", options)
        path = self.get_option("vaultPath", options)
        obj_name = self.get_option("objectName", options)
        api_version = self.get_option("vaultKvApiVersion", options)
        cert_filter = "-----BEGIN CERTIFICATE-----"
        cert_delimiter = "-----END CERTIFICATE-----"

        client = hvac.Client(url=url)
        if auth_method == "token":
            with open(auth_key, "r") as tfile:
                token = tfile.readline().rstrip("\n")
            client.token = token

        if auth_method == "kubernetes":
            token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            with open(token_path, "r") as f:
                jwt = f.read()
            client.auth_kubernetes(auth_key, jwt)

        client.secrets.kv.default_kv_version = api_version

        path = "{0}/{1}".format(path, obj_name)

        secret = get_secret(client, mount, path)
        for cname in secret["data"]:
            if "crt" in secret["data"][cname]:
                cert = secret["data"][cname]["crt"].split(cert_delimiter + "\n")
            elif "pem" in secret["data"][cname]:
                cert = secret["data"][cname]["pem"].split(cert_delimiter + "\n")
            else:
                for key in secret["data"][cname]:
                    if secret["data"][cname][key].startswith(cert_filter):
                        cert = secret["data"][cname][key].split(cert_delimiter + "\n")
                        break
            body = cert[0] + cert_delimiter
            if "chain" in secret["data"][cname]:
                chain = secret["data"][cname]["chain"]
            elif len(cert) > 1:
                if cert[1].startswith(cert_filter):
                    chain = cert[1] + cert_delimiter
                else:
                    chain = None
            else:
                chain = None
            data.append({"body": body, "chain": chain, "name": cname})
        return [
            dict(body=c["body"], chain=c.get("chain"), name=c["name"]) for c in data
        ]

    def get_endpoints(self, options, **kwargs):
        """Not implemented yet"""
        endpoints = []
        return endpoints


class VaultDestinationPlugin(DestinationPlugin):
    """Hashicorp Vault Destination plugin for Lemur"""

    title = "Vault"
    slug = "hashi-vault-destination"
    description = "Allow the uploading of certificates to Hashi Vault as secret"

    author = "Christopher Jolley"
    author_url = "https://github.com/alwaysjolley/lemur"

    options = [
        {
            "name": "vaultUrl",
            "type": "str",
            "required": True,
            "validation": bool(url),
            "helpMessage": "Valid URL to Hashi Vault instance",
        },
        {
            "name": "vaultKvApiVersion",
            "type": "select",
            "value": "2",
            "available": ["1", "2"],
            "required": True,
            "helpMessage": "Version of the Vault KV API to use",
        },
        {
            "name": "authenticationMethod",
            "type": "select",
            "value": "token",
            "available": ["token", "kubernetes"],
            "required": True,
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "tokenFileOrVaultRole",
            "type": "str",
            "required": True,
            "validation": check_validation("^([a-zA-Z0-9/._-]+/?)+$"),
            "helpMessage": "Must be vaild file path for token based auth and valid role if k8s based auth",
        },
        {
            "name": "vaultMount",
            "type": "str",
            "required": True,
            "validation": check_validation(r"^\S+$"),
            "helpMessage": "Must be a valid Vault secrets mount name!",
        },
        {
            "name": "vaultPath",
            "type": "str",
            "required": True,
            "validation": check_validation(
                "^(([a-zA-Z0-9._-]+|{(CN|OU|O|L|S|C)})+/?)+$"
            ),
            "helpMessage": "Must be a valid Vault secrets path. Support vars: {CN|OU|O|L|S|C}",
        },
        {
            "name": "objectName",
            "type": "str",
            "required": False,
            "validation": check_validation("^([0-9a-zA-Z.:_-]+|{(CN|OU|O|L|S|C)})+$"),
            "helpMessage": "Name to bundle certs under, if blank use {CN}. Support vars: {CN|OU|O|L|S|C}",
        },
        {
            "name": "bundleChain",
            "type": "select",
            "value": "cert only",
            "available": ["Nginx", "Apache", "PEM", "no chain"],
            "required": True,
            "helpMessage": "Bundle the chain into the certificate",
        },
        {
            "name": "sanFilter",
            "type": "str",
            "value": ".*",
            "required": False,
            "validation": check_validation(".*"),
            "helpMessage": "Valid regex filter",
        },
    ]

    def __init__(self, *args, **kwargs):
        super(VaultDestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        """
        Upload certificate and private key

        :param private_key:
        :param cert_chain:
        :return:
        """
        cert = parse_certificate(body)
        cname = common_name(cert)

        url = self.get_option("vaultUrl", options)
        auth_method = self.get_option("authenticationMethod", options)
        auth_key = self.get_option("tokenFileOrVaultRole", options)
        mount = self.get_option("vaultMount", options)
        path = self.get_option("vaultPath", options)
        bundle = self.get_option("bundleChain", options)
        obj_name = self.get_option("objectName", options)
        api_version = self.get_option("vaultKvApiVersion", options)
        san_filter = self.get_option("sanFilter", options)

        san_list = get_san_list(body)
        if san_filter:
            for san in san_list:
                try:
                    if not re.match(san_filter, san, flags=re.IGNORECASE):
                        current_app.logger.exception(
                            "Exception uploading secret to vault: invalid SAN: {}".format(
                                san
                            ),
                            exc_info=True,
                        )
                        os._exit(1)
                except re.error:
                    current_app.logger.exception(
                        "Exception compiling regex filter: invalid filter",
                        exc_info=True,
                    )

        client = hvac.Client(url=url)
        if auth_method == "token":
            with open(auth_key, "r") as tfile:
                token = tfile.readline().rstrip("\n")
            client.token = token

        if auth_method == "kubernetes":
            token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            with open(token_path, "r") as f:
                jwt = f.read()
            client.auth_kubernetes(auth_key, jwt)

        client.secrets.kv.default_kv_version = api_version

        t_path = path.format(
            CN=cname,
            OU=organizational_unit(cert),
            O=organization(cert),  # noqa: E741
            L=location(cert),
            S=state(cert),
            C=country(cert),
        )
        if not obj_name:
            obj_name = "{CN}"

        f_obj_name = obj_name.format(
            CN=cname,
            OU=organizational_unit(cert),
            O=organization(cert),  # noqa: E741
            L=location(cert),
            S=state(cert),
            C=country(cert),
        )

        path = "{0}/{1}".format(t_path, f_obj_name)

        secret = get_secret(client, mount, path)
        secret["data"][cname] = {}

        if not cert_chain:
            chain = ""
        else:
            chain = cert_chain

        if bundle == "Nginx":
            secret["data"][cname]["crt"] = "{0}\n{1}".format(body, chain)
            secret["data"][cname]["key"] = private_key
        elif bundle == "Apache":
            secret["data"][cname]["crt"] = body
            secret["data"][cname]["chain"] = chain
            secret["data"][cname]["key"] = private_key
        elif bundle == "PEM":
            secret["data"][cname]["pem"] = "{0}\n{1}\n{2}".format(
                body, chain, private_key
            )
        else:
            secret["data"][cname]["crt"] = body
            secret["data"][cname]["key"] = private_key
        if isinstance(san_list, list):
            secret["data"][cname]["san"] = san_list
        try:
            client.secrets.kv.create_or_update_secret(
                path=path, mount_point=mount, secret=secret["data"]
            )
        except ConnectionError as err:
            current_app.logger.exception(
                "Exception uploading secret to vault: {0}".format(err), exc_info=True
            )


def get_san_list(body):
    """parse certificate for SAN names and return list, return empty list on error"""
    san_list = []
    try:
        byte_body = body.encode("utf-8")
        cert = x509.load_pem_x509_certificate(byte_body, default_backend())
        ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_list = ext.value.get_values_for_type(x509.DNSName)
    except x509.extensions.ExtensionNotFound:
        pass
    finally:
        return san_list


def get_secret(client, mount, path):
    """retreive existing data from mount path and return dictionary"""
    result = {"data": {}}
    try:
        if client.secrets.kv.default_kv_version == "1":
            result = client.secrets.kv.v1.read_secret(path=path, mount_point=mount)
        else:
            result = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=mount
            )
            result = result["data"]
    except ConnectionError:
        pass
    finally:
        return result


# ---------------------------------------------------------------------------
# COA (Cert Orchestration Adapter) destination plugin
# ---------------------------------------------------------------------------

class COADestinationPlugin(DestinationPlugin):
    """Destination plugin that delivers certificates to the Cert Orchestration
    Adapter (COA) service over gRPC.

    Extends the base COA destination with a ``retry_until_healthy`` option: when
    enabled, a gRPC UNAVAILABLE / "no healthy upstream" error causes the plugin
    to retry with exponential back-off instead of failing immediately.  This is
    useful during initial cluster bootstrapping when COA may not yet be deployed.

    The plugin delegates connection setup to
    ``cert_orchestration_adapter.plugin.create_coa_connection`` so that auth
    (JWT / Ticino), channel setup, and path parsing stay in one place.

    Configuration example (per-destination options)::

        hostname: cert-orchestration-adapter.cert-orchestration.<env>.fabric.dog
        port: 3000
        audience: cert-orchestration-adapter
        paths: /secret/certs/my-app
        use_xdcgw: false
        use_ticino: false
        retry_until_healthy: true   # <-- new flag
        retry_timeout_seconds: 600  # give up after 10 min (0 = retry forever)
        retry_initial_wait_seconds: 5
    """

    title = "Cert Orchestration Adapter (with retry)"
    slug = "coa-destination-retry"
    description = (
        "Uploads certificates to the Cert Orchestration Adapter over gRPC.  "
        "When retry_until_healthy is enabled the plugin retries on "
        "UNAVAILABLE / 'no healthy upstream' errors with exponential back-off."
    )

    author = "Datadog Runtime DNA"
    author_url = "https://github.com/DataDog/lemur"

    options = [
        {
            "name": "audience",
            "type": "str",
            "required": True,
            "helpMessage": "JWT audience claim for authenticating with the COA service.",
        },
        {
            "name": "hostname",
            "type": "str",
            "required": True,
            "validation": check_validation("^.*.fabric.dog|localhost$"),
            "helpMessage": (
                "COA service hostname.  Must be a Fabric DNS name or localhost."
            ),
        },
        {
            "name": "port",
            "type": "int",
            "required": True,
            "validation": check_validation(r"^\d+$"),
            "helpMessage": "COA service gRPC port.",
        },
        {
            "name": "paths",
            "type": "str",
            "required": True,
            "validation": check_validation(r"^(/[\w-]+)+(,[/\w-]+)*$"),
            "helpMessage": "Comma-delimited list of Vault paths to write each certificate to.",
        },
        {
            "name": "use_xdcgw",
            "type": "bool",
            "required": False,
            "helpMessage": "Route the request through the Cross-DC Gateway.",
            "default": False,
        },
        {
            "name": "use_ticino",
            "type": "bool",
            "required": False,
            "helpMessage": "Use Ticino tokens for cross-DC internal service auth.",
            "default": False,
        },
        {
            "name": "retry_until_healthy",
            "type": "bool",
            "required": False,
            "helpMessage": (
                "When true, retry the gRPC call with exponential back-off on "
                "UNAVAILABLE / 'no healthy upstream' errors.  All other errors "
                "are raised immediately.  Useful when COA may not be deployed "
                "yet on the target cluster."
            ),
            "default": False,
        },
        {
            "name": "retry_timeout_seconds",
            "type": "str",
            "required": False,
            "validation": check_validation(r"^\d+$"),
            "helpMessage": (
                "How long (in seconds) to keep retrying before giving up.  "
                "Set to 0 to retry forever.  Only used when retry_until_healthy "
                "is true.  Default: 600 (10 minutes)."
            ),
            "default": "600",
        },
        {
            "name": "retry_initial_wait_seconds",
            "type": "str",
            "required": False,
            "validation": check_validation(r"^\d+(\.\d+)?$"),
            "helpMessage": (
                "Initial back-off delay in seconds before the first retry.  "
                "Doubles on each attempt, capped at 60 s.  "
                "Only used when retry_until_healthy is true.  Default: 5."
            ),
            "default": "5",
        },
    ]

    def __init__(self, *args, **kwargs):
        super(COADestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        """Upload a certificate to COA.

        When *retry_until_healthy* is set the call is retried with exponential
        back-off whenever gRPC returns UNAVAILABLE with a detail string that
        looks like "no healthy upstream" (or similar).  All other gRPC errors
        propagate immediately.
        """
        if not _COA_AVAILABLE:
            raise RuntimeError(
                "cert_orchestration_adapter wheel is not installed; "
                "cannot use COADestinationPlugin."
            )

        retry_until_healthy = self.get_option("retry_until_healthy", options)
        retry_timeout = float(self.get_option("retry_timeout_seconds", options) or 600)
        initial_wait = float(self.get_option("retry_initial_wait_seconds", options) or 5)

        try:
            stub, channel, paths_list, host, auth_token = create_coa_connection(self, options)
        except Exception as exc:
            current_app.logger.error(
                "Failed to create COA gRPC connection: %s", exc, exc_info=True
            )
            raise

        parsed_crt = coa_parse_certificate(body)
        parsed_chain = coa_parse_certificate(cert_chain)
        ca_vendor = parse_ca_vendor(parsed_chain)
        key_type = get_key_type_from_certificate(body)
        crt_name = "{cn}_{vendor}_{ktype}".format(
            cn=coa_common_name(parsed_crt),
            vendor=ca_vendor,
            ktype=key_type,
        )

        with channel:
            if not paths_list:
                current_app.logger.error(
                    "COADestinationPlugin: no paths configured for certificate upload"
                )
                return

            for path in paths_list:
                vault_path = os.path.join(path, crt_name)
                current_app.logger.info(
                    {
                        "message": "Uploading certificate via COADestinationPlugin",
                        "name": name,
                        "endpoint": host,
                        "path": vault_path,
                        "retry_until_healthy": retry_until_healthy,
                    }
                )

                request = _coa_adapter_pb2.CertificateUploadRequest(
                    certificate=body,
                    intermediate=cert_chain,
                    private_key=private_key,
                    vault_path=vault_path,
                )

                if retry_until_healthy:
                    _upload_with_retry(
                        stub=stub,
                        request=request,
                        auth_token=auth_token,
                        retry_timeout_seconds=retry_timeout,
                        initial_wait_seconds=initial_wait,
                        endpoint=host,
                    )
                else:
                    try:
                        stub.Upload(request=request, metadata=[auth_token])
                    except Exception as exc:
                        current_app.logger.error(
                            "COA gRPC upload failed for path %s: %s",
                            vault_path,
                            exc,
                            exc_info=True,
                        )
                        raise
