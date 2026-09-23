Envoy endpoint discovery
=======================

COA sources can discover loaded Envoy certificates instead of exposing Vault
paths as endpoints. Certificate import still runs through the existing COA
source plugin. No Vault paths or Vault data are modified by endpoint discovery.

This is opt-in through the Lemur application configuration::

    ENVOY_ADMIN_SOURCES = {
        "<existing COA source label>": [
            {
                "name": "<stable unique proxy identity>",
                "url": "https://<individual-proxy-admin-host>:8086",
                "listeners": ["<active TLS listener name>"],
                # Optional requests-compatible TLS credentials:
                # "ca_bundle": "/path/to/ca.pem",
                # "client_cert": ("/path/to/client.pem", "/path/to/client-key.pem"),
            },
        ],
    }

Configure every relevant replica, not a load-balanced admin service. A replica
can serve a different certificate during a rollout. Listener names are an
explicit allowlist, so internal listeners need not be imported. The proxy list
must be maintained as replicas change. Automatic Fabric inventory discovery is
not implemented. Deployment configuration must supply the actual URLs and
network access before enabling this in sandbox.

Discovery uses GET requests to config_dump with dynamic_listeners and
dynamic_active_secrets resource filters. It reads active listeners only and
requires inline certificate-chain PEM from their active SDS secrets. Static
listeners, inline listener certificates, certificate providers and secrets
containing only filenames are not supported by this initial implementation.
The certs admin endpoint alone does not provide a certificate fingerprint.

Each TLS filter chain becomes an endpoint. Its identity includes the COA source,
proxy identity, listener name and filter chain name (or match conditions).
The name includes a readable proxy/listener prefix and a hash to fit the
existing database column. The address and port are the listener's bind address
and port, not necessarily a publicly reachable hostname.

The leaf certificate is matched to exactly one Lemur record by SHA-256 of DER,
using serial only to narrow candidates. Names and Vault paths are not matching
keys. The first certificate uses Lemur's primary association, with additional
certificates stored in its existing SNI associations. This is a storage
convention, not a claim that Envoy always selects the first certificate.
Association paths are empty because discovery does not need a Vault path.

An unavailable proxy, missing configured listener, unavailable SDS secret or
unknown/ambiguous certificate fails the source sync before endpoint writes and
expiration. Dumps are never logged by this code and only certificates are
retained; admin access must nevertheless be restricted because dumps may contain
sensitive material. TLS verification cannot be disabled. HTTP is supported only
for trusted local admin access; prefer authenticated HTTPS for remote access.

After successful syncs, old Vault-path endpoints expire through the existing
two-hour database cleanup. This does not delete anything from Vault. Removing
this configuration restores legacy COA discovery, and stale Envoy endpoints
then age out the same way.

Endpoint updates are intentionally a TODO/no-op. Neither deployment nor the
rotation command fabricates new associations or reports successful rotations
for Envoy endpoints. Only observed discovery updates associations. Existing COA
destination uploads remain responsible for distribution. Revocation checks use
fresh discovery and fail closed if the endpoint cannot be verified.

Tests: ``python -m pytest lemur/tests/test_envoy.py``. These are local tests with
mocked HTTP and database access, not proof of reachability or the exact dump
format on deployed proxies. Validate that format and source/proxy coverage in
sandbox before migrating production sources.
