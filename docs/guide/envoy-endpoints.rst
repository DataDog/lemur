Fabric endpoint discovery
=========================

Fabric is a standalone, read-only source (``fabric-source``). Create one source
per datacenter with its ``datacenter`` option, such as ``us1.staging.dog``.
There is no Fabric destination. Existing COA and Vault sources and destinations
continue importing and distributing certificates unchanged. Fabric observes
where those certificates are served, independently of their storage location.
No application-level ``ENVOY_ADMIN_SOURCES`` configuration is used.

Implementation status
---------------------

This is an incomplete draft, not ready to enable. Automatic per-datacenter
proxy inventory and authenticated admin routing still need implementation and
sandbox validation. ``discover_proxies`` currently raises a discovery error,
so attempting to sync a Fabric source fails before endpoint writes or expiry.
Do not configure manual proxy URLs or listener allowlists as a workaround.

The snapshot reader discovers all active listeners on each proxy. Plaintext
filter chains are ignored. TLS filter chains reference active SDS secrets,
which currently must contain inline certificate-chain PEM. Static listeners,
inline listener certificates, certificate providers and filename-only secrets
are not supported yet. This coverage must be validated against actual proxies
before enabling the source.

Each TLS filter chain becomes an endpoint. Identity includes the Fabric source,
proxy identity, listener name and filter chain name (or match conditions).
The leaf certificate is matched to exactly one existing Lemur certificate by
SHA-256 of DER, with serial only narrowing candidates. Fabric does not import
certificates or attach destinations. Primary and SNI associations are storage
conventions, not a claim about Envoy's certificate selection algorithm.
Association paths are empty. Vault paths are not endpoint identities.

Discovery must finish successfully before endpoint writes and expiry. Failed
inventory or snapshot requests must never be treated as an empty successful
result. Successful Fabric syncs expire only that Fabric source's stale endpoint
records using the existing TTL. They do not expire COA endpoints or change
Vault data. Migration of existing Vault-path endpoints is a separate step.

Endpoint updates remain a TODO/no-op. Only observed discovery changes endpoint
associations. Revocation checks require fresh discovery and fail closed when
the endpoint cannot be verified. No Fabric destination is registered.

Run ``python -m pytest lemur/tests/test_envoy.py`` for mocked discovery and
source-isolation tests. These do not validate live Fabric access.
