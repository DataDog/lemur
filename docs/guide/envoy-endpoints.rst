Fabric endpoint discovery
=========================

Fabric is a standalone, read-only source (``fabric-source``). Create one source
per datacenter and admin destination namespace. Required options are
``datacenter`` (such as ``us1.staging.dog``) and ``namespace``. An optional
``destination`` filters by exact Fabric destination name.

For Edge use ``namespace=edge-backend``. For ISP use
``namespace=fabric-gateway`` and ``destination=internal-services-proxy-admin``.
There is no Fabric destination. Existing COA and Vault sources and destinations
continue importing and distributing certificates unchanged. Fabric observes
where those certificates are served, independently of their storage location.
No application-level ``ENVOY_ADMIN_SOURCES`` configuration is used.

Implementation status
---------------------

Discovery reads the ``fabric-gateway/internal-services-proxy`` Fabric route
configuration and selects virtual hosts routing to the requested destination
namespace/name. Explicit hostnames in the requested DC become HTTPS admin URLs,
deduplicated across zones. No Edge pool or ISP hostname list is maintained.
The runtime requires the ``fabric`` CLI on PATH and service read permissions for
that route configuration. The current Lemur image does not install the CLI yet;
image packaging and service permissions must be supplied before enabling this.
Lemur's service access and certificate matching still need sandbox validation
before enabling a source. Laptop access does not prove service access.
Live ISP snapshots also contain different certificates with the same SDS name
(public DigiCert and internal infrastructure certificates). Discovery currently
fails closed on this ambiguity. SDS provider disambiguation remains required
before this source can be enabled.

Each sync samples one replica of each discovered admin endpoint. It does not assert
that every replica has converged during a rollout or certificate rotation.
Listeners and active SDS secrets are read in one ``/config_dump`` request so
they come from the same replica. Envoy rejects field masks spanning these two
configuration types, so the reader extracts them from the full response and
never logs or persists the raw dump. This is not a transactional snapshot of SDS.

The snapshot reader discovers all active listeners on the sampled proxy. Plaintext
filter chains are ignored. TLS filter chains reference active SDS secrets,
which currently must contain inline certificate-chain PEM. Static listeners,
inline listener certificates, certificate providers and filename-only secrets
are not supported yet. This coverage must be validated against actual proxies
before enabling the source.

Each TLS filter chain becomes an endpoint. Identity includes the Fabric source,
logical destination and hostname, listener name and filter chain name (or
match conditions). Replica changes do not create new endpoint identities.
The leaf certificate is matched to exactly one existing Lemur certificate by
SHA-256 of DER, with serial only narrowing candidates. Certificates not managed
by Lemur are ignored, including internal service identities. Fabric does not import
certificates or attach destinations. Duplicate SDS names are accepted only when
their leaf fingerprints match. Primary and SNI associations are storage
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
