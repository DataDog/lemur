See [CLAUDE.md](./CLAUDE.md) for project documentation and guidelines.

## Sandbox COA isolation

- Never configure Lemur Sandbox COA destinations or sources to use Vault paths managed by commercial Lemur, even when the Vault or datacenter is named `staging`. Commercial Lemur also manages staging infrastructure certificates.
- Use a dedicated path per sandbox destination: `/kv/data/k8s/cert-orchestration/cert-orchestration-adapter/lemur-sandbox-tests/dest-<destination-id>`. Keep its matching source on the exact same path.
- Before creating or changing a sandbox COA configuration, verify the actual COA/Vault target, its permissions for the test path, and that no commercial source, destination, or service consumer uses that path. A test label or the `all-clusters.local-dc.fabric.dog` alias does not provide isolation.
- Do not use shared service paths such as `/kv/data/managed-certificates/k8s/ingress-haproxy`, `/kv/data/k8s/cert-orchestration/isp/public-certificates`, or `/kv/data/managed-certificates/saml/...` for sandbox tests. Sandbox uploads can overwrite service certificates, and source sync can import commercial-managed certificates.
- Changing a configured path does not migrate or delete existing Vault secrets or clear certificate/endpoint associations. Treat cleanup and consumer changes as separate actions requiring explicit authorization. Do not upload certificates or run a source sync as an implicit part of a path-only update.
