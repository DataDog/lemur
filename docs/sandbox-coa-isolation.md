# Sandbox COA path isolation

Set `SANDBOX_COA_PATH_ISOLATION = True` in the sandbox application configuration.
The default is false; commercial and government must leave it disabled.
Deployment configuration lives in the separate k8s-resources repo. This code
change does not enable the setting or deploy anything.

With enforcement enabled, COA create/update operations, certificate uploads, and
certificate/endpoint source reads require every comma-separated path to be a
descendant of:

`/kv/data/k8s/cert-orchestration/cert-orchestration-adapter/lemur-sandbox-tests/`

Use `dest-<destination-id>` and the same path on its matching source. Missing,
duplicate, empty, shared, and traversal paths fail explicitly. Non-COA plugins
are unaffected. Direct database edits cannot bypass the runtime checks in Lemur.
This is an application guard, not a Vault ACL boundary or protection against
code calling the external COA plugin directly.

## Inventory and rollout

Verified after cleanup on November 5, 2026: all remaining COA configurations use
the isolated test prefix. The 27 incompatible destinations and nine sources were
exported and deleted with user approval. Their certificate records and Vault
secrets were left untouched.

| Configuration | IDs | Strict guard |
| --- | --- | --- |
| Isolated destinations | 38, 40, 49, 59, 60, 61, 62, 63, 64, 72, 73 | Pass |
| Matching isolated sources | 38, 39, 40, 41, 51, 52 | Pass |

1. Refresh all COA records, resolve actual targets, and confirm Vault permissions.
2. If new incompatible configurations have appeared, migrate or retire them with
   explicit approval before enabling enforcement.
3. Verify zero incompatible configurations remain before enabling the setting in
   sandbox. Test rejection of shared paths and successful isolated reads/uploads.
4. Monitor source sync and upload failures. Existing Vault secrets and endpoint
   associations are not moved or cleaned up by changing paths.

Do not infer isolation from a staging hostname or test label: commercial Lemur
also manages staging infrastructure. Keep matching sources and destinations on
the same isolated path.
