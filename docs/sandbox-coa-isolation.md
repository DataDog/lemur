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
