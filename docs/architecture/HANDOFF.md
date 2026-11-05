# Certificate Architecture — Handoff & Dev Guide

This document covers the full state of the interactive certificate architecture
diagram as of October 2026: what was built, how to run it, how to extend it, what
has been validated, and what still needs a human to close out.

---

## What was built

An interactive TLS certificate architecture reference for Lemur and its surrounding
services, modelled after the [Fabric Architecture][fabric-arch] site in
`service-discovery-platform`. It consists of:

| File | Purpose |
|---|---|
| `model.yaml` | Source of truth — nodes, edges, views, flows, owner palette |
| `lemur-certificate-architecture.md` | Prose panels for every node/view |
| `generate-diagram.py` | Validates the model, lays out d2, exports `architecture-data.json` |
| `src/` | React/Druids app (identical scaffold to fabric-architecture) |

The static-app is registered in `ddoghq/web-ui` at
`static-apps/certificate-architecture/` (PR [web-ui#27766][web-ui-pr]). The model
and generator live in this repo (PR [lemur#409][lemur-pr]).

The architecture reference was seeded from the "Datadog Certificate Management —
Organizational North Star" notebook (#15475223) and grounded against four
repositories: `DataDog/lemur`, `DataDog/vault-platform`,
`DataDog/service-discovery-platform`, `DataDog/cloud-inventory`.

---

## Running locally

### Full interactive app (recommended)

```bash
cd ~/go/src/github.com/ddoghq/web-ui
export PATH="$HOME/.yarn/switch/bin:$HOME/.volta/bin:$PATH"
yarn dev --filter=certificate-architecture
```

Open the URL printed by Vite (usually `http://localhost:5173`), then navigate to
`/static-apps/certificate-architecture/`.

**Prereqs:**
- `web-ui` checkout at `~/go/src/github.com/ddoghq/web-ui`
- `volta` (Node 24.14.1) — install via `curl https://get.volta.sh | bash`
- `yarn switch` — `yarn global add @datadog/yarn-switch`
- Run `yarn switch trust --set true ~/go/src/github.com/ddoghq/web-ui` once
- Run `yarn install` in the web-ui root once (you will be prompted to trust the
  workspace; accept)

### Static SVG preview (no web-ui needed)

```bash
cd ~/go/src/github.com/DataDog/lemur/docs/architecture
export PATH="$HOME/.local/d2bin:$PATH"          # d2 v0.9.0 with TALA
./generate-diagram.py --output /tmp/cert-arch   # generates architecture-data.json + d2 files
d2 --layout=tala /tmp/cert-arch/overview.d2 overview.svg
open overview.svg
```

### Model validation only (fastest)

```bash
cd ~/go/src/github.com/DataDog/lemur/docs/architecture
./generate-diagram.py --check
# → "model.yaml and lemur-certificate-architecture.md are consistent"
```

Always run `--check` before committing changes to `model.yaml` or the markdown.

---

## Model structure

`model.yaml` sections, in order:

| Section | What lives here |
|---|---|
| `site:` | Title, app name, source URL, repo aliases |
| `flows:` | Edge colour palette (issuance / delivery / bootstrap / config) |
| `kinds:` | Line style vocabulary (call / read / traffic) |
| `owners:` | Team fill colours for boxes |
| `shapes:` | Box shape vocabulary |
| `frame_kinds:` | Frame vocabulary (boundary / component) |
| `frames:` | Named datacenters and composite services |
| `nodes:` | Every box in the diagram |
| `views:` | Architecture tabs and flow tabs |
| `edges:` | Every arrow — from/to/label/kind/flow/views |

### Owner colours

| Owner key | Team | Colour |
|---|---|---|
| `resource-management` | Resource Management | red `#d64541` |
| `compute` | Compute | blue `#2f7fb8` |
| `cloud-foundations` | Cloud Foundations | green `#2e8b57` |
| `pplat-identity` | PPLAT / Identity Core | purple `#8e6bb0` |
| `external-ca` | External CAs | grey `#7f8c8d` |
| `fabric` | Service Discovery Platform | gold `#c89f3c` |

Nodes with no `owner` render white — used for sub-nodes inside a coloured frame
(e.g. `lemur_api`, `lemur_celery`, `lemur_db` inside the red Lemur frame).

### Active certificate authorities (API-confirmed, Oct 2026)

| Lemur authority name | Plugin slug | Model node |
|---|---|---|
| DigiCertTLSRSASHA2562020CA1 | `digicert-issuer` | `digicert` |
| DigiCert_Global_G2_TLS_RSA_SHA256_2020_CA1_RSA2048 | `digicert-issuer` | `digicert` |
| SectigoRSADomainValidationSecureServerCA | `sectigo-issuer` | `sectigo` |
| LetsEncryptProduction | `acme-issuer` | `letsencrypt` |

Entrust, GCP CA, and CFSSL have plugin code in the repo but are **not configured in
production**. They were removed from the model in commit `f159a9982`.

### Active destination plugin slugs (API-confirmed, Oct 2026)

| Plugin slug | Plugin title | Model node |
|---|---|---|
| `cert-orchestration-adapter-dest` | Cert Orchestration Adapter | `coa` / `coavault` |
| `aws-destination` | AWS | `aws` |
| `aws-acm-destination` | AWS-ACM | `acm` |
| `gcp-destination` | GCP | `gcp` |
| `azure-keyvault-destination` | Azure | `azure` |

---

## How to extend the model

### Add a new node

```yaml
nodes:
  my_service: {label: "My Service\n(subtitle)", shape: service, owner: resource-management, doc: my-service}
```

Then add a `### My Service` section to `lemur-certificate-architecture.md`:

```markdown
### My Service

<!-- catalog: no-service -->

One-paragraph description.

Source: `path/to/relevant/code`
```

Run `./generate-diagram.py --check` to verify the slug matches the heading.

### Add a new edge

```yaml
edges:
  - {from: lemur_celery, to: my_service, label: "deliver cert", kind: call, flow: delivery, views: [complete]}
```

`views:` controls which architecture tabs show the edge. Omit `views:` (or leave it
`[]`) for flow-only edges.

### Add a new flow

```yaml
views:
  - id: flow-my-scenario
    title: My Scenario
    category: flow
    group: Core Flows
    scenario:
      actor: ddcert
      trigger: "Description of what triggers this flow."
      preconditions: [precondition 1, precondition 2]
      end_state: "What the world looks like when the flow completes."
      limitations: [anything unverified or not yet shipped]
      architecture_view: landscape
    steps:
      - from: ddcert
        to: lemur_api
        label: "request"
        verification: unverified
        note: "Explanation."
        sources: []
```

The `actor` must participate in the first step. Steps reference base edges that must
exist in `edges:`.

---

## Confluence page

Companion runbook: **"Things to know about Lemur"** — page 7301956476 in the CLOUDR
space.

Direct link: `https://datadoghq.atlassian.net/wiki/spaces/CLOUDR/pages/edit-v2/7301956476`

**Status as of Oct 2026: draft — needs one manual click of Publish.**

The Confluence v2 API does not support programmatically publishing a draft for the
first time; all content edits are done and the page is ready.

---

## ddcert CLI — validated commands

All commands were validated against `ddcert v1.202.0` (built 2026-05-14) and the
live Lemur commercial API.

### Check auth

```bash
ddcert whoami
```

### List certificate authorities

```bash
ddcert authorities list
```

No domain-lookup subcommand exists. To check if a domain is registered with DigiCert,
use the Lemur UI (**Admin → Certificate Authorities → DigiCertTLSRSASHA2562020CA1 →
Domains**) or the REST API:

```bash
curl -H "Authorization: token $LEMUR_API_KEY" \
  "https://lemur-commercial.us1.ddbuild.io/api/1/domains?filter=name;example.datadoghq.com"
```

### Create a destination

`--label` does not exist; the label is auto-generated from slug + datacenter.
`--type` is required. `--dry-run` defaults to `true`; omit it to actually create.

```bash
ddcert destinations create \
  --slug cert-orchestration-adapter-dest \
  --type "Cert Orchestration Adapter" \
  --datacenter us1-prod
```

### Create a certificate

`--destination` does not exist. Create first, then attach destinations separately.

```bash
# Step 1 — create (default authority: DigiCertTLSRSASHA2562020CA1)
ddcert certificates create --common-name example.datadoghq.com

# Step 2 — attach destinations by ID
ddcert certificates list --label <new-cert-name>          # find the cert ID
ddcert certificates update --cert-id <id> --destination-ids <dest-id-1>,<dest-id-2>
```

### Force-rotate a certificate (break-glass)

There is no `ddcert certificates rotate` command. You must exec into the Lemur API
pod and run the Flask management CLI:

```bash
# Find the pod (ask #lemur-ops if the selector is stale)
kubectl get pods -n lemur -l app=lemur-commercial

# Dry run first (omit --commit)
kubectl exec -it -n lemur <pod-name> -- \
  lemur certificate rotate \
  --old-certificate <old-cert-name> \
  --new-certificate <new-cert-name>

# Commit the rotation
kubectl exec -it -n lemur <pod-name> -- \
  lemur certificate rotate \
  --old-certificate <old-cert-name> \
  --new-certificate <new-cert-name> \
  --commit
```

Note the subcommand is singular `certificate` (not `certificates`), matching the
Flask manager registration in `lemur/manage.py`.

---

## Open items

| Item | Status | Notes |
|---|---|---|
| lemur#409 (model + generator) | Open, CI green | Bandit B314 fixed (`# nosec`); ready for review |
| web-ui#27766 (static-app scaffold) | Open | Signing identity: `evan.mcelheny_ddoghq`, key `ak8JqL…` |
| Confluence page 7301956476 | Draft | All content correct; click **Publish** in the UI |
| RDNA-1000 Automated DCV | Not shipped | `flow-automated-dcv` in model marked planned; `get_dcv_expiration_data()` is the only shipped code |
| `lemur.managed` IAM boundary | Not in main | Planned (IR-57191); `lemur_managed_iam` node in model marked planned |
| `verification: unverified` steps | All flows unverified | Each flow step needs `sources:` paths added and `verification: verified` set |
| Hosting + RUM | Not configured | `site.rum: null`; routing-domain registration needs owner approval |

---

## Key file locations

| What | Where |
|---|---|
| Model + generator | `DataDog/lemur/docs/architecture/` |
| Static-app | `ddoghq/web-ui/static-apps/certificate-architecture/` |
| d2 binary (TALA) | `~/.local/d2bin/d2` |
| Lemur Flask CLI | `lemur/certificates/cli.py`, registered in `lemur/manage.py` |
| Lemur API key (local) | macOS Keychain, service `lemur-commercial`, account `evan.mcelheny` |
| Confluence page | Page ID 7301956476, space CLOUDR |

[fabric-arch]: https://github.com/DataDog/service-discovery-platform/tree/master/docs/architecture
[web-ui-pr]: https://github.com/ddoghq/web-ui/pull/27766
[lemur-pr]: https://github.com/DataDog/lemur/pull/409
