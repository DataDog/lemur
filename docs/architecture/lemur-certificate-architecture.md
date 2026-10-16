# Certificate Architecture

How TLS certificates are requested, issued, delivered and trusted at Datadog: the
systems that call **Lemur**, the certificate authorities and destinations **Lemur**
talks to, and the ancillary certificate systems that run alongside it. Select a
component box to open its details in the side panel; flow views follow one triggered
behaviour through numbered steps.

This is a reference, not live status. It is seeded from the "Datadog Certificate
Management — Organizational North Star" investigation, so several claims are marked
**unverified** until they have been re-checked against code. Every section cites the
files it relies on; anything outside this repository or not confirmed says so.

## Overview

<!-- view: overview -->

**Lemur** is the broker and inventory for TLS certificates: clients request
certificates, Lemur delegates issuance to a certificate authority through a CA plugin,
records the result in PostgreSQL, and pushes the issued certificate to a destination
plugin. **Lemur runs in ddbuild** (the control-plane datacenters); certificates are
delivered **out of ddbuild** into each site datacenter (COA → Vault KV, Envoy) and to
CSP destinations. Alongside Lemur, **cert-manager** issues the pre-Vault bootstrap
certificate that dedicated-vault needs to start, and **cert-distribute** handles Vault
server TLS.

Source: `lemur/certificates/service.py`

## Complete

<!-- view: complete -->

Every component and connection on one board. Use the legend above the diagram to hide
the connection families you don't care about; hovering a box highlights its neighbours.

Source: `lemur/certificates/service.py`

## System Landscape

<!-- view: landscape -->

Everything that calls Lemur, what Lemur calls, and the ancillary certificate systems
beside it. Clients of Lemur, certificate authorities and destinations, and
cert-manager / cert-distribute / Envoy.

Source: `lemur/certificates/service.py`

## Issue a Certificate

<!-- view: flow-issuance -->

A caller — for example the `ddcert` CLI — requests a certificate through the Lemur
API. Lemur issues it via a CA plugin (here shown as Let's Encrypt / ACME), records it in
PostgreSQL, and delivers it to its destination (COA → Vault KV for internal services).

Source: `lemur/certificates/service.py`

## Let's Encrypt Migration

<!-- view: flow-le-migration -->

Datadog is migrating certificates from DigiCert to Let's Encrypt. Edge certificates
issued by LE must be trusted by consumers: an Envoy trust bundle must contain the ISRG
Root X1 (a one-time per-DC check).

Source: `lemur/plugins/lemur_acme/`

## DC Turnup — Phase 0 (Pre-Vault)

<!-- view: flow-dc-turnup-phase0 -->

During a datacenter turnup, before any Vault is available, cert-manager issues the
dedicated-vault bootstrap TLS certificate via Let's Encrypt (ACME/DNS01) and writes it
as a Kubernetes Secret so Vault can start and unseal.

Source: in k8s-platform-resources, `README.md`

## DC Turnup — Phase 1 (Post-Vault)

<!-- view: flow-dc-turnup-phase1 -->

After Vault is up, the certificate-bootstrapping-agent (a release-actions agent) asks
Lemur to create the DC's certificates and destinations. Lemur issues them (DigiCert) and
delivers them to the COA destination → Vault KV (and AWS/GCP/Azure for edge/load
balancers).

Source: `lemur/certificates/service.py`

## Automated DCV (RDNA-1000, planned)

<!-- view: flow-automated-dcv -->

**Status: planned (RDNA-1000, in-flight; not yet in main.)** The design is that on
each DigiCert renewal, Lemur triggers DCV automatically via a direct REST call;
DigiCert reads a **persistent** DCV record set already in Route 53 and signs the
renewed certificate. Current main only has monitoring, not the active renewal path.

What is already in place (verified):

- `lemur/plugins/lemur_digicert/plugin.py:500-533` — `get_dcv_expiration_data()`
  reads DigiCert `/v2/domain` for persistent-DCV token expiry. This is used by the
  Celery `_emit_dcv_expiration_metrics` task to export monitoring metrics only; it
  does **not** request DCV.
- In `cloud-inventory`, `terraform-modules/aws-dns/main.tf:2-12` plus every zone
  module (e.g. `aws/prod/fgw--dns--public--datadoghq.com/main.tf:154-155`) already
  create `_dnsauth.<domain>` CNAME + `_validation-persist.<domain>` TXT records.
  CLOUDR-2118 is not referenced in the code, but the canonical form is present.

What is not yet in main:

- No `request_dcv` / `check_dcv` / renewal-driven DCV call in `lemur_digicert`.
- The automated-renewal glue in Celery `certificate_rotate` still delegates to
  the general rotation path; there is no DigiCert-specific pre-renewal DCV hook.

Source: `lemur/plugins/lemur_digicert/plugin.py`, `lemur/common/celery.py`

## cert-distribute Distribution

<!-- view: flow-distribution -->

cert-distribute manages Vault server TLS: it requests certificates from Lemur, reads
them from the Build Vault, and writes each site's cert into a **per-site CSP bucket**.
Each site datacenter's Vault server pulls its own TLS cert from that bucket;
cert-distribute never writes to a Vault server directly.

Source: in vault-platform, `README.md`

---

## Lemur

### Lemur

<!-- catalog: no-service -->

Datadog's fork of Netflix OSS Lemur. Three cooperating processes with a shared
PostgreSQL inventory:

- **Flask REST API + Web UI** — the synchronous surface every client talks to
  (`ddcert`, `lemur-agent`, `certificate-bootstrapping-agent`, `dc-registry`, humans).
  Validates the request, picks the right CA plugin and destination plugins from
  configuration, and writes the pending certificate row.
- **Celery worker pool** — runs the slow / fallible work: calls the CA plugin to
  issue, polls DCV + DigiCert order state, calls each destination plugin to deliver,
  retries, and runs the rotation / expiry scanners (`sync` and `rotate` beat tasks)
  on a schedule. All runtime side effects go through here, not the HTTP request.
- **PostgreSQL inventory** — the only centralized cert inventory at Datadog: every
  issued cert, its owner, authority, destinations, rotation history, and expiry.
  Reads from `ddcert` and the web UI go straight against this DB; the API never
  returns from a CA on the request path.

Lemur does not issue certificates itself. CA plugins (`lemur_digicert`,
`lemur_acme`, `lemur_sectigo`, `lemur_entrust`, `lemur_gcp`, `lemur_cfssl`) wrap each
upstream CA; destination plugins (`lemur_vault_dest`, `lemur_aws`, `lemur_gcp`,
`lemur_azure`) deliver the issued body + chain + key to each target. CA and
destination choice is per-cert configuration.

Source: `lemur/certificates/service.py`, `lemur/factory.py`,
`lemur/common/celery.py`, `lemur/plugins/`

### Lemur API

<!-- catalog: no-service -->

The synchronous entrypoint. Every client of Lemur (`ra_agent`, `ddcert`,
`dc-registry`, `cert-distribute`, the web UI, humans) talks to this process. It
validates the request, reads/writes the pending row in the inventory, picks the
right CA plugin and destination plugins from configuration (plugin registration
happens at app boot in `install_plugins`), and **enqueues** the slow work onto
Celery. The HTTP request returns long before the CA or destinations have been
touched; the API never returns from a CA on the request path.

Source: `lemur/certificates/views.py`, `lemur/factory.py`

### Lemur Celery

<!-- catalog: no-service -->

All runtime side effects run here. The worker pool executes each enqueued task —
call the CA plugin to issue, poll DCV + the CA's order state, call each destination
plugin to deliver, retry on failure, record the result in the inventory. The
Celery **beat** scheduler drives the periodic jobs: `sync_source` reconciles
pending orders with the upstream CA, and `certificate_rotate` scans for expiring
certs and calls `cli_certificate.rotate` → `deployment_service.rotate_certificate`
to update endpoints. The 71-day **IR-57191 silent-failure window was a
`certificate_rotate` task gap**, not an API gap: the task catches destination-plugin
exceptions and marks success even when an endpoint update silently fails. Automated
DCV on renewal (RDNA-1000) would hook into this same task but is not yet shipped.

Source: `lemur/common/celery.py`, `lemur/plugins/`

### Lemur inventory

<!-- catalog: no-service -->

Centralized certificate inventory (PostgreSQL): all certs, owners, expiry and history
in one place. This is what makes Lemur the single source of truth for the estate.

Source: `lemur/certificates/models.py`

## Clients of Lemur

### COA

<!-- catalog: no-service -->

Cert Orchestration Adapter — a Go service co-located with each Vault store that
validates and stores certificates in Vault KV via Emissary. Lemur's destination/source
plugins talk to COA over gRPC / xDCGW to push and query certs.

Source: `lemur/destinations/service.py`, `lemur/sources/service.py`

### certificate-bootstrapping-agent

<!-- catalog: no-service -->

Release-actions agent invoked with `dc boot` during DC turnup; creates certificates and
destinations, and registers new-DC domains with DigiCert. Reads Lemur credentials from
Vault, so it cannot run before Vault is up.

Source: `lemur/certificates/service.py`

### ddcert CLI

<!-- catalog: no-service -->

Human CLI to list certificates and destinations. Calls the Lemur API.

Source: `lemur/certificates/cli.py`

### Lemur Web UI

<!-- catalog: no-service -->

Human interface for certificate management. Calls the Lemur API.

Source: `lemur/certificates/views.py`

### dc registry

<!-- catalog: no-service -->

New client (Artifact Management): uses the release-actions agent to create an ACM
destination and certificate for a Fargate ALB.

Source: `lemur/certificates/service.py`

## Certificate authorities

### Certificate Authority (generic)

<!-- catalog: no-service -->

Placeholder for the upstream CA chosen for a given certificate. Lemur's CA plugins
wrap each supported authority — `lemur_digicert`, `lemur_acme` (Let's Encrypt),
`lemur_sectigo`, `lemur_entrust`, `lemur_gcp` and `lemur_cfssl` — and the per-cert
configuration decides which plugin is used. Overview and the Issue a Certificate
flow use this generic box to stay independent of CA choice; the Landscape and
Complete views enumerate every real CA.

Source: `lemur/plugins/`

### DigiCert

<!-- catalog: no-service -->

Primary certificate authority.

Source: `lemur/plugins/lemur_digicert/`

### Lets Encrypt

<!-- catalog: no-service -->

Certificate authority (ACME/DNS01); the migration target for DV certificates.

Source: `lemur/plugins/lemur_acme/`

### Sectigo

<!-- catalog: no-service -->

Premium certificate authority (OV/EV).

Source: `lemur/plugins/lemur_sectigo/`

### Entrust

<!-- catalog: no-service -->

Premium certificate authority (OV/EV).

Source: `lemur/plugins/lemur_entrust/`

### GCP CA

<!-- catalog: no-service -->

GCP certificate authority.

Source: `lemur/plugins/lemur_gcp/`

### CFSSL

<!-- catalog: no-service -->

Certificate authority.

Source: `lemur/plugins/lemur_cfssl/`

## Destinations

### COA to Vault KV

<!-- catalog: no-service -->

Destination: the site datacenter's **Vault KV**, where ISP and Edge certs land after
Lemur delivers them. Delivery goes through the **COA** cross-DC gRPC path from
ddbuild into each site; COA is the service that writes into the Vault KV. This box
represents the KV destination itself (owned by PPLAT / Identity), not the COA
service (shown separately as a client of Lemur).

Source: `lemur/destinations/service.py`, `lemur/plugins/lemur_vault_dest/`

### AWS IAM / CloudFront

<!-- catalog: no-service -->

Destination: AWS IAM / CloudFront (long-term ACM migration). Lemur uploads the renewed
cert body to IAM and switches the CloudFront distribution to the new IAM cert id.

Source: `lemur/plugins/lemur_aws/`

### AWS ACM

<!-- catalog: no-service -->

Destination: AWS Certificate Manager, reached via the ACM destination plugin
(CLOUDR-2056). ACM renews CloudFront / ALB certs natively once a cert is imported,
which removes the `lemur.managed` IAM boundary from the hot path over time.

Source: `lemur/plugins/lemur_aws/`

### lemur-managed IAM

<!-- catalog: no-service -->

**Status: planned IR-57191 remediation; not yet in main.** The intended model
is a tag-based boundary (`lemur.managed=true`) that gates which CloudFront
distributions and ACM resources Lemur is allowed to update, with Cloud Security
SCP approval needed to flip it from opt-in to opt-out.

Current main (verified absence):

- `lemur/plugins/lemur_aws/sts.py:20-73` — assumes a single IAM role via
  `LEMUR_INSTANCE_PROFILE`; no tag filtering.
- `lemur/plugins/lemur_aws/cloudfront.py` — `list_distributions()` returns every
  distribution the role can see and the rotation code acts on all of them; no
  `lemur.managed` tag check in main.
- The tag-based opt-out code exists on an in-flight branch (not merged).

IR-57191 traced to a CloudFront distribution outside the intended boundary; the
remediation is the opt-out rollout plus closing the silent-rotation path in
`certificate_rotate` (see Lemur Celery panel).

Source: `lemur/plugins/lemur_aws/sts.py`, `lemur/plugins/lemur_aws/cloudfront.py`

### Route 53

<!-- catalog: no-service -->

AWS Route 53 hosted zones. Carries two independent cert workloads: the DNS01 ACME
challenge records written by cert-manager (ephemeral, per-challenge) and the
**persistent** DCV TXT/CNAME records read by DigiCert on every Lemur renewal.

Source: in k8s-platform-resources, `README.md`

### cloud-inventory DNS

<!-- catalog: no-service -->

The `cloud-inventory` Terraform repo (not a service) that manages the persistent
DCV TXT/CNAME record set in Route 53. Verified: `terraform-modules/aws-dns/main.tf`
default-enables both records for every zone the module instantiates, and every
public domain's zone module (e.g.
`aws/prod/fgw--dns--public--datadoghq.com/main.tf:154-155`) declares them in a
single canonical shape — `_dnsauth.<domain>` CNAME to DigiCert, plus
`_validation-persist.<domain>` TXT carrying both the DigiCert and Sectigo
account URIs. These records are applied **once per domain**, not per renewal.

CLOUDR-2118 attribution is **not** present in the code itself; the canonical form
is in place but the ticket number is not referenced. The claim that these changes
flow through SDP is false in general — cloud-inventory applies most zones
directly to Route 53. It does **NS-delegate** some transit subzones to accounts
owned by SDP terraform (see the SDP DNS panel).

Source: in cloud-inventory, `terraform-modules/aws-dns/main.tf`,
`aws/prod/fgw--dns--public--datadoghq.com/main.tf`

### SDP DNS

<!-- catalog: no-service -->

**Correction after code review.** SDP / Fabric does **not** own or enforce the DNS
zones that carry the persistent DCV records; that was imprecise. What's actually
true:

- A subset of hosted zones is managed by **SDP's own Terraform**
  (in `service-discovery-platform`, `terraform/dns/` — e.g.
  `terraform/dns/edge-uk1.prod.dog/main.tf` calling `modules/aws-dns`). SDP
  terraform applies these zones **directly to Route 53**, not through a Fabric
  control plane.
- The rest of the zones (including the main public domains that carry the DCV
  records) are managed by **cloud-inventory Terraform**, also directly against
  Route 53.
- cloud-inventory sometimes **NS-delegates** transit subzones into accounts that
  SDP terraform owns (e.g. `cloud-inventory` ↝
  `aws/prod/fgw--dns--public--datadoghq.com/main.tf:238` notes
  "NS delegation for prtest08.datadoghq.com — zone managed in the prtest08
  transit account by SDP terraform").

There is no Fabric service that intercepts or enforces DNS writes at runtime —
no `ZoneChange` / `zone-change` / `dns-enforce` proto or service exists in
`service-discovery-platform`. So the Automated DCV path does not inherit any
Fabric runtime guarantee; its guarantee comes from the Terraform discipline
(records applied once, canonical form) that **cloud-inventory** enforces at plan
time.

Source: in service-discovery-platform, `terraform/dns/dns.hcl`,
`terraform/dns/README.md`; in cloud-inventory,
`aws/prod/fgw--dns--public--datadoghq.com/main.tf`

### GCP Load Balancer

<!-- catalog: no-service -->

Destination: GCP load balancer certificates.

Source: `lemur/plugins/lemur_gcp/`

### Azure Key Vault

<!-- catalog: no-service -->

Destination: Azure Key Vault.

Source: `lemur/plugins/lemur_azure/`

### Build Vault

<!-- catalog: no-service -->

Destination used by cert-distribute for Vault server TLS.

Source: `lemur/plugins/lemur_vault_dest/`

## Ancillary systems

### ddbuild

<!-- catalog: no-service -->

**ddbuild** is the control-plane datacenter site where **Lemur** and its PostgreSQL
inventory live, along with **cert-distribute** and the **Build Vault**. This is where
certificates are issued and recorded; they then flow **out of ddbuild** to site
datacenters and CSP destinations.

Source: `lemur/certificates/service.py`

### Site Datacenter

<!-- catalog: no-service -->

Every commercial site datacenter (us1, us3, us5, eu1, eu3, ap1, ap3, …) is the place
certificates are delivered into: **COA → Vault KV** holds the Edge/ISP certs that
**Envoy** terminates TLS with, and each datacenter's **dedicated-vault / Vault server**
gets its bootstrap and server TLS via cert-manager and cert-distribute respectively.
A DC turnup bootstraps a new site datacenter before its own Vault is reachable (Phase 0
via cert-manager), then continues with post-Vault certificate creation from ddbuild
(Phase 1 via the certificate-bootstrapping-agent → Lemur → COA).

Source: `lemur/certificates/service.py`

### cert-manager

<!-- catalog: no-service -->

CNCF Kubernetes controller that issues certificates directly to CAs via Issuer CRDs,
storing the result as Kubernetes Secrets. Owns the Layer 0 pre-Vault bootstrap
(dedicated-vault) path.

Source: in k8s-platform-resources, `README.md`

### cert-distribute vault-pki

<!-- catalog: no-service -->

A **systemd sidecar** that runs on each Vault node (`cert-distribute service
vault-pki`). It polls the per-site cert bucket on an interval (default 2h, 1 min
on error), writes the pulled cert to `/var/lib/vault/pki/cert.pem` and `key.pem`
on local disk, and reloads Vault by sending `SIGHUP` or running
`systemctl reload vault.service`. **This**, not the Vault server, is what reads
from the cert bucket. Communication is file + signal, not RPC.

Source: in vault-platform, `cmd/cert-distribute/internal/cmd/service.go`,
`cmd/cert-distribute/internal/maintainer/maintainer.go`,
`ansible/roles/vault/templates/systemd/cert-distribute.service`

### cert-distribute

<!-- catalog: no-service -->

Tool managing Vault server TLS certificates; reads certs from the Build Vault and
distributes them via buckets to each target Vault.

Source: in vault-platform, `README.md`

### Envoy

<!-- catalog: no-service -->

Datacenter edge / ingress proxy that terminates TLS for public and internal endpoints.
Consumes the Edge certificates that Lemur issues and delivers via COA → Vault KV, and
maintains a CA trust bundle that must include Let's Encrypt's ISRG Root X1 after the LE
migration.

Source: in dd-source, `README.md`

### dedicated-vault

<!-- catalog: no-service -->

The Vault instance that handles a new datacenter's secrets; needs a TLS certificate
before it can start and unseal, provided by cert-manager in Phase 0.

Source: in k8s-platform-resources, `README.md`

### cert bucket

<!-- catalog: no-service -->

Per-site CSP bucket that cert-distribute writes Vault-server TLS certificates
into. One bucket per Vault host, named `certs.{vault_host}` (normalised to
`certs-{vault_host}` on GCP/Azure); backed by S3, GCS or Azure Blob depending on
the site. Objects default to `certs/cert.pem` and `certs/key.pem`.

The local Vault server does **not** pull from this bucket itself. The pull is
done by **cert-distribute's own `vault-pki` sidecar** (one per Vault node): see
the "cert-distribute vault-pki" panel.

Source: in vault-platform, `cmd/cert-distribute/internal/distribute/bucket.go`,
`cmd/cert-distribute/internal/distribute/remote_cert_manager.go`

### Vault server

<!-- catalog: no-service -->

The Vault service endpoints whose server TLS certificates cert-distribute maintains.

Source: in vault-platform, `README.md`
