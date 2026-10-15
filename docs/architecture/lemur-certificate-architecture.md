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
plugin. Certificate delivery to Vault KV goes through the **COA** (Cert Orchestration
Adapter). Alongside Lemur, **cert-manager** issues the pre-Vault bootstrap certificate
that dedicated-vault needs to start, and **cert-distribute** handles Vault server TLS.

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

## cert-distribute Distribution

<!-- view: flow-distribution -->

cert-distribute manages Vault server TLS: it requests certificates from Lemur, reads
them from the Build Vault, and distributes them via buckets to each target Vault.

Source: in vault-platform, `README.md`

---

## Lemur

### Lemur

<!-- catalog: no-service -->

Datadog's fork of Netflix OSS Lemur: a REST API and web UI that brokers TLS certificate
issuance between callers and upstream CAs. It does not issue certificates itself — it
delegates to CA plugins and pushes issued certs to destination plugins.

Source: `lemur/certificates/service.py`

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

### NOM

<!-- catalog: no-service -->

Legacy DC turnup automation, being replaced by Release Actions.

Source: `lemur/certificates/cli.py`

## Certificate authorities

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

Destination: cross-DC Vault KV delivery for ISP and Edge certificates.

Source: `lemur/destinations/service.py`, `lemur/plugins/lemur_vault_dest/`

### AWS IAM / CloudFront

<!-- catalog: no-service -->

Destination: AWS IAM / CloudFront (long-term ACM migration).

Source: `lemur/plugins/lemur_aws/`

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

### cert-manager

<!-- catalog: no-service -->

CNCF Kubernetes controller that issues certificates directly to CAs via Issuer CRDs,
storing the result as Kubernetes Secrets. Owns the Layer 0 pre-Vault bootstrap
(dedicated-vault) path.

Source: in k8s-platform-resources, `README.md`

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

### Vault server

<!-- catalog: no-service -->

The Vault service endpoints whose server TLS certificates cert-distribute maintains.

Source: in vault-platform, `README.md`
