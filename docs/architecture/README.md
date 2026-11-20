# Certificate Architecture

A source-backed interactive reference for Datadog TLS certificate management: the
systems around **Lemur**, how a certificate is requested, issued, delivered and
trusted, and the behaviour flows that follow one triggered path. Architecture views
map components and dependencies; flow views follow numbered, evidence-backed steps.
The reference is not live status or proof of runtime success.

This is built with the `architecture-sites` plugin (`building-architecture-sites`
skill) from ddoghq/claude-marketplace — the same tooling as Fabric Architecture.

## Sources and Ownership

- `model.yaml` — site settings, light/dark connection palettes, nodes, architecture
  membership, flow scenarios and ordered steps.
- `lemur-certificate-architecture.md` — view guides (`##` plus `<!-- view: id -->`)
  and component/frame panels (`###` plus `<!-- catalog: -->`), with `Source:`
  citations.
- `generate-diagram.py` — validation, d2 layout (TALA/ELK), JSON export.
- `src/` — React/Druids interface, styles, unit tests and Python browser gates
  (`check-geometry.py`, `check-ui.py`).

Every edge and factual claim needs repository code/configuration evidence or an
explicitly unverified note. This site is **seeded from the "Datadog Certificate
Management — Organizational North Star" investigation**: several components and flow
steps are marked `unverified` until a refresh pass re-checks them against this
repository and the cited external repositories (`dd-source`, `vault-platform`,
`k8s-platform-resources`).

## Conventions

- Colour is a connection family (`flows:`), with `color` and `dark_color`; line style
  is the interaction: solid call/write, dashed read/watch (arrow points the way data
  flows), thick request traffic.
- Shape is ownership/type (`shapes:`); there are no frames in this model yet.
- Architecture membership comes from `edges[].views`. Flows use `category: flow`, a
  scenario and 3–8 ordered steps that reference base `(from, to)` pairs; numbers
  derive from list order. Never add flow IDs to base-edge membership.
- Every flow step is `unverified` for now and carries a note. To verify, add real
  source paths (`sources:`) and mark `verification: verified`.
- Component panels separate `Source:` paragraphs into collapsed Sources lists.

## Generate and Validate

Requires `uv` and d2 v0.9.0 or later (with TALA). A d2 with TALA is required; install
one you can put on PATH (e.g. the v0.9.0 release binary), then:

```sh
export PATH="$HOME/.local/d2bin:$PATH"   # or wherever your d2-with-TALA lives
./generate-diagram.py --check            # validate model + prose (no d2 layout needed)
./generate-diagram.py --output dist      # emit dist/src/architecture-data.json
```

`--check` validates `model.yaml` and `lemur-certificate-architecture.md` against each
other. Generation lays out each view with d2 (TALA for architecture, ELK for flows)
and writes the JSON the React app imports. Generated `dist/`, d2 and JSON are not
committed.

## Local Preview

The full React + Druids app is a web-ui static-app and needs a `web-ui` checkout to
run (`yarn dev`), which is a later phase. Without web-ui you can still preview the
diagrams by rendering each view's d2 to an SVG:

```sh
uv run --with markdown-it-py --with 'pyyaml>=6,<7' python -c "..."  # or use --d2
./generate-diagram.py --d2 /tmp/d2
d2 --omit-version /tmp/d2/overview.d2 overview.svg   # substitute __SEED__ first for TALA views
```

See the notebook north star for the org-level context this reference summarizes.

## Hosting and Measurement (later phase)

The native host is a web-ui static-app (`site.app: certificate-architecture`).
Deployment uses SPA serving and an internal-services proxy; routing-domain
registration is an owner-approved operation. Optional `site.rum` is currently `null`
until hosting and an application id are approved. A periodic refresh DDWorkflow can
re-check drift once the source is published.
