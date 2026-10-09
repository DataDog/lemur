# lemur-cert-cost

> Lives in the `DataDog/lemur` repo at `tools/lemur_cert_cost/`.

CA‑agnostic cost metrics + dashboard for the public TLS certificates managed by
**Lemur**. Turns Lemur's inventory and each CA's billing feed into Datadog
custom metrics (`lemur.cert.cost.*`) and a “Cost of Lemur” dashboard.

There is **no built‑in cost metric on Lemur** — DigiCert/Sectigo/Let's Encrypt
bill on issuance, not continuously. So cost has to be *derived* from a current
inventory snapshot plus a pricing table, refreshed on a schedule. This tool does
exactly that, and it’s **CA‑agnostic**: adding a CA is a pricing‑table + adapter
change, not a rewrite.

## Architecture

```
 Lemur inventory   ─┐
 DigiCert actuals  ─┼─►  engine.py  ──►  emit.py  ──►  Datadog custom metrics
 Sectigo actuals   ─┘     (pricing)         └────────►  dashboard.py (JSON)
 ```

- `pricing.py` — per‑CA pricing keyed by `(ca, validation_tier, shape)`. Adding
  Sectigo/SSL.com/ACM is a data change.
- `engine.py` — joins inventory + actuals, prices each cert, detects orphans.
- `clients/` — one read‑only adapter per CA (Lemur, DigiCert, Sectigo).
- `emit.py` — low‑cardinality metric payloads + 3 emission modes.
- `dashboard.py` — Datadog v1 dashboard JSON.
- `cli.py` — entrypoint.

## Run

```bash
# No credentials needed — bundled sample data:
python -m lemur_cost.cli run --sample

# Against real Lemur (read only) + optional CA actuals, emit to Datadog:
export LEMUR_URL=https://lemur-commercial.us1.ddbuild.io
export LEMUR_TOKEN=$(workspace_secret LEMUR_TOKEN)
export DIGICERT_API_KEY=$(workspace_secret DIGICERT_API_KEY)   # optional actuals
export SECTIGO_ENABLED=true SECTIGO_USERNAME=... SECTIGO_PASSWORD=...
export DD_API_KEY=... LEMUR_COST_MODE=datadog
python -m lemur_cost.cli run

# Print a dry run first (no external calls):
LEMUR_COST_MODE=print python -m lemur_cost.cli run

# Generate the dashboard JSON:
python -m lemur_cost.cli dashboard --output dashboards/cost-of-lemur.json
```

Install once: `pip install -r requirements.txt` (or `pip install -e .`).

### Scheduled emission

Run the exporter on a cron/launchd/Celery‑beat schedule (daily). Because cost is
a point‑in‑time gauge, frequency controls freshness — daily is plenty.

## Metrics emitted

| metric | type | tag | meaning |
|--------|------|-----|---------|
| `lemur.cert.cost.monthly` | gauge | `env` | grand total $/mo |
| `lemur.cert.cost.annual` | gauge | `env` | grand total $/yr |
| `lemur.cert.cost.monthly_by_ca` | gauge | `ca` | $/mo per CA |
| `lemur.cert.cost.monthly_by_owner` | gauge | `owner` | $/mo per team |
| `lemur.cert.cost.monthly_by_zone` | gauge | `dc_zone` | $/mo per DC zone |
| `lemur.cert.cost.orphaned` | gauge | `ca` | wasted $/mo on unused certs |
| `lemur.cert.count` | gauge | `ca` | active cert count per CA |
| `lemur.cert.issued.count` | count | — | issuance rate (optional hook) |

Each is single‑tagged to keep cardinality low. `ca` is normalized to
`digicert | sectigo | letsencrypt | acm | gov | unknown`.

## Adding a CA (e.g. SSL.com)

1. `pricing.py`: add a `PRICING[ca][tier][shape]` block + an `AUTHORITY_CA_MAP` row.
2. `clients/`: add an adapter returning `BillingActual` list (or skip — estimates
   still work off inventory + pricing).
3. Nothing else: metrics and dashboard pick up the new `ca` tag automatically.

## Tests

```bash
python -m pytest -q
```

## Caveats

- **Prices are estimates** with a pricing table; reconcile against CA billing
  feeds (`actuals`) so estimates don't drift. `source: actual` marks rows matched
  to a billing feed.
- Orphan detection mirrors CLOUDR‑1957: certs with no destinations, no
  endpoints, and not an in‑rotation successor are counted as wasted spend.
- GovCloud (`*.fed.dog` / `*.ddog-gov.com`) certs are priced under the `gov` CA.
