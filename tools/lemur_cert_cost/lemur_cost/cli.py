"""CLI entrypoint for the Lemur cert cost exporter.

Run modes:
  python -m lemur_cost.cli run         # fetch inventory + actuals, compute cost
  python -m lemur_cost.cli run --sample  # use bundled sample data (no creds)
  python -m lemur_cost.cli dashboard   # write the Datadog dashboard JSON
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .config import Config
from .engine import build_report, summarize_counts, CostReport
from .emit import DatadogEmitter, StatsdEmitter, emit, render_report
from .models import CertRecord


def _build_report(config: Config, use_sample: bool, sample_certs: List[CertRecord]) -> CostReport:
    """Collect inventory (+ optional CA actuals) and produce a CostReport."""
    pricing = config.load_pricing()

    if use_sample:
        certs = sample_certs
        actuals = None
    else:
        if not (config.lemur_url and config.lemur_token):
            raise SystemExit(
                "LEMUR_URL and LEMUR_TOKEN are required. "
                "Or pass --sample to run against bundled test data."
            )
        from .clients.lemur_client import LemurClient

        lemur = LemurClient(config.lemur_url, config.lemur_token)
        certs = lemur.list_certificates(active_only=config.lemur_active_only)

        actuals = []
        if config.digicert_api_key:
            from .clients.digicert_client import DigiCertClient

            digi = DigiCertClient(config.digicert_api_key, config.digicert_base_url)
            actuals += digi.get_domains()
            actuals += digi.get_orders()
        if config.sectigo_enabled:
            from .clients.sectigo_client import SectigoClient

            sectigo = SectigoClient(
                config.sectigo_base_url,
                config.sectigo_username,
                config.sectigo_password,
            )
            sectigo.login()
            actuals += sectigo.get_dcv_validation()
            sectigo.close()

    return build_report(certs, actuals=actuals or None, pricing=pricing)


def _make_emitter(config: Config):
    if config.mode == "datadog":
        return DatadogEmitter(config.dd_api_key, config.dd_app_key, config.dd_site)
    if config.mode == "statsd":
        return StatsdEmitter(config.statsd_host, config.statsd_port)
    return None


def cmd_run(args: argparse.Namespace) -> int:
    config = Config.from_env()
    if args.mode:
        config.mode = args.mode

    from . import sample

    report = _build_report(config, args.sample, sample.certs())

    # Counts need derived fields populated; re-derive cheaply from report rows.
    counts = summarize_counts([r.cert for r in report.rows if r.cert])

    if config.mode == "print" or args.sample:
        print(render_report(report, counts))
        if args.json:
            print(json.dumps(report.summary(), indent=2))
        return 0

    emitter = _make_emitter(config)
    payload = emit(report, counts, mode=config.mode, emitter=emitter)
    print(f"emitted {len(payload['series'])} metric series ({config.mode})")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    from .dashboard import write_dashboard

    path = write_dashboard(args.output, args.title)
    print(f"wrote dashboard JSON -> {path}")
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lemur-cert-cost", description="CA-agnostic cost of Lemur certs")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="compute and emit cert cost metrics")
    run.add_argument("--sample", action="store_true", help="use bundled sample data (no credentials)")
    run.add_argument("--mode", choices=["print", "datadog", "statsd"], help="override emission mode")
    run.add_argument("--json", action="store_true", help="also print JSON summary")
    run.set_defaults(func=cmd_run)

    dash = sub.add_parser("dashboard", help="write the Datadog dashboard JSON")
    dash.add_argument("--output", default="dashboards/cost-of-lemur.json")
    dash.add_argument("--title", default="Cost of Lemur")
    dash.set_defaults(func=cmd_dashboard)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
