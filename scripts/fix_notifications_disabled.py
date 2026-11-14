#!/usr/bin/env python
"""
ONE-SHOT fix: re-enable notifications on certs that have notifications disabled
and were NOT replaced.

Background
----------
Replaced certs are auto-muted via the `Certificate.replaces` append event listener
(models.py), so notifications off on a replaced cert is expected and must NOT be
touched. The only real operator error is a cert with notifications disabled that
was NEVER replaced. This script finds exactly those and (optionally) re-enables
notifications on them. After applying, it forces an immediate rerun of the
certificate health check so the CRDL022 dashboard reflects the fix immediately.

How to run (end-to-end)
-----------------------
The script needs the Lemur app context and real DB config, which only exist inside
the running lemur pod. Run it there via kubectl. These commands are copy-pasteable:
(POD is a BARE pod name — no namespace prefix; the namespace comes from `-n`.)

# 1) Point kubectl at the right cluster (e.g. prod):
    kubectl config use-context build1.us1.ddbuild.io

# 2) Resolve the lemur pod name, then copy the script into its lemur container:
    POD=$(kubectl -n cert-orchestration get pods -l app=lemur --no-headers \
        -o custom-columns=:.metadata.name | head -1)
    echo "POD=$POD"
    kubectl -n cert-orchestration cp scripts/fix_notifications_disabled.py \
        "$POD":/tmp/fix.py -c lemur

# 3) DRY-RUN (default — lists candidates, changes nothing):
    kubectl -n cert-orchestration exec "$POD" -c lemur -- \
        /opt/venv/bin/python /tmp/fix.py

# 4) Review the printed list, then APPLY (sets notify=True on those certs):
    kubectl -n cert-orchestration exec "$POD" -c lemur -- \
        /opt/venv/bin/python /tmp/fix.py --apply

# Apply AND dispatch the certificate_health_check celery task to the worker
# (instead of rerunning the health metrics in-process):
    kubectl -n cert-orchestration exec "$POD" -c lemur -- \
        /opt/venv/bin/python /tmp/fix.py --apply --celery

# Test ONE cert first (dry-run, then apply) before the full batch:
    kubectl -n cert-orchestration exec "$POD" -c lemur -- \
        /opt/venv/bin/python /tmp/fix.py --cert-id 1452
    kubectl -n cert-orchestration exec "$POD" -c lemur -- \
        /opt/venv/bin/python /tmp/fix.py --cert-id 1452 --apply

Why this works: inside the pod, `create_app(None)` resolves the config from the
`LEMUR_CONF` env var (/etc/lemur/lemur.conf.py), which the deployment already sets,
so no `--config` is needed in the pod.
"""
import argparse
import os
import sys

import arrow
from sqlalchemy.sql.expression import false

from lemur import create_app, database
from lemur.certificates import health as certificate_health
from lemur.certificates.models import Certificate


def rerun_health_check(via_celery=False):
    """Force the certificate health check to rerun after applying a fix.

    By default this re-emits health metrics in-process via
    send_certificate_health_metrics() (same code path as the celery task). Pass
    via_celery=True to instead dispatch the real celery task
    (lemur.common.celery.certificate_health_check) to the broker/worker.

    Note: send_task enqueues asynchronously; the worker runs it on its own
    cadence. Run inside an active Flask app context.
    """
    if via_celery:
        from lemur.common.celery import celery_app
        print("\nDispatching certificate_health_check celery task to the worker ...")
        async_result = celery_app.send_task(
            "lemur.common.celery.certificate_health_check"
        )
        print(
            "Task dispatched (async id=%s). The worker will emit updated health "
            "metrics on its next run." % async_result.id
        )
        return

    print("\nForcing a rerun of the certificate health check (in-process) ...")
    summary = certificate_health.send_certificate_health_metrics()
    print("Health check rerun complete:")
    print(f"  certificates_checked = {summary['certificates_checked']}")
    print(f"  unhealthy_certificates = {summary['unhealthy_certificates']}")
    print(f"  failed_checks = {summary['failed_checks']}")
    print(f"  errors = {summary['errors']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="Persist changes (set notify=True). Dry-run by default.")
    parser.add_argument("--config", default=None,
                        help="Path to lemur.conf.py. If omitted, the app resolves it via "
                             "LEMUR_CONF or the default ~/.lemur/lemur.conf.py.")
    parser.add_argument("--cert-id", type=int, default=None,
                        help="Restrict to a single certificate id (e.g. test one first). "
                             "Skips eligibility checks; use with --apply to touch only it.")
    parser.add_argument("--celery", action="store_true",
                        help="After apply, dispatch the certificate_health_check celery "
                             "task to the worker instead of rerunning in-process.")
    args = parser.parse_args()

    apply = args.apply
    app = create_app(args.config)
    with app.app_context():
        if args.cert_id is not None:
            # Targeted mode: act on exactly this one cert, regardless of replaced state.
            target = Certificate.query.get(args.cert_id)
            if target is None:
                print(f"No certificate with id={args.cert_id}.")
                return
            print("=" * 70)
            print(f"TARGETED mode: cert id={target.id}")
            print(f"  cn={target.cn!r} owner={target.owner or 'N/A'!r}")
            print(f"  notify={target.notify} rotation={target.rotation} replaced={bool(target.replaced)}")
            print(f"  {'DRY-RUN - would set notify=True' if not apply else 'APPLY - setting notify=True'}")
            print("=" * 70)
            if not apply:
                print("Dry run complete. Re-run with --apply to persist.")
                return
            if target.notify is not True:
                target.notify = True
                database.update(target)
                print(f"Fixed cert id={target.id} (notify=True).")
            else:
                print(f"Cert id={target.id} notify is already True; no change.")
            rerun_health_check(via_celery=args.celery)
            return

        # Same eligibility as the CRDL022 health-check query: not deleted, not
        # expired, not revoked. Then restrict to notify==False (disabled).
        candidates = (
            Certificate.query
            .filter(Certificate.deleted.isnot(True))
            .filter(Certificate.not_after > arrow.utcnow())
            .filter(Certificate.revoked == false())
            .filter(Certificate.notify.is_(False))
            .order_by(Certificate.id)  # noqa
            .all()
        )

        # Only certs that were NOT replaced are true errors; skip replaced ones.
        unreplaced = [c for c in candidates if not c.replaced]
        skipped = [c for c in candidates if c.replaced]

        print("=" * 70)
        print(f"Candidates (notify disabled, valid):  {len(candidates)}")
        print(f"  -> NOT replaced (to fix):           {len(unreplaced)}")
        print(f"  -> replaced (skipped, expected):    {len(skipped)}")
        print(f"Mode: {'APPLY  (notify will be set to True)' if apply else 'DRY-RUN (no changes)'}")
        print("=" * 70)

        for c in unreplaced:
            print(
                f"[{c.id:4d}] notify={c.notify} rotation={c.rotation} "
                f"cn={c.cn!r} owner={c.owner or 'N/A'!r}"
            )

        if unreplaced:
            print(f"\nWould fix {len(unreplaced)} certs.")

        if not apply:
            print("Dry run complete. Re-run with --apply to persist changes.")
            return

        print("\nApplying: setting notify=True ...")
        fixed = 0
        for c in unreplaced:
            if c.notify is not True:
                c.notify = True
                database.update(c)
                fixed += 1
        print(f"Fixed {fixed} certs.")
        rerun_health_check(via_celery=args.celery)
        print("Done.")


if __name__ == "__main__":
    main()
