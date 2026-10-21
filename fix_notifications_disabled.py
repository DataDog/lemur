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
notifications on them.

Use
---
    # dry-run (default): list candidates, make no changes
    python fix_notifications_disabled.py

    # apply: set notify=True on candidates
    python fix_notifications_disabled.py --apply

    # explicit config path (optional); otherwise the app resolves it via the
    # LEMUR_CONF env var (in-cluster: /etc/lemur/lemur.conf.py) or the default
    # ~/.lemur/lemur.conf.py, matching how `lemur` itself bootstraps.
    python fix_notifications_disabled.py --config /path/to/lemur.conf.py --apply
"""
import argparse
import os
import sys

import arrow
from sqlalchemy.sql.expression import false

from lemur import create_app
from lemur.certificates.models import Certificate
from lemur import database


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="Persist changes (set notify=True). Dry-run by default.")
    parser.add_argument("--config", default=None,
                        help="Path to lemur.conf.py. If omitted, the app resolves it via "
                             "LEMUR_CONF or the default ~/.lemur/lemur.conf.py.")
    args = parser.parse_args()

    apply = args.apply
    app = create_app(args.config)
    with app.app_context():
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
        print("Done.")


if __name__ == "__main__":
    main()
