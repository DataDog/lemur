"""
Lemur monitoring tasks.

Tasks here are pure observability: they read DB state and emit metrics. They
must not mutate state. Business-logic Celery tasks (cert rotation, source
sync, etc.) live in lemur/common/celery.py or in the relevant domain package.
"""

import sys
from flask import current_app

from lemur.common.celery import celery_app
from lemur.extensions import metrics


@celery_app.task(soft_time_limit=600)
def check_source_destination_parity():
    """
    Strict 1:1 parity check between sources and destinations: every source label
    should have a destination with the exact same label, and vice versa. This
    mirrors the auto-attach contract in `lemur/sources/service.py:sync_update_destination`,
    where source-imported certs get a destination automatically only when the
    labels match exactly. Drift (a renamed source, or a destination added without
    its discovery counterpart) breaks that loop silently.

    Emits two gauges plus per-label counters so the Datadog monitor can both alert
    on the aggregate count and surface which specific labels are unpaired.
    """
    function = f"{__name__}.{sys._getframe().f_code.co_name}"

    from lemur.sources.models import Source
    from lemur.destinations.models import Destination

    source_labels = {s.label for s in Source.query.all() if s.label}
    destination_labels = {d.label for d in Destination.query.all() if d.label}

    destinations_missing_source = destination_labels - source_labels
    sources_missing_destination = source_labels - destination_labels

    metrics.send(
        "lemur.parity.destinations_missing_source",
        "gauge",
        len(destinations_missing_source),
    )
    metrics.send(
        "lemur.parity.sources_missing_destination",
        "gauge",
        len(sources_missing_destination),
    )

    for label in destinations_missing_source:
        metrics.send(
            "lemur.parity.unmatched_destination",
            "counter",
            1,
            metric_tags={"label": label},
        )
    for label in sources_missing_destination:
        metrics.send(
            "lemur.parity.unmatched_source",
            "counter",
            1,
            metric_tags={"label": label},
        )

    log_data = {
        "function": function,
        "message": "Source/destination parity check complete",
        "destinations_missing_source": sorted(destinations_missing_source),
        "sources_missing_destination": sorted(sources_missing_destination),
    }
    current_app.logger.info(log_data)
    metrics.send(f"{function}.success", "counter", 1)
    return log_data
