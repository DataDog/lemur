"""Run the isolated Lemur sandbox test suite through a real Celery worker."""

import json
import time
import uuid
from contextlib import contextmanager

from flask import current_app
from sqlalchemy.sql import text

from lemur.common.celery import celery_app
from lemur.common.redis import RedisHandler
from lemur.extensions import db, metrics
from lemur.test.catalog import scenarios, validate_task_catalog


LOCK_KEY = "lemur-test:run-lock"


def validate_isolation():
    """Refuse to run unless every destructive isolation boundary is active."""
    if not current_app.config.get("LEMUR_TEST_ENABLED", False):
        raise RuntimeError("LEMUR_TEST_ENABLED must be true")

    identity = db.engine.execute(
        text("SELECT current_database(), current_user")
    ).fetchone()
    expected_database = current_app.config.get("LEMUR_TEST_DATABASE", "test")
    expected_user = current_app.config.get("LEMUR_TEST_DATABASE_USER", "lemur_test")
    if tuple(identity) != (expected_database, expected_user):
        raise RuntimeError(
            "Refusing to run against database={!r}, user={!r}; expected database={!r}, user={!r}".format(
                identity[0], identity[1], expected_database, expected_user
            )
        )

    redis_db = current_app.config.get("REDIS_DB")
    expected_redis_db = current_app.config.get("LEMUR_TEST_REDIS_DB", 1)
    if redis_db != expected_redis_db:
        raise RuntimeError(
            "Refusing to run against Redis database {!r}; expected {!r}".format(
                redis_db, expected_redis_db
            )
        )

    queue = current_app.config.get("LEMUR_TEST_QUEUE", "lemur-test")
    if current_app.config.get("CELERY_DEFAULT_QUEUE", queue) != queue:
        raise RuntimeError("CELERY_DEFAULT_QUEUE must match LEMUR_TEST_QUEUE")


@contextmanager
def run_lock(run_id):
    """Prevent concurrent manual and scheduled test runs."""
    redis_client = RedisHandler().redis()
    timeout = current_app.config.get("LEMUR_TEST_LOCK_SECONDS", 3 * 60 * 60)
    acquired = redis_client.set(LOCK_KEY, run_id, nx=True, ex=timeout)
    if not acquired:
        owner = redis_client.get(LOCK_KEY)
        raise RuntimeError("Another Lemur test run holds the lock: {}".format(owner))
    try:
        yield
    finally:
        if redis_client.get(LOCK_KEY) == run_id:
            redis_client.delete(LOCK_KEY)


def _selected_scenarios(task_names=None):
    configured = current_app.config.get("LEMUR_TEST_TASK_SCENARIOS", {})
    resolved = scenarios(configured)
    if not task_names:
        return resolved

    unknown = sorted(set(task_names) - set(resolved))
    if unknown:
        raise RuntimeError("Unknown requested tasks: {}".format(", ".join(unknown)))
    return {name: resolved[name] for name in task_names}


def run(task_names=None, timeout=None):
    """Dispatch cataloged tasks sequentially and wait for their real results."""
    validate_isolation()
    validate_task_catalog(celery_app)

    run_id = str(uuid.uuid4())
    queue = current_app.config.get("LEMUR_TEST_QUEUE", "lemur-test")
    timeout = timeout or current_app.config.get("LEMUR_TEST_TASK_TIMEOUT", 2 * 60 * 60)
    results = []
    started = time.time()

    with run_lock(run_id):
        for task_name, scenario in _selected_scenarios(task_names).items():
            task_started = time.time()
            entry = {"task": task_name, "status": "failed"}
            try:
                result = celery_app.send_task(
                    task_name,
                    args=scenario.args,
                    kwargs=scenario.kwargs,
                    queue=queue,
                )
                entry["task_id"] = result.id
                entry["result"] = result.get(timeout=timeout, propagate=True)
                entry["status"] = "passed"
                metrics.send(
                    "test.task.success",
                    "counter",
                    1,
                    metric_tags={"task_name": task_name, "run_id": run_id},
                )
            except Exception as error:
                entry["error"] = repr(error)
                metrics.send(
                    "test.task.failure",
                    "counter",
                    1,
                    metric_tags={"task_name": task_name, "run_id": run_id},
                )
            finally:
                entry["duration_seconds"] = round(time.time() - task_started, 3)
                results.append(entry)

    report = {
        "run_id": run_id,
        "status": "passed" if all(r["status"] == "passed" for r in results) else "failed",
        "duration_seconds": round(time.time() - started, 3),
        "tasks": results,
    }
    metrics.send(
        "test.run.success",
        "gauge",
        1 if report["status"] == "passed" else 0,
        metric_tags={"run_id": run_id},
    )
    current_app.logger.info({"message": "Lemur test run complete", **report})
    return report


def render_report(report):
    """Return stable JSON suitable for logs and manual invocations."""
    return json.dumps(report, sort_keys=True, default=str)

