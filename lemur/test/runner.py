"""Run the isolated Lemur sandbox test suite through a real Celery worker."""

import json
import time
import uuid
from contextlib import contextmanager

from flask import current_app

from lemur.extensions import db
from lemur.common.celery import celery_app
from lemur.common.redis import RedisHandler
from lemur.extensions import metrics
from lemur.test.catalog import scenarios, validate_task_catalog
from lemur.test.database import reset_and_seed, validate_database_identity
from lemur.test import fixtures

LOCK_KEY = "lemur-test:run-lock"


def validate_isolation():
    """Refuse to run unless every destructive isolation boundary is active."""
    if not current_app.config.get("LEMUR_TEST_ENABLED", False):
        raise RuntimeError("LEMUR_TEST_ENABLED must be true")

    validate_database_identity()

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


def run(task_names=None, timeout=None, reset_database=False):
    """Dispatch cataloged tasks sequentially and wait for their real results."""
    validate_isolation()
    validate_task_catalog(celery_app)

    run_id = str(uuid.uuid4())
    queue = current_app.config.get("LEMUR_TEST_QUEUE", "lemur-test")
    timeout = timeout or current_app.config.get("LEMUR_TEST_TASK_TIMEOUT", 2 * 60 * 60)
    results = []
    phases = []
    started = time.time()

    with run_lock(run_id):
        fixture_state = None
        database_ready = not reset_database
        setup_succeeded = not reset_database
        if reset_database:
            phase_started = time.time()
            phase = {"phase": "prepare", "status": "failed"}
            try:
                reset_and_seed()
                database_ready = True
                fixture_state = fixtures.prepare(run_id)
                phase["status"] = "passed"
                setup_succeeded = True
            except Exception as error:
                phase["error"] = repr(error)
            finally:
                db.session.remove()
                phase["duration_seconds"] = round(time.time() - phase_started, 3)
                phases.append(phase)

        try:
            if setup_succeeded:
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
                        if scenario.wait_after_seconds:
                            time.sleep(scenario.wait_after_seconds)
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

            if reset_database and fixture_state:
                phase_started = time.time()
                phase = {"phase": "verify", "status": "failed"}
                try:
                    phase["result"] = fixtures.verify(fixture_state)
                    phase["status"] = "passed"
                except Exception as error:
                    phase["error"] = repr(error)
                finally:
                    phase["duration_seconds"] = round(time.time() - phase_started, 3)
                    phases.append(phase)
        finally:
            if reset_database and database_ready:
                db.session.remove()
                phase_started = time.time()
                phase = {"phase": "cleanup", "status": "failed"}
                try:
                    fixtures.cleanup(fixture_state)
                    phase["status"] = "passed"
                except Exception as error:
                    phase["error"] = repr(error)
                finally:
                    phase["duration_seconds"] = round(time.time() - phase_started, 3)
                    phases.append(phase)

    report = {
        "run_id": run_id,
        "status": (
            "passed"
            if all(item["status"] == "passed" for item in results + phases)
            else "failed"
        ),
        "duration_seconds": round(time.time() - started, 3),
        "phases": phases,
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
