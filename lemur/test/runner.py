"""Run the isolated Lemur sandbox test suite through a real Celery worker."""

import json
import time
import uuid

from flask import current_app

from lemur.extensions import db
from lemur.common.celery import celery_app
from lemur.extensions import metrics
from lemur.test.catalog import scenarios, validate_task_catalog
from lemur.test.database import reset_and_seed, validate_database_identity
from lemur.test import fixtures


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

    account = current_app.config.get("LEMUR_TEST_AWS_ACCOUNT")
    allowed_account = current_app.config.get("LEMUR_TEST_ALLOWED_AWS_ACCOUNT")
    if not allowed_account or account != allowed_account:
        raise RuntimeError(
            "Refusing AWS test access for account {!r}; expected RDNA account {!r}".format(
                account, allowed_account
            )
        )

    configured_plugins = current_app.config.get(
        "LEMUR_TEST_DESTINATIONS", []
    ) + current_app.config.get("LEMUR_TEST_SOURCES", [])
    for configured in configured_plugins:
        plugin_name = configured.get("plugin_name", "")
        options = configured.get("options", {})
        if plugin_name.startswith("aws"):
            configured_account = options.get("accountNumber")
            if configured_account != allowed_account:
                raise RuntimeError(
                    "Refusing {} access for AWS account {!r}".format(
                        plugin_name, configured_account
                    )
                )

    allowed_coa_prefix = current_app.config.get("LEMUR_TEST_ALLOWED_COA_PATH_PREFIX")
    if not allowed_coa_prefix:
        raise RuntimeError("LEMUR_TEST_ALLOWED_COA_PATH_PREFIX must be configured")
    for configured in configured_plugins:
        if configured.get("plugin_name") not in (
            "cert-orchestration-adapter-dest",
            "coa-source",
        ):
            continue
        configured_paths = configured.get("options", {}).get("paths", "")
        for path in configured_paths.split(","):
            if path != allowed_coa_prefix:
                raise RuntimeError(
                    "Refusing COA test access outside {!r}: {!r}".format(
                        allowed_coa_prefix, path
                    )
                )


def _selected_scenarios(task_names=None):
    configured = current_app.config.get("LEMUR_TEST_TASK_SCENARIOS", {})
    resolved = scenarios(configured)
    if not task_names:
        return resolved

    unknown = sorted(set(task_names) - set(resolved))
    if unknown:
        raise RuntimeError("Unknown requested tasks: {}".format(", ".join(unknown)))
    return {name: resolved[name] for name in task_names}


def _run_task(task_name, scenario, queue, timeout, run_id, results, stage):
    """Dispatch one task through the isolated worker and record its result."""
    task_started = time.time()
    entry = {"task": task_name, "stage": stage, "status": "failed"}
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
            metric_tags={"task_name": task_name, "run_id": run_id, "stage": stage},
        )
    except Exception as error:
        entry["error"] = repr(error)
        metrics.send(
            "test.task.failure",
            "counter",
            1,
            metric_tags={"task_name": task_name, "run_id": run_id, "stage": stage},
        )
    finally:
        entry["duration_seconds"] = round(time.time() - task_started, 3)
        results.append(entry)
    return entry


def _sync_test_sources(state, queue, timeout, run_id, results, stage):
    scenario = scenarios()["lemur.common.celery.sync_source"]
    for source_label in state["source_labels"]:
        source_scenario = type(scenario)(
            args=[source_label],
            kwargs=dict(scenario.kwargs),
            wait_after_seconds=scenario.wait_after_seconds,
        )
        _run_task(
            "lemur.common.celery.sync_source",
            source_scenario,
            queue,
            timeout,
            run_id,
            results,
            stage,
        )


def _verify_generation(state, generation, phases):
    phase_started = time.time()
    phase = {
        "phase": "verify-generation-{}".format(generation),
        "status": "failed",
    }
    try:
        phase["result"] = fixtures.verify_generation(state, generation)
        phase["status"] = "passed"
    except Exception as error:
        phase["error"] = repr(error)
    finally:
        phase["duration_seconds"] = round(time.time() - phase_started, 3)
        phases.append(phase)


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
                _run_task(
                    task_name,
                    scenario,
                    queue,
                    timeout,
                    run_id,
                    results,
                    "catalog",
                )

        if reset_database and fixture_state:
            _sync_test_sources(
                fixture_state,
                queue,
                timeout,
                run_id,
                results,
                "generation-1-resync",
            )
            _verify_generation(fixture_state, 1, phases)

            rotation_generations = current_app.config.get(
                "LEMUR_TEST_ROTATION_GENERATIONS", 2
            )
            resolved = scenarios(
                current_app.config.get("LEMUR_TEST_TASK_SCENARIOS", {})
            )
            for generation in range(2, rotation_generations + 1):
                stage = "generation-{}".format(generation)
                _run_task(
                    "lemur.common.celery.certificate_reissue",
                    resolved["lemur.common.celery.certificate_reissue"],
                    queue,
                    timeout,
                    run_id,
                    results,
                    stage,
                )
                _run_task(
                    "lemur.common.celery.certificate_rotate",
                    resolved["lemur.common.celery.certificate_rotate"],
                    queue,
                    timeout,
                    run_id,
                    results,
                    stage,
                )
                _sync_test_sources(
                    fixture_state,
                    queue,
                    timeout,
                    run_id,
                    results,
                    "{}-resync".format(stage),
                )
                _verify_generation(fixture_state, generation, phases)
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
