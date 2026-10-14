"""CLI entry points for the isolated Lemur sandbox test suite."""

import sys

from flask_script import Manager

from lemur.test.catalog import validate_task_catalog
from lemur.test.database import reset_and_seed
from lemur.test.runner import celery_app, render_report, run


manager = Manager(usage="Runs the isolated Lemur sandbox integration tests.")


@manager.command
def coverage():
    """Validate that every Lemur Celery task has a test scenario."""
    validate_task_catalog(celery_app)
    print("All Lemur Celery tasks have a test scenario.")


@manager.command
def reset():
    """Reset and seed the isolated test database."""
    seeded = reset_and_seed()
    print("Reset Lemur test database: {}".format(seeded))


@manager.option(
    "-t",
    "--task",
    dest="task_names",
    action="append",
    help="Run one fully-qualified Celery task. Repeat to run several tasks.",
)
@manager.option(
    "--timeout",
    dest="timeout",
    type=int,
    default=None,
    help="Per-task timeout in seconds.",
)
def execute(task_names, timeout):
    """Dispatch the integration test scenarios through the test worker."""
    report = run(task_names=task_names, timeout=timeout)
    print(render_report(report))
    if report["status"] != "passed":
        sys.exit(1)


@manager.option(
    "-t",
    "--task",
    dest="task_names",
    action="append",
    help="Run one fully-qualified Celery task. Repeat to run several tasks.",
)
@manager.option(
    "--timeout",
    dest="timeout",
    type=int,
    default=None,
    help="Per-task timeout in seconds.",
)
def nightly(task_names, timeout):
    """Reset state and run the task suite under one isolation lock."""
    report = run(task_names=task_names, timeout=timeout, reset_database=True)
    print(render_report(report))
    if report["status"] != "passed":
        sys.exit(1)
