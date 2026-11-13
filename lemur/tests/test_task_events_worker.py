"""Real worker logging regression, using only in-memory broker and result storage."""

import ast
import importlib.util
from contextlib import nullcontext
import io
import json
import logging
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from celery import Celery, signals
from celery.contrib.testing.worker import start_worker
import logmatic

spec = importlib.util.spec_from_file_location(
    "task_events", Path(__file__).parents[1] / "common" / "task_events.py"
)
events = importlib.util.module_from_spec(spec)
spec.loader.exec_module(events)


class TaskEventWorkerTest(unittest.TestCase):
    def test_error_and_terminal_failure_are_searchable(self):
        app = Celery("isolated-logging-test", broker="memory://", backend="cache+memory://")
        app.conf.update(task_always_eager=False, worker_hijack_root_logger=False)
        config = {
            "LOG_JSON": True,
            "CELERYBEAT_SCHEDULE": {
                "caught": {"task": "test.caught"},
                "uncaught": {"task": "test.uncaught"},
            },
            "CELERY_FAILURE_EVENT_RECIPIENTS": "@slack-test-only",
            "CELERY_FAILURE_EVENT_LOGS_URL": "https://example.test/logs",
        }
        send = Mock()
        flask = SimpleNamespace(
            config=config, logger=logging.getLogger("isolated-flask"), app_context=nullcontext,
        )
        # Load the actual logging setup and failure callback without importing
        # the application module, which initializes database and Redis clients.
        source = Path(__file__).parents[1] / "common" / "celery.py"
        tree = ast.parse(source.read_text())
        make_celery = next(n for n in tree.body if getattr(n, "name", None) == "make_celery")
        configure = next(n for n in make_celery.body
                         if getattr(n, "name", None) == "_configure_worker_logging")
        failure = next(n for n in tree.body
                       if getattr(n, "name", None) == "notify_failed_scheduled_task")
        failure.decorator_list = []
        namespace = {
            "app": flask, "flask_app": flask, "current_app": flask, "celery": app,
            "json_log_formatter": logmatic.JsonFormatter,
            "ScheduledTaskErrorHandler": events.ScheduledTaskErrorHandler,
            "TaskErrorContextFilter": events.TaskErrorContextFilter,
            "notify_task_failure": events.notify_task_failure,
            "plugins": SimpleNamespace(get=lambda name: SimpleNamespace(
                statsd=SimpleNamespace(event=send))),
        }
        exec(compile(ast.Module(body=[configure, failure], type_ignores=[]), str(source), "exec"),
             namespace)
        setup = namespace["_configure_worker_logging"]
        callback = Mock(wraps=namespace["notify_failed_scheduled_task"])
        signals.after_setup_logger.connect(setup, weak=False)
        signals.after_setup_task_logger.connect(setup, weak=False)
        signals.task_failure.connect(callback, weak=False)
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        root = logging.getLogger()
        previous_handlers, previous_level = root.handlers[:], root.level
        root.handlers = [handler]

        @app.task(name="test.caught")
        def caught():
            try:
                raise ValueError("caught test failure")
            except ValueError:
                flask.logger.exception("caught test error")
            return "still succeeds"

        @app.task(name="test.uncaught")
        def uncaught():
            raise RuntimeError("uncaught test failure")

        try:
            with start_worker(app, pool="solo", perform_ping_check=False, loglevel="INFO"):
                first = caught.delay()
                self.assertEqual(first.get(timeout=10), "still succeeds")
                second = uncaught.delay()
                self.assertIsInstance(second.get(timeout=10, propagate=False), RuntimeError)
                self.assertEqual(second.state, "FAILURE")
            rows = [json.loads(line) for line in output.getvalue().splitlines()]
            callback.assert_called_once()
            self.assertEqual(callback.call_args.kwargs["task_id"], second.id)
            self.assertEqual(send.call_count, 2)
            for result, name in ((first, "test.caught"), (second, "test.uncaught")):
                errors = [row for row in rows if row.get("levelname") == "ERROR"
                          and row.get("task_id") == result.id]
                self.assertTrue(errors, "No correlated error for " + name)
                self.assertTrue(all(row["task_name"] == name for row in errors))
                self.assertTrue(any("exc_info" in row for row in errors))
                event = next(call.kwargs for call in send.call_args_list
                             if call.kwargs["aggregation_key"] == result.id)
                link = event["message"].split("[Failure logs](", 1)[1].split(")", 1)[0]
                self.assertEqual(parse_qs(urlsplit(link).query)["query"],
                                 ['service:lemur @task_id:"{}"'.format(result.id)])
        finally:
            signals.after_setup_logger.disconnect(setup)
            signals.after_setup_task_logger.disconnect(setup)
            signals.task_failure.disconnect(callback)
            root.handlers, root.level = previous_handlers, previous_level
            app.close()


if __name__ == "__main__":
    unittest.main()
