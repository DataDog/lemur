"""Dependency-free tests: python3 lemur/tests/test_task_events.py."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit


# Loading this small helper directly avoids starting Flask, Redis or a database.
spec = importlib.util.spec_from_file_location(
    "task_events", Path(__file__).parents[1] / "common" / "task_events.py"
)
events = importlib.util.module_from_spec(spec)
spec.loader.exec_module(events)


def task(name="scheduled", headers=None):
    return SimpleNamespace(name=name, request=SimpleNamespace(headers=headers))


class TaskEventsTest(unittest.TestCase):
    def setUp(self):
        self.config = {
            "CELERYBEAT_SCHEDULE": {"daily": {"task": "scheduled"}},
            "CELERY_FAILURE_EVENT_RECIPIENTS": "@slack-test-channel",
            "CELERY_FAILURE_EVENT_LOGS_URL": "https://example.test/logs?storage=flex_tier",
        }
        self.send = Mock()

    def notify(self, sender=None, execution="execution-1"):
        events.notify_task_failure(
            sender or task(), execution, ValueError("secret @all"), self.config, self.send
        )

    def test_disabled_by_default(self):
        for key in ("CELERY_FAILURE_EVENT_RECIPIENTS", "CELERY_FAILURE_EVENT_LOGS_URL"):
            with self.subTest(key=key):
                original = self.config.pop(key)
                self.notify()
                self.send.assert_not_called()
                self.config[key] = original

    def test_unscheduled_task_does_not_notify(self):
        self.notify(task("manual"))
        self.send.assert_not_called()

    def test_new_schedule_entry_automatically_qualifies(self):
        self.config["CELERYBEAT_SCHEDULE"]["new"] = {"task": "new_task"}
        self.notify(task("new_task"))
        self.send.assert_called_once()

    def test_missing_schedule_does_not_notify(self):
        self.config.pop("CELERYBEAT_SCHEDULE")
        self.notify()
        self.send.assert_not_called()

    def test_event_is_scoped_to_execution_without_sensitive_error(self):
        with patch.object(events.time, "time", return_value=2000):
            self.notify()
        event = self.send.call_args.kwargs
        self.assertEqual(event["alert_type"], "error")
        self.assertEqual(event["aggregation_key"], "execution-1")
        self.assertIn("task_name:scheduled", event["tags"])
        self.assertIn("ValueError", event["text"])
        self.assertIn("@slack-test-channel", event["text"])
        self.assertNotIn("secret", event["text"])
        self.assertNotIn("@all", event["text"])
        link = event["text"].split("[Failure logs](", 1)[1].split(")", 1)[0]
        query = parse_qs(urlsplit(link).query)
        self.assertEqual(query["storage"], ["flex_tier"])
        self.assertEqual(query["query"], ['service:lemur "execution-1"'])
        self.assertEqual(query["from_ts"], ["1100000"])
        self.assertEqual(query["to_ts"], ["2300000"])
        self.assertEqual(query["live"], ["false"])

    def test_logs_url_without_existing_query(self):
        self.config["CELERY_FAILURE_EVENT_LOGS_URL"] = "https://example.test/logs"
        self.notify()
        self.assertIn("/logs?query=", self.send.call_args.kwargs["text"])

    def test_each_failed_execution_emits_an_event(self):
        self.notify(execution="first")
        self.notify(execution="second")
        self.assertEqual(self.send.call_count, 2)
        self.assertEqual(
            [call.kwargs["aggregation_key"] for call in self.send.call_args_list],
            ["first", "second"],
        )

    def test_child_and_grandchild_inherit_classification(self):
        schedule = self.config["CELERYBEAT_SCHEDULE"]
        headers = {"existing": "preserved"}
        events.mark_scheduled_child(headers, task(), schedule)
        self.assertEqual(headers, {"existing": "preserved", events.SCHEDULED_HEADER: True})
        child = task("child", headers)
        self.notify(child)
        grandchild_headers = {}
        events.mark_scheduled_child(grandchild_headers, child, schedule)
        self.notify(task("grandchild", grandchild_headers))
        self.assertEqual(self.send.call_count, 2)

    def test_manual_parent_does_not_mark_child(self):
        headers = {}
        events.mark_scheduled_child(headers, task("manual"), self.config["CELERYBEAT_SCHEDULE"])
        self.assertEqual(headers, {})

    def test_publish_without_parent_or_headers_is_safe(self):
        events.mark_scheduled_child({}, None, self.config["CELERYBEAT_SCHEDULE"])
        events.mark_scheduled_child(None, task(), self.config["CELERYBEAT_SCHEDULE"])

    def test_false_marker_does_not_qualify(self):
        self.notify(task("manual", {events.SCHEDULED_HEADER: False}))
        self.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
