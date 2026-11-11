"""One-off failure events for scheduled task types and their children."""

import logging
import time
from urllib.parse import urlencode


SCHEDULED_HEADER = "lemur_scheduled_task"


def is_scheduled_task(task, schedule):
    if task is None:
        return False
    return any(entry.get("task") == task.name for entry in schedule.values()) or (
        (getattr(task.request, "headers", None) or {}).get(SCHEDULED_HEADER) is True
    )


def mark_scheduled_child(headers, parent, schedule):
    if headers is not None and is_scheduled_task(parent, schedule):
        headers[SCHEDULED_HEADER] = True


def notify_task_failure(task, task_id, exception, config, send_event):
    """Report an error once per task request, including the terminal failure fallback."""
    recipients = config.get("CELERY_FAILURE_EVENT_RECIPIENTS", "")
    logs_url = config.get("CELERY_FAILURE_EVENT_LOGS_URL", "")
    if not recipients or not logs_url:
        return
    if not is_scheduled_task(task, config.get("CELERYBEAT_SCHEDULE", {})):
        return
    if not task_id or getattr(task.request, "_lemur_error_reported", False):
        return
    if getattr(task.request, "_lemur_reporting_error", False):
        return

    now = int(time.time() * 1000)
    query = {
        "query": 'service:lemur "{}"'.format(task_id),
        "from_ts": now - 15 * 60 * 1000,
        "to_ts": now + 5 * 60 * 1000,
        "live": "false",
    }
    separator = "&" if "?" in logs_url else "?"
    link = logs_url + separator + urlencode(query)
    # Exception messages and task arguments can contain secrets or notification handles.
    message = (
        "Task: {}\nExecution: {}\nError type: {}\n[Failure logs]({})\n\n{}"
    ).format(task.name, task_id, type(exception).__name__ if exception else "Error log", link, recipients)
    task.request._lemur_reporting_error = True
    try:
        send_event(
            title="[Lemur] Scheduled task reported an error: {}".format(task.name),
            message=message,
            alert_type="error",
            aggregation_key=task_id,
            tags=["service:lemur", "task_name:" + task.name, "task_id:" + task_id],
        )
        task.request._lemur_error_reported = True
    finally:
        task.request._lemur_reporting_error = False


class ScheduledTaskErrorHandler(logging.Handler):
    """Observe error logs without changing task results or exception handling."""

    def __init__(self, current_task, config, send_event):
        super().__init__(level=logging.ERROR)
        self.current_task = current_task
        self.config = config
        self.send_event = send_event

    def emit(self, record):
        task = self.current_task()
        if task is None:
            return
        try:
            notify_task_failure(
                task, getattr(task.request, "id", None),
                record.exc_info[1] if record.exc_info else None,
                self.config, self.send_event,
            )
        except Exception:
            # Warning avoids recursively reporting failures of this reporting path.
            logging.getLogger(__name__).warning("Unable to submit scheduled task error event")
