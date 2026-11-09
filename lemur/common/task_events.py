"""One-off failure events for scheduled task types and their children."""

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
    """Send only terminal failures. The caller connects this to task_failure, not task_retry."""
    recipients = config.get("CELERY_FAILURE_EVENT_RECIPIENTS", "")
    logs_url = config.get("CELERY_FAILURE_EVENT_LOGS_URL", "")
    if not recipients or not logs_url:
        return
    if not is_scheduled_task(task, config.get("CELERYBEAT_SCHEDULE", {})):
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
    ).format(task.name, task_id, type(exception).__name__, link, recipients)
    send_event(
        title="[Lemur] Scheduled task failed: {}".format(task.name),
        text=message,
        alert_type="error",
        aggregation_key=task_id,
        tags=["service:lemur", "task_name:" + task.name, "task_id:" + task_id],
    )
