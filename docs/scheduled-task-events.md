# Scheduled task failure events

Lemur sends a Datadog error event when a scheduled task logs ERROR or CRITICAL,
even if it catches the error and returns success. The `task_failure` signal
remains a fallback for unlogged failures. Neither hook changes task behavior.
There is no recovery event or ongoing monitor state. The first error is reported
once per task request, deduplicating later logs and the failure callback.
The retry signal itself does not notify, but an error logged before a retry does.
A retry starts a new request and can report another error, even with the same task ID.

Configure both settings in each deployment to enable notifications:

```python
CELERY_FAILURE_EVENT_RECIPIENTS = "@slack-<account>-<channel>"
CELERY_FAILURE_EVENT_LOGS_URL = "https://<datadog-site>/logs?storage=flex_tier"
```

Use the deployment's actual Datadog site and log storage tier. Leaving either
setting empty disables events. Events use the existing `statsd-metrics` plugin
and DogStatsD agent, with no new API credentials. Validate delivery and Slack
notification in sandbox before enabling elsewhere or removing existing monitors.

Task types come from `CELERYBEAT_SCHEDULE`, so new scheduled task types need no
notification registration. Manual executions of those types also qualify.
Children published by qualifying tasks inherit a header, including nested
children and Celery retries. Independently invoked, unscheduled tasks do not
qualify. This identifies scheduled task families, not exclusively Beat-originated
executions.

Events include the task name, execution ID, exception class and a time-bounded
logs link. Raw arguments, exception messages and tracebacks stay out of events
to avoid leaking secrets or interpreting arbitrary text as notification mentions.

Errors that are not logged at ERROR or CRITICAL and do not escape the task,
expired/revoked tasks and missing executions are not covered. Keep task heartbeat and certificate
health monitors. DogStatsD delivery is best effort, not an exactly-once notification
guarantee. Deduplication is local to the request, not durable across worker restarts.
