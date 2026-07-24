"""
.. module: lemur.plugins.lemur_aws.retry
    :synopsis: Shared retry config for throttled AWS ELB/IAM describe calls.

Flat retries (wait_fixed) made concurrent callers retry in lockstep and sustained
the throttle, so we use exponential backoff (~2/4/8/16/30s) plus jitter to de-sync
them. stop_max_delay caps total retry time per call so backoff can't run for
minutes and blow the source-sync task's Celery soft_time_limit.
"""

# Shared by the @retry decorators in elb.py and iam.py; retry_throttled and
# stop_max_attempt_number stay per-call-site since they differ by API.
THROTTLE_RETRY_KWARGS = {
    "wait_exponential_multiplier": 1000,
    "wait_exponential_max": 30000,
    "wait_jitter_max": 1000,
    "stop_max_delay": 60000,
}
