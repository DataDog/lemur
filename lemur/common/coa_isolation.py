"""Optional sandbox isolation for COA source and destination Vault paths."""

import re

from flask import current_app
from werkzeug.exceptions import BadRequest

SANDBOX_COA_PREFIX = (
    "/kv/data/k8s/cert-orchestration/cert-orchestration-adapter/lemur-sandbox-tests/"
)
_TEST_PATH = re.compile(re.escape(SANDBOX_COA_PREFIX) + r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*")


class CoaPathViolation(BadRequest):
    """A COA configuration violates the sandbox path restriction."""


def validate_coa_paths(plugin_name, options):
    """Fail before persistence or I/O when sandbox COA paths are not isolated."""
    if not current_app.config.get("SANDBOX_COA_PATH_ISOLATION", False):
        return
    if plugin_name not in ("cert-orchestration-adapter-dest", "coa-source"):
        return

    values = [option.get("value") for option in (options or []) if option.get("name") == "paths"]
    if len(values) == 1 and isinstance(values[0], str):
        paths = values[0].split(",")
        if all(_TEST_PATH.fullmatch(path) for path in paths):
            return

    raise CoaPathViolation(
        "Sandbox COA paths must all be under "
        + SANDBOX_COA_PREFIX
        + " (for example dest-49). Shared service paths, empty paths, and traversal are forbidden."
    )
