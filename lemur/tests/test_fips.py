import json
import os
import subprocess
import sys


def test_fips_startup_logs_are_json():
    env = os.environ.copy()
    env["FIPS_ENABLED"] = "false"

    # Load the early-startup modules without importing the full Flask application.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys, types; "
                "lemur = types.ModuleType('lemur'); "
                "lemur.__path__ = ['lemur']; "
                "sys.modules['lemur'] = lemur; "
                "from lemur import fips; "
                "fips.instance.must_enable_fips_if_needed()"
            ),
        ],
        capture_output=True,
        check=False,
        env=env,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    log_lines = [line for line in result.stderr.splitlines() if line]
    payloads = [json.loads(line) for line in log_lines]

    assert payloads
    assert all(payload["levelname"] == "INFO" for payload in payloads)
    assert any(
        payload["message"] == "Enabling FIPS mode on OpenSSL if needed..."
        for payload in payloads
    )
