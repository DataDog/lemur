from types import SimpleNamespace
from unittest.mock import call, patch

import pytest

from lemur.certificates import cli
from lemur.constants import FAILURE_METRIC_STATUS, SUCCESS_METRIC_STATUS


@pytest.mark.parametrize("fails", [False, True])
def test_request_reissue_reports_outcome(app, fails):
    certificate = SimpleNamespace(name="test-certificate", notify=False)
    with (
        patch.object(cli.identity_changed, "send"),
        patch.object(cli, "get_certificate_primitives", return_value={}),
        patch.object(cli, "print_certificate_details"),
        patch.object(cli, "capture_exception"),
        patch.object(cli, "reissue_certificate") as reissue,
        patch.object(cli.metrics, "send") as metric,
    ):
        reissue.return_value = SimpleNamespace(name="replacement")
        if fails:
            reissue.side_effect = ValueError("No ACM ARN matches")
        assert cli.request_reissue(certificate, False, True) is (not fails)
        metric.assert_called_once_with(
            "certificate_reissue",
            "counter",
            1,
            metric_tags={
                "status": FAILURE_METRIC_STATUS if fails else SUCCESS_METRIC_STATUS,
                "certificate": certificate.name,
            },
        )


@pytest.mark.parametrize("outcomes", [[True, True], [False, True], [True, False]])
def test_reissue_finishes_batch_before_reporting_failure(app, outcomes):
    certificates = [object(), object()]
    with (
        patch.object(cli, "validate_certificate", return_value=None),
        patch.object(cli, "get_all_pending_reissue", return_value=certificates),
        patch.object(cli, "request_reissue", side_effect=outcomes) as request,
        patch.object(cli.metrics, "send") as metric,
    ):
        if all(outcomes):
            cli.reissue(None, False, True)
        else:
            with pytest.raises(RuntimeError, match="Certificate reissuance failed"):
                cli.reissue(None, False, True)
        assert request.call_args_list == [
            call(cert, False, True) for cert in certificates
        ]
        metric.assert_called_once_with(
            "certificate_reissue_job",
            "counter",
            1,
            metric_tags={
                "status": (
                    SUCCESS_METRIC_STATUS if all(outcomes) else FAILURE_METRIC_STATUS
                )
            },
        )


def test_named_reissue_failure_propagates(app):
    with (
        patch.object(cli, "validate_certificate", return_value=object()),
        patch.object(cli, "request_reissue", return_value=False),
        patch.object(cli.metrics, "send"),
    ):
        with pytest.raises(RuntimeError, match="Certificate reissuance failed"):
            cli.reissue("test-certificate", False, True)


def test_reissue_selection_failure_propagates(app):
    with (
        patch.object(cli, "validate_certificate", return_value=None),
        patch.object(
            cli, "get_all_pending_reissue", side_effect=ValueError("query failed")
        ),
        patch.object(cli, "capture_exception"),
        patch.object(cli.metrics, "send"),
    ):
        with pytest.raises(RuntimeError, match="Certificate reissuance failed"):
            cli.reissue(None, False, True)
