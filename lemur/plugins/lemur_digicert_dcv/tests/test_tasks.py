from unittest.mock import patch, Mock, MagicMock
import pytest


def _config(key, default=None):
    values = {
        "DIGICERT_DCV_ENABLED": True,
        "DIGICERT_DCV_RENEWAL_WINDOW_DAYS": 60,
    }
    return values.get(key, default)


@patch("lemur.plugins.lemur_digicert_dcv.tasks.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.metrics")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.DigiCertDCVProvider")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.Route53DCVWriter")
def test_sweep_revalidates_expiring_domains(mock_writer_cls, mock_provider_cls, mock_metrics, mock_app):
    mock_app.config.get.side_effect = _config

    mock_provider = mock_provider_cls.return_value
    mock_provider.list_all_domain_names.return_value = ["ap3.prod.dog"]

    from lemur.plugins.lemur_digicert_dcv.provider import ValidationStatus, DNSRecord
    mock_provider.check_validation.return_value = ValidationStatus(status="EXPIRING_SOON")
    mock_provider.initiate_validation.return_value = DNSRecord(
        name="_dv.ap3.prod.dog", value="tok.dcv.digicert.com"
    )
    mock_provider.confirm_validation.return_value = True

    mock_writer = mock_writer_cls.return_value

    from lemur.plugins.lemur_digicert_dcv.tasks import validate_digicert_domains
    validate_digicert_domains()

    mock_provider.initiate_validation.assert_called_once_with("ap3.prod.dog")
    mock_writer.upsert.assert_called_once()
    mock_writer.wait_for_propagation.assert_called_once()
    mock_provider.confirm_validation.assert_called_once_with("ap3.prod.dog")


@patch("lemur.plugins.lemur_digicert_dcv.tasks.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.metrics")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.DigiCertDCVProvider")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.Route53DCVWriter")
def test_sweep_skips_valid_domains(mock_writer_cls, mock_provider_cls, mock_metrics, mock_app):
    mock_app.config.get.side_effect = _config

    mock_provider = mock_provider_cls.return_value
    mock_provider.list_all_domain_names.return_value = ["ap3.prod.dog"]

    from lemur.plugins.lemur_digicert_dcv.provider import ValidationStatus
    mock_provider.check_validation.return_value = ValidationStatus(status="VALID")

    from lemur.plugins.lemur_digicert_dcv.tasks import validate_digicert_domains
    validate_digicert_domains()

    mock_provider.initiate_validation.assert_not_called()


@patch("lemur.plugins.lemur_digicert_dcv.tasks.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.metrics")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.DigiCertDCVProvider")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.Route53DCVWriter")
def test_sweep_disabled_when_feature_flag_off(mock_writer_cls, mock_provider_cls, mock_metrics, mock_app):
    mock_app.config.get.side_effect = lambda k, d=None: False if k == "DIGICERT_DCV_ENABLED" else d

    from lemur.plugins.lemur_digicert_dcv.tasks import validate_digicert_domains
    validate_digicert_domains()

    mock_provider_cls.assert_not_called()


@patch("lemur.plugins.lemur_digicert_dcv.tasks.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.metrics")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.DigiCertDCVProvider")
@patch("lemur.plugins.lemur_digicert_dcv.tasks.Route53DCVWriter")
def test_sweep_emits_failure_metric_and_continues_on_error(mock_writer_cls, mock_provider_cls, mock_metrics, mock_app):
    mock_app.config.get.side_effect = _config

    mock_provider = mock_provider_cls.return_value
    mock_provider.list_all_domain_names.return_value = ["bad.prod.dog", "good.prod.dog"]

    from lemur.plugins.lemur_digicert_dcv.provider import ValidationStatus, DNSRecord
    mock_provider.check_validation.return_value = ValidationStatus(status="EXPIRING_SOON")
    mock_provider.initiate_validation.side_effect = [
        Exception("API error"),
        DNSRecord(name="_dv.good.prod.dog", value="tok.dcv.digicert.com"),
    ]
    mock_provider.confirm_validation.return_value = True

    from lemur.plugins.lemur_digicert_dcv.tasks import validate_digicert_domains
    validate_digicert_domains()  # should not raise

    # failure metric emitted for bad.prod.dog
    failure_calls = [
        c for c in mock_metrics.send.call_args_list
        if "validation_failed" in str(c)
    ]
    assert len(failure_calls) == 1

    # good.prod.dog was still processed
    mock_writer_cls.return_value.upsert.assert_called_once()
