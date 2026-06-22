# lemur/plugins/lemur_digicert_dcv/tests/test_digicert.py
from datetime import datetime, timezone
from unittest.mock import patch, Mock, MagicMock

import pytest


def _config(key, default=None):
    values = {
        "DIGICERT_URL": "https://www.digicert.com",
        "DIGICERT_API_KEY": "test-devkey",
        "DIGICERT_ORG_ID": 111111,
        "DIGICERT_DCV_RENEWAL_WINDOW_DAYS": 60,
        "DIGICERT_DCV_ISSUANCE_WINDOW_DAYS": 30,
        "DIGICERT_DCV_PROPAGATION_TIMEOUT_SECS": 600,
        "DIGICERT_DCV_VALIDATION_TIMEOUT_SECS": 5,  # short for tests
        "DIGICERT_DCV_ENABLED": True,
    }
    return values.get(key, default)


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
def test_check_validation_returns_valid(mock_app):
    mock_app.config.get.side_effect = _config
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "domains": [{
            "id": 42,
            "name": "ap3.prod.dog",
            "dcv_expiration_date": "2027-10-01",
        }]
    }
    provider._session.get.return_value = mock_resp

    status = provider.check_validation("ap3.prod.dog")

    assert status.status == "VALID"
    assert status.expiry.year == 2027


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
def test_check_validation_returns_missing_when_no_domains(mock_app):
    mock_app.config.get.side_effect = _config
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"domains": []}
    provider._session.get.return_value = mock_resp

    status = provider.check_validation("new.prod.dog")
    assert status.status == "MISSING"


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
def test_check_validation_returns_expiring_soon(mock_app):
    mock_app.config.get.side_effect = _config
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider
    from freezegun import freeze_time

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "domains": [{
            "id": 42,
            "name": "ap3.prod.dog",
            "dcv_expiration_date": "2026-08-01",  # within 60-day window from 2026-06-22
        }]
    }
    provider._session.get.return_value = mock_resp

    with freeze_time("2026-06-22"):
        status = provider.check_validation("ap3.prod.dog")

    assert status.status == "EXPIRING_SOON"


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
def test_check_validation_raises_on_api_error(mock_app):
    mock_app.config.get.side_effect = _config
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider
    from lemur.plugins.lemur_digicert_dcv.provider import DCVAPIError

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    mock_resp = Mock()
    mock_resp.status_code = 403
    mock_resp.text = "Forbidden"
    provider._session.get.return_value = mock_resp

    with pytest.raises(DCVAPIError):
        provider.check_validation("ap3.prod.dog")
