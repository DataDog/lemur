# lemur/plugins/lemur_digicert_dcv/tests/test_digicert.py
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


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
def test_list_all_domain_names_paginates(mock_app):
    mock_app.config.get.side_effect = _config
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    page1 = {"domains": [{"name": f"domain{i}.prod.dog"} for i in range(100)]}
    page2 = {"domains": [{"name": "last.prod.dog"}]}

    call_count = [0]

    def get_side_effect(url, params=None):
        resp = Mock()
        resp.status_code = 200
        call_count[0] += 1
        resp.json.return_value = page1 if call_count[0] == 1 else page2
        return resp

    provider._session.get.side_effect = get_side_effect

    names = provider.list_all_domain_names()

    assert len(names) == 101
    assert names[0] == "domain0.prod.dog"
    assert names[-1] == "last.prod.dog"
    assert call_count[0] == 2  # exactly 2 pages


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
def test_initiate_validation_returns_dns_record(mock_app):
    mock_app.config.get.side_effect = _config
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider
    from lemur.plugins.lemur_digicert_dcv.provider import DNSRecord

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    def get_side_effect(url, params=None):
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {
            "domains": [{"id": 42, "name": "ap3.prod.dog", "dcv_expiration_date": "2027-10-01"}]
        }
        return resp

    def post_side_effect(url, json=None):
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {"token": "abc123xyz"}
        return resp

    provider._session.get.side_effect = get_side_effect
    provider._session.post.side_effect = post_side_effect

    record = provider.initiate_validation("ap3.prod.dog")

    assert isinstance(record, DNSRecord)
    assert record.name == "_dv.ap3.prod.dog"
    assert record.value == "abc123xyz.dcv.digicert.com"


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
def test_initiate_validation_raises_when_domain_not_registered(mock_app):
    mock_app.config.get.side_effect = _config
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider
    from lemur.plugins.lemur_digicert_dcv.provider import DCVDomainNotRegistered

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"domains": []}
    provider._session.get.return_value = mock_resp

    with pytest.raises(DCVDomainNotRegistered):
        provider.initiate_validation("unknown.prod.dog")


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.digicert.time.sleep", return_value=None)
def test_confirm_validation_returns_true_on_success(mock_sleep, mock_app):
    mock_app.config.get.side_effect = _config
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    def get_side_effect(url, params=None):
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {
            "domains": [{"id": 42, "name": "ap3.prod.dog", "dcv_expiration_date": "2027-10-01"}]
        }
        return resp

    def post_side_effect(url, json=None):
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {"status": "active"}
        return resp

    provider._session.get.side_effect = get_side_effect
    provider._session.post.side_effect = post_side_effect

    result = provider.confirm_validation("ap3.prod.dog")
    assert result is True


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.digicert.time.sleep", return_value=None)
@patch("lemur.plugins.lemur_digicert_dcv.digicert.time.time")
def test_confirm_validation_raises_on_timeout(mock_time, mock_sleep, mock_app):
    mock_app.config.get.side_effect = _config  # DIGICERT_DCV_VALIDATION_TIMEOUT_SECS = 5
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    # time.time() returns 0, then 10 (past deadline of 5s) on second call
    mock_time.side_effect = [0, 10]

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider
    from lemur.plugins.lemur_digicert_dcv.provider import DCVAPIError

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    def get_side_effect(url, params=None):
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {
            "domains": [{"id": 42, "name": "ap3.prod.dog", "dcv_expiration_date": "2027-10-01"}]
        }
        return resp

    def post_side_effect(url, json=None):
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {"status": "pending"}  # never becomes active
        return resp

    provider._session.get.side_effect = get_side_effect
    provider._session.post.side_effect = post_side_effect

    with pytest.raises(DCVAPIError, match="timeout"):
        provider.confirm_validation("ap3.prod.dog")


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.digicert.Route53DCVWriter")
def test_register_domain_full_flow(mock_writer_cls, mock_app):
    mock_app.config.get.side_effect = _config
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    call_count = [0]

    def get_side_effect(url, params=None):
        resp = Mock()
        resp.status_code = 200
        call_count[0] += 1
        if call_count[0] == 1:
            # First call: check_validation → domain not yet registered
            resp.json.return_value = {"domains": []}
        else:
            # Subsequent calls: domain now exists
            resp.json.return_value = {
                "domains": [{"id": 99, "name": "new.prod.dog", "dcv_expiration_date": "2027-10-01"}]
            }
        return resp

    def post_side_effect(url, json=None):
        resp = Mock()
        resp.status_code = 200
        if "domain" in url and "dcv" not in url:
            resp.json.return_value = {"id": 99}  # POST /services/v2/domain → domain created
        elif "dcv" in url and "token" not in url and "check" not in url:
            resp.json.return_value = {"token": "newtoken456"}  # POST /dcv → token
        elif "check" in url:
            resp.json.return_value = {"status": "active"}
        return resp

    provider._session.get.side_effect = get_side_effect
    provider._session.post.side_effect = post_side_effect

    mock_writer = mock_writer_cls.return_value

    provider.register_domain("new.prod.dog")

    mock_writer.upsert.assert_called_once()
    mock_writer.wait_for_propagation.assert_called_once()


@patch("lemur.plugins.lemur_digicert_dcv.digicert.current_app")
def test_register_domain_noop_when_already_valid(mock_app):
    mock_app.config.get.side_effect = _config
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: _config(k))

    from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider

    provider = DigiCertDCVProvider()
    provider._session = MagicMock()

    mock_resp = Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "domains": [{"id": 42, "name": "ap3.prod.dog", "dcv_expiration_date": "2027-10-01"}]
    }
    provider._session.get.return_value = mock_resp

    from freezegun import freeze_time
    with freeze_time("2026-06-22"):
        provider.register_domain("ap3.prod.dog")

    # No POST calls — the domain was already valid with > 30 days remaining
    provider._session.post.assert_not_called()
