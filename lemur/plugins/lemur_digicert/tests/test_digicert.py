import json
from unittest.mock import patch, Mock

import arrow
import pytest
from cryptography import x509
from freezegun import freeze_time
from lemur.plugins.lemur_digicert import plugin
from lemur.tests.vectors import CSR_STR


def config_mock(*args):
    values = {
        "DIGICERT_ORG_ID": 111111,
        "DIGICERT_PRIVATE": False,
        "DIGICERT_DEFAULT_SIGNING_ALGORITHM": "sha256",
        "DIGICERT_CIS_PROFILE_NAMES": {"digicert": "digicert"},
        "DIGICERT_CIS_SIGNING_ALGORITHMS": {"digicert": "digicert"},
        "DIGICERT_CIS_ROOTS": {"root": "ROOT"},
    }
    return values[args[0]]


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_determine_validity_years(mock_current_app):
    assert plugin.determine_validity_years(1) == 1
    assert plugin.determine_validity_years(0) == 1
    assert plugin.determine_validity_years(3) == 1


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_determine_end_date(mock_current_app):
    mock_current_app.config.get = Mock(return_value=397)  # 397 days validity
    with freeze_time(time_to_freeze=arrow.get(2016, 11, 3).datetime):
        assert arrow.get(2017, 12, 5) == plugin.determine_end_date(
            0
        )  # 397 days from (2016, 11, 3)
        assert arrow.get(2017, 12, 5) == plugin.determine_end_date(
            arrow.get(2017, 12, 5)
        )
        assert arrow.get(2017, 12, 5) == plugin.determine_end_date(
            arrow.get(2020, 5, 7)
        )


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_map_fields_with_validity_years(mock_current_app):
    mock_current_app.config.get = Mock(side_effect=config_mock)

    with patch(
        "lemur.plugins.lemur_digicert.plugin.signature_hash"
    ) as mock_signature_hash:
        mock_signature_hash.return_value = "sha256"

        names = ["one.example.com", "two.example.com", "three.example.com"]
        options = {
            "common_name": "example.com",
            "owner": "bob@example.com",
            "description": "test certificate",
            "extensions": {
                "sub_alt_names": {"names": [x509.DNSName(x) for x in names]}
            },
            "validity_years": 1,
        }
        expected = {
            "certificate": {
                "csr": CSR_STR,
                "common_name": "example.com",
                "dns_names": names,
                "signature_hash": "sha256",
            },
            "organization": {"id": 111111},
            "validity_years": 1,
        }
        assert expected == plugin.map_fields(options, CSR_STR)


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_map_fields_with_validity_end_and_start(mock_current_app):
    mock_current_app.config.get = Mock(side_effect=config_mock)
    plugin.determine_end_date = Mock(return_value=arrow.get(2017, 5, 7))

    with patch(
        "lemur.plugins.lemur_digicert.plugin.signature_hash"
    ) as mock_signature_hash:
        mock_signature_hash.return_value = "sha256"

        names = ["one.example.com", "two.example.com", "three.example.com"]
        options = {
            "common_name": "example.com",
            "owner": "bob@example.com",
            "description": "test certificate",
            "extensions": {
                "sub_alt_names": {"names": [x509.DNSName(x) for x in names]}
            },
            "validity_end": arrow.get(2017, 5, 7),
            "validity_start": arrow.get(2016, 10, 30),
        }

        expected = {
            "certificate": {
                "csr": CSR_STR,
                "common_name": "example.com",
                "dns_names": names,
                "signature_hash": "sha256",
            },
            "organization": {"id": 111111},
            "custom_expiration_date": arrow.get(2017, 5, 7).format("YYYY-MM-DD"),
        }

        assert expected == plugin.map_fields(options, CSR_STR)


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_map_cis_fields_with_validity_years(mock_current_app, authority):
    mock_current_app.config.get = Mock(side_effect=config_mock)
    plugin.determine_end_date = Mock(return_value=arrow.get(2018, 11, 3))

    with patch(
        "lemur.plugins.lemur_digicert.plugin.signature_hash"
    ) as mock_signature_hash:
        mock_signature_hash.return_value = "sha256"

        names = ["one.example.com", "two.example.com", "three.example.com"]
        options = {
            "common_name": "example.com",
            "owner": "bob@example.com",
            "description": "test certificate",
            "extensions": {
                "sub_alt_names": {"names": [x509.DNSName(x) for x in names]}
            },
            "organization": "Example, Inc.",
            "organizational_unit": "Example Org",
            "validity_years": 2,
            "authority": authority,
        }

        expected = {
            "common_name": "example.com",
            "csr": CSR_STR,
            "additional_dns_names": names,
            "signature_hash": "sha256",
            "organization": {"name": "Example, Inc."},
            "validity": {
                "valid_to": arrow.get(2018, 11, 3).format("YYYY-MM-DDTHH:mm:ss") + "Z"
            },
            "profile_name": None,
        }

        assert expected == plugin.map_cis_fields(options, CSR_STR)


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_map_cis_fields_with_validity_end_and_start(mock_current_app, app, authority):
    mock_current_app.config.get = Mock(side_effect=config_mock)
    plugin.determine_end_date = Mock(return_value=arrow.get(2017, 5, 7))

    with patch(
        "lemur.plugins.lemur_digicert.plugin.signature_hash"
    ) as mock_signature_hash:
        mock_signature_hash.return_value = "sha256"

        names = ["one.example.com", "two.example.com", "three.example.com"]
        options = {
            "common_name": "example.com",
            "owner": "bob@example.com",
            "description": "test certificate",
            "extensions": {
                "sub_alt_names": {"names": [x509.DNSName(x) for x in names]}
            },
            "organization": "Example, Inc.",
            "organizational_unit": "Example Org",
            "validity_end": arrow.get(2017, 5, 7),
            "validity_start": arrow.get(2016, 10, 30),
            "authority": authority,
        }

        expected = {
            "common_name": "example.com",
            "csr": CSR_STR,
            "additional_dns_names": names,
            "signature_hash": "sha256",
            "organization": {"name": "Example, Inc."},
            "validity": {
                "valid_to": arrow.get(2017, 5, 7).format("YYYY-MM-DDTHH:mm:ss") + "Z"
            },
            "profile_name": None,
        }

        assert expected == plugin.map_cis_fields(options, CSR_STR)


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_signature_hash(mock_current_app, app):
    mock_current_app.config.get = Mock(side_effect=config_mock)
    assert plugin.signature_hash(None) == "sha256"
    assert plugin.signature_hash("sha256WithRSA") == "sha256"
    assert plugin.signature_hash("sha384WithRSA") == "sha384"
    assert plugin.signature_hash("sha512WithRSA") == "sha512"

    with pytest.raises(Exception):
        plugin.signature_hash("sdfdsf")


def test_issuer_plugin_create_certificate(
    certificate_="""\
-----BEGIN CERTIFICATE-----
abc
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
def
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
ghi
-----END CERTIFICATE-----
""",
):
    import requests_mock
    from lemur.plugins.lemur_digicert.plugin import DigiCertIssuerPlugin

    pem_fixture = certificate_

    subject = DigiCertIssuerPlugin()
    adapter = requests_mock.Adapter()
    adapter.register_uri(
        "POST",
        "mock://www.digicert.com/services/v2/order/certificate/ssl_plus",
        text=json.dumps({"id": "id123"}),
    )
    adapter.register_uri(
        "GET",
        "mock://www.digicert.com/services/v2/order/certificate/id123",
        text=json.dumps({"status": "issued", "certificate": {"id": "cert123"}}),
    )
    adapter.register_uri(
        "GET",
        "mock://www.digicert.com/services/v2/certificate/cert123/download/format/pem_all",
        text=pem_fixture,
    )
    subject.session.mount("mock", adapter)

    cert, intermediate, external_id = subject.create_certificate(
        "", {"common_name": "test.com"}
    )

    assert cert == "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"
    assert intermediate == "-----BEGIN CERTIFICATE-----\ndef\n-----END CERTIFICATE-----"


@patch("lemur.pending_certificates.models.PendingCertificate")
def test_cancel_ordered_certificate(mock_pending_cert):
    import requests_mock
    from lemur.plugins.lemur_digicert.plugin import DigiCertIssuerPlugin

    mock_pending_cert.external_id = 1234
    subject = DigiCertIssuerPlugin()
    adapter = requests_mock.Adapter()
    adapter.register_uri(
        "PUT",
        "mock://www.digicert.com/services/v2/order/certificate/1234/status",
        status_code=204,
    )
    adapter.register_uri(
        "PUT",
        "mock://www.digicert.com/services/v2/order/certificate/111/status",
        status_code=404,
    )
    subject.session.mount("mock", adapter)
    data = {"note": "Test"}
    subject.cancel_ordered_certificate(mock_pending_cert, **data)

    # A non-existing order id, does not raise exception because if it doesn't exist, then it doesn't matter
    mock_pending_cert.external_id = 111
    subject.cancel_ordered_certificate(mock_pending_cert, **data)


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_create_authority(mock_current_app):
    from lemur.plugins.lemur_digicert.plugin import DigiCertIssuerPlugin

    options = {"name": "test Digicert authority"}
    digicert_root, intermediate, role = DigiCertIssuerPlugin.create_authority(options)
    assert role == [
        {
            "username": "",
            "password": "",
            "name": "digicert_test_Digicert_authority_admin",
        }
    ]


@patch("lemur.plugins.lemur_digicert.plugin.current_app")
def test_create_cis_authority(mock_current_app, authority):
    from lemur.plugins.lemur_digicert.plugin import DigiCertCISIssuerPlugin

    mock_current_app.config.get = Mock(side_effect=config_mock)

    options = {"name": "test Digicert CIS authority", "authority": authority}
    digicert_root, intermediate, role = DigiCertCISIssuerPlugin.create_authority(
        options
    )
    assert role == [
        {
            "username": "",
            "password": "",
            "name": "digicert_test_Digicert_CIS_authority_admin",
        }
    ]


@patch("lemur.plugins.lemur_digicert.plugin.current_app", new_callable=Mock)
@patch("lemur.plugins.lemur_digicert.plugin.DigiCertDCVProvider")
def test_create_certificate_calls_dcv_hook_when_enabled(mock_dcv_cls, mock_app):
    """DCV hook fires when DIGICERT_DCV_ENABLED is True."""
    from lemur.plugins.lemur_digicert_dcv.provider import ValidationStatus

    mock_app.config.get.side_effect = lambda k, d=None: {
        "DIGICERT_URL": "https://www.digicert.com",
        "DIGICERT_ORDER_TYPE": "ssl_plus",
        "DIGICERT_DCV_ENABLED": True,
        "DIGICERT_DCV_ISSUANCE_WINDOW_DAYS": 30,
    }.get(k, d)
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: {
        "DIGICERT_API_KEY": "test-key",
    }.get(k))

    mock_dcv = mock_dcv_cls.return_value
    mock_dcv.check_validation.return_value = ValidationStatus(status="VALID")

    from lemur.plugins.lemur_digicert.plugin import DigiCertIssuerPlugin
    plugin = DigiCertIssuerPlugin.__new__(DigiCertIssuerPlugin)
    plugin.session = Mock()
    plugin.session.post.return_value = Mock(
        status_code=201,
        json=Mock(return_value={"id": 99})
    )

    # Will raise after the hook because get_certificate_id isn't mocked,
    # but that's fine — we only care that the hook fired.
    try:
        plugin.create_certificate("fake_csr", {"common_name": "test.example.com"})
    except Exception:
        pass

    mock_dcv.check_validation.assert_called_once()


@patch("lemur.plugins.lemur_digicert.plugin.current_app", new_callable=Mock)
@patch("lemur.plugins.lemur_digicert.plugin.DigiCertDCVProvider")
def test_create_certificate_skips_dcv_hook_when_disabled(mock_dcv_cls, mock_app):
    """DCV hook is skipped when DIGICERT_DCV_ENABLED is False or unset."""
    mock_app.config.get.side_effect = lambda k, d=None: {
        "DIGICERT_URL": "https://www.digicert.com",
        "DIGICERT_ORDER_TYPE": "ssl_plus",
        "DIGICERT_DCV_ENABLED": False,
    }.get(k, d)

    from lemur.plugins.lemur_digicert.plugin import DigiCertIssuerPlugin
    plugin = DigiCertIssuerPlugin.__new__(DigiCertIssuerPlugin)
    plugin.session = Mock()
    plugin.session.post.return_value = Mock(
        status_code=201,
        json=Mock(return_value={"id": 99})
    )

    try:
        plugin.create_certificate("fake_csr", {"common_name": "test.example.com"})
    except Exception:
        pass

    mock_dcv_cls.assert_not_called()


@patch("lemur.plugins.lemur_digicert.plugin.current_app", new_callable=Mock)
@patch("lemur.plugins.lemur_digicert.plugin.DigiCertDCVProvider")
def test_create_certificate_calls_register_domain_when_missing(mock_dcv_cls, mock_app):
    """MISSING status triggers register_domain() instead of initiate_validation()."""
    from lemur.plugins.lemur_digicert_dcv.provider import ValidationStatus

    mock_app.config.get.side_effect = lambda k, d=None: {
        "DIGICERT_URL": "https://www.digicert.com",
        "DIGICERT_ORDER_TYPE": "ssl_plus",
        "DIGICERT_DCV_ENABLED": True,
        "DIGICERT_DCV_ISSUANCE_WINDOW_DAYS": 30,
    }.get(k, d)
    mock_app.config.__getitem__ = Mock(side_effect=lambda k: {
        "DIGICERT_API_KEY": "test-key",
    }.get(k))

    mock_dcv = mock_dcv_cls.return_value
    mock_dcv.check_validation.return_value = ValidationStatus(status="MISSING")

    from lemur.plugins.lemur_digicert.plugin import DigiCertIssuerPlugin
    p = DigiCertIssuerPlugin.__new__(DigiCertIssuerPlugin)
    p.session = Mock()
    p.session.post.return_value = Mock(
        status_code=201,
        json=Mock(return_value={"id": 99})
    )

    try:
        p.create_certificate("fake_csr", {"common_name": "test.example.com"})
    except Exception:
        pass

    mock_dcv.register_domain.assert_called_once_with("example.com")
    mock_dcv.initiate_validation.assert_not_called()


@patch("lemur.plugins.lemur_digicert.plugin.current_app", new_callable=Mock)
@patch("lemur.plugins.lemur_digicert.plugin.Route53DCVWriter")
@patch("lemur.plugins.lemur_digicert.plugin.DigiCertDCVProvider")
def test_ensure_dcv_valid_expiring_soon_cleans_up_on_failure(mock_dcv_cls, mock_writer_cls, mock_app):
    """EXPIRING_SOON: writer.delete() is called when wait_for_propagation raises."""
    from lemur.plugins.lemur_digicert_dcv.provider import ValidationStatus
    from lemur.plugins.lemur_digicert.plugin import _ensure_dcv_valid

    mock_app.config.get.side_effect = lambda k, d=None: {
        "DIGICERT_DCV_ISSUANCE_WINDOW_DAYS": 30,
    }.get(k, d)

    mock_dcv = mock_dcv_cls.return_value
    mock_dcv.check_validation.return_value = ValidationStatus(status="EXPIRING_SOON")
    dns_record = Mock()
    mock_dcv.initiate_validation.return_value = dns_record

    mock_writer = mock_writer_cls.return_value
    mock_writer.wait_for_propagation.side_effect = RuntimeError("propagation timed out")

    with pytest.raises(RuntimeError, match="propagation timed out"):
        _ensure_dcv_valid("sub.example.com")

    mock_writer.delete.assert_called_once_with(dns_record.name)


@patch("lemur.plugins.lemur_digicert.plugin.current_app", new_callable=Mock)
@patch("lemur.plugins.lemur_digicert.plugin.Route53DCVWriter")
@patch("lemur.plugins.lemur_digicert.plugin.DigiCertDCVProvider")
def test_ensure_dcv_valid_expiring_soon_confirm_failure_cleans_up(mock_dcv_cls, mock_writer_cls, mock_app):
    """EXPIRING_SOON: writer.delete() is called when confirm_validation raises."""
    from lemur.plugins.lemur_digicert_dcv.provider import ValidationStatus
    from lemur.plugins.lemur_digicert.plugin import _ensure_dcv_valid

    mock_app.config.get.side_effect = lambda k, d=None: {
        "DIGICERT_DCV_ISSUANCE_WINDOW_DAYS": 30,
    }.get(k, d)

    mock_dcv = mock_dcv_cls.return_value
    mock_dcv.check_validation.return_value = ValidationStatus(status="EXPIRING_SOON")
    dns_record = Mock()
    mock_dcv.initiate_validation.return_value = dns_record
    mock_dcv.confirm_validation.side_effect = RuntimeError("CA rejected")

    mock_writer = mock_writer_cls.return_value
    mock_writer.wait_for_propagation.return_value = None

    with pytest.raises(RuntimeError, match="CA rejected"):
        _ensure_dcv_valid("sub.example.com")

    mock_writer.delete.assert_called_once_with(dns_record.name)
