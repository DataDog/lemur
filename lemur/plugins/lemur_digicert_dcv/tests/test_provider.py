import pytest
from datetime import datetime
from lemur.plugins.lemur_digicert_dcv.provider import (
    DNSRecord,
    ValidationStatus,
    DCVAPIError,
    DCVDomainNotRegistered,
    DCVPropagationTimeout,
    DCVRegistrationError,
    DCVProvider,
)


def test_validation_status_valid():
    s = ValidationStatus(status="VALID", expiry=datetime(2027, 10, 1))
    assert s.status == "VALID"
    assert s.expiry == datetime(2027, 10, 1)


def test_validation_status_missing_has_no_expiry():
    s = ValidationStatus(status="MISSING")
    assert s.expiry is None


def test_dns_record_fields():
    r = DNSRecord(name="_dv.ap3.prod.dog", value="abc123.dcv.digicert.com")
    assert r.name == "_dv.ap3.prod.dog"
    assert r.value == "abc123.dcv.digicert.com"


def test_dcv_api_error_includes_domain_and_ca():
    e = DCVAPIError(domain="ap3.prod.dog", ca="digicert", reason="401 Unauthorized")
    assert "ap3.prod.dog" in str(e)
    assert "digicert" in str(e)
    assert e.domain == "ap3.prod.dog"
    assert e.ca == "digicert"


def test_dcv_domain_not_registered_message_mentions_register():
    e = DCVDomainNotRegistered("ap3.prod.dog")
    assert "register_domain" in str(e)
    assert e.domain == "ap3.prod.dog"


def test_dcv_propagation_timeout_fields():
    e = DCVPropagationTimeout(domain="ap3.prod.dog", record_name="_dv.ap3.prod.dog")
    assert "_dv.ap3.prod.dog" in str(e)


def test_dcv_registration_error_fields():
    e = DCVRegistrationError(domain="ap3.prod.dog", reason="POST /v1/domains returned 403")
    assert "ap3.prod.dog" in str(e)
    assert e.domain == "ap3.prod.dog"


def test_dcv_provider_is_abstract():
    with pytest.raises(TypeError):
        DCVProvider()
