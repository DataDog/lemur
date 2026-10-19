import datetime
import ipaddress
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from marshmallow import ValidationError

from lemur.certificates import service
from lemur.common.utils import parse_private_key
from lemur.tests.vectors import SAN_CERT_KEY, VALID_ADMIN_HEADER_TOKEN


@pytest.fixture
def validate_replacement_names(app):
    def validate(data):
        with patch.object(
            service, "mint", side_effect=RuntimeError("mint reached")
        ) as mint:
            try:
                service.create(authority=SimpleNamespace(name="test"), **data)
            except RuntimeError as error:
                assert str(error) == "mint reached"
                mint.assert_called_once()

    return validate


@pytest.fixture
def replacement_material():
    key = parse_private_key(SAN_CERT_KEY)

    def make(common_name="example.com", names=("example.com", "www.example.com")):
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
        names = [x509.DNSName(n) if isinstance(n, str) else n for n in names]
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
        )
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject)
        if names:
            extension = x509.SubjectAlternativeName(names)
            builder = builder.add_extension(extension, critical=False)
            csr = csr.add_extension(extension, critical=False)
        certificate = builder.sign(key, hashes.SHA256())
        return (
            SimpleNamespace(id=123, cn=common_name, parsed_cert=certificate),
            csr.sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode(),
        )

    return make


@pytest.mark.parametrize(
    "common_name,names,error",
    [
        ("example.com", ["example.com", "www.example.com"], None),
        ("example.com", ["api.example.com", "www.example.com", "example.com"], None),
        ("other.example.com", ["example.com", "www.example.com"], "CN must match"),
        ("example.com", ["example.com"], "www.example.com"),
        ("example.com", [], "cannot remove SANs"),
        ("example.com", ["*.example.com", "example.com"], "www.example.com"),
    ],
)
def test_replacement_names(
    replacement_material, validate_replacement_names, common_name, names, error
):
    old, _ = replacement_material()
    data = {
        "common_name": common_name,
        "extensions": {
            "sub_alt_names": {
                "names": x509.SubjectAlternativeName([x509.DNSName(n) for n in names])
            }
        },
        "replaces": [old],
    }
    if error:
        with pytest.raises(ValidationError, match=error):
            validate_replacement_names(data)
    else:
        validate_replacement_names(data)


def test_no_replacement_is_unaffected(validate_replacement_names):
    validate_replacement_names({})


def test_predecessor_without_sans(replacement_material, validate_replacement_names):
    old, _ = replacement_material(names=[])
    validate_replacement_names({"common_name": old.cn, "replaces": [old]})


def test_checks_every_predecessor(replacement_material, validate_replacement_names):
    first, _ = replacement_material(names=["example.com"])
    second, _ = replacement_material()
    with pytest.raises(ValidationError, match="www.example.com"):
        validate_replacement_names(
            {
                "common_name": first.cn,
                "extensions": {"sub_alt_names": {"names": [x509.DNSName(first.cn)]}},
                "replaces": [first, second],
            }
        )


def test_preserves_non_dns_sans(replacement_material, validate_replacement_names):
    old, csr = replacement_material(
        names=[x509.IPAddress(ipaddress.ip_address("192.0.2.1"))]
    )
    validate_replacement_names({"csr": csr, "replaces": [old]})
    with pytest.raises(ValidationError, match="IPAddress:192.0.2.1"):
        validate_replacement_names({"common_name": old.cn, "replaces": [old]})


@pytest.mark.parametrize("change", ["cn", "sans"])
def test_csr_is_authoritative(replacement_material, validate_replacement_names, change):
    old, original_csr = replacement_material()
    _, changed_csr = replacement_material(
        common_name="other.example.com" if change == "cn" else old.cn,
        names=["example.com"],
    )
    data = {"common_name": old.cn, "replaces": [old], "csr": changed_csr}
    with pytest.raises(ValidationError):
        validate_replacement_names(data)
    data.update(common_name="ignored.example.com", csr=original_csr)
    validate_replacement_names(data)


@pytest.mark.parametrize("provided_csr", [False, True])
def test_create_rejects_before_mint(replacement_material, provided_csr):
    old, _ = replacement_material()
    _, csr = replacement_material(names=["example.com"])
    data = {
        "common_name": old.cn,
        "extensions": {"sub_alt_names": {"names": [x509.DNSName(old.cn)]}},
        "replaces": [old],
    }
    if provided_csr:
        data["csr"] = csr
    with (
        patch.object(service, "mint") as mint,
        pytest.raises(ValidationError, match="www.example.com"),
    ):
        service.create(**data)
    mint.assert_not_called()


@pytest.mark.parametrize("change", ["cn", "sans"])
def test_api_rejects_invalid_replacement_before_mint(
    client, session, authority, replacement_material, change
):
    from lemur.tests.factories import CertificateFactory

    old, _ = replacement_material()
    predecessor = CertificateFactory(
        body=old.parsed_cert.public_bytes(serialization.Encoding.PEM).decode(),
        chain=None,
    )
    session.flush()
    payload = {
        "commonName": "other.example.com" if change == "cn" else old.cn,
        "owner": "jim@example.com",
        "authority": {"id": authority.id},
        "replaces": [{"id": predecessor.id}],
        "extensions": {
            "subAltNames": {"names": [{"nameType": "DNSName", "value": "example.com"}]}
        },
    }
    with patch.object(service, "mint") as mint:
        response = client.post(
            "/api/1/certificates",
            data=json.dumps(payload),
            content_type="application/json",
            headers=VALID_ADMIN_HEADER_TOKEN,
        )
    assert response.status_code == 400, response.get_data(as_text=True)
    assert "Replacement" in response.get_data(as_text=True)
    mint.assert_not_called()
