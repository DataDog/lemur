import pytest
from marshmallow import ValidationError

from lemur.certificates.schemas import CertificateInputSchema


@pytest.mark.parametrize("sans", [[], ["edge.example.com"], ["a.example.com", "b.example.com"]])
def test_top_level_sans_are_normalized(sans):
    data = CertificateInputSchema().load_data({"SANs": sans})

    assert "SANs" not in data
    assert data["extensions"]["subAltNames"]["names"] == [
        {"nameType": "DNSName", "value": name} for name in sans
    ]


def test_existing_extensions_are_preserved():
    extensions = {
        "subAltNames": {"names": [{"nameType": "DNSName", "value": "edge.example.com"}]},
        "keyUsage": {"useDigitalSignature": True},
    }
    data = CertificateInputSchema().load_data({"extensions": extensions})
    assert data["extensions"] == extensions

    data = CertificateInputSchema().load_data(
        {"SANs": ["edge.example.com"], "extensions": extensions}
    )
    assert data["extensions"] == extensions


def test_conflicting_san_formats_are_rejected():
    with pytest.raises(ValidationError, match="conflicts"):
        CertificateInputSchema().load_data(
            {
                "SANs": ["edge.example.com"],
                "extensions": {
                    "subAltNames": {
                        "names": [{"nameType": "DNSName", "value": "other.example.com"}]
                    }
                },
            }
        )


@pytest.mark.parametrize("sans", [None, "edge.example.com", {}, [None], [{}]])
def test_invalid_top_level_sans_are_rejected(sans):
    with pytest.raises(ValidationError):
        CertificateInputSchema().load_data({"SANs": sans})


@pytest.mark.parametrize("extensions", [None, [], {"subAltNames": None}])
def test_invalid_extensions_with_sans_are_rejected(extensions):
    with pytest.raises(ValidationError):
        CertificateInputSchema().load_data(
            {"SANs": ["edge.example.com"], "extensions": extensions}
        )
