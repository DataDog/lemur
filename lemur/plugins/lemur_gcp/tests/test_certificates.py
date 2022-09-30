import pytest

from lemur.plugins.lemur_gcp.certificates import get_name, modify_cert_name_for_gcp

body = """
-----BEGIN CERTIFICATE-----
MIIB7zCCAZagAwIBAgIRAILPQ22P50KYnufSOcyC3xgwCgYIKoZIzj0EAwIwYjES
MBAGA1UEAwwJbG9jYWxob3N0MRYwFAYDVQQKDA1FeGFtcGxlLCBJbmMuMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJTG9zIEdhdG9z
MB4XDTIyMDgzMDE2MzkwN1oXDTIzMDgzMDE2MzkwN1owazEbMBkGA1UEAwwSdGVz
dC5sb2NhbGhvc3QuY29tMRYwFAYDVQQKDA1FeGFtcGxlLCBJbmMuMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJTG9zIEdhdG9zMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4FP/xJlvy7jDFRbElv7opDMFF0Tw7jSr
S03Nyh8//spXeNPIvu49uknYsJiMtC19OW8GsH4FXxAMarmLsuUaraMkMCIwIAYD
VR0RAQH/BBYwFIISdGVzdC5sb2NhbGhvc3QuY29tMAoGCCqGSM49BAMCA0cAMEQC
IHDfzhvpCm37SjMbJUY0hbAs+hXYIayNjCZaOvl5gQUEAiAuZ93rbdEZ69Tzd/iN
I/Wm13nhSNDgVeEWbr3BP1ZacQ==
-----END CERTIFICATE-----
"""


def test_get_name():
    assert get_name(body) == 'ssl-test-localhost-com-localhost-2022-08-30'


@pytest.mark.parametrize(
    ('original_cert_name', 'gcp_cert_name'),
    [
        ("*.test.com", "star-test-com"),
        ("CAPITALIZED.TEST.COM", "capitalized-test-com"),
        ("ssl-lemur-sandbox-datad0g-com-digicerttlsrsasha2562020ca1-2022-",
         "ssl-lemur-sandbox-datad0g-com-digicerttlsrsasha2562020ca1-2022"),
        (
            "this.is.a.long.certificate.name.that.should.get.cut.off.after.63.characters.test.com",
            "this-is-a-long-certificate-name-that-should-get-cut-off-after-6"
        )
    ]
)
def test_modify_cert_name_for_gcp(original_cert_name, gcp_cert_name):
    assert modify_cert_name_for_gcp(original_cert_name) == gcp_cert_name
