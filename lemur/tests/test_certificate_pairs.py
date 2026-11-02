from types import SimpleNamespace

import pytest

from lemur.certificates.cli import certificate_pair, paired_reissue_candidates


def cert(cert_id, key_type="RSA2048", pair="edge-us9:*.edge-us9.prod.dog"):
    return SimpleNamespace(
        id=cert_id,
        key_type=key_type,
        cn="*.edge-us9.prod.dog",
        description=f"[certificate-pair:{pair}]" if pair else "ordinary certificate",
    )


def test_pair_identifier_survives_reissue_description():
    certificate = cert(1)
    certificate.description = (
        "Reissued by Lemur for cert ID 100, "
        "[dc-bootstrap:edge-us9:*.edge-us9.prod.dog:RSA2048] " + certificate.description
    )
    assert certificate_pair(certificate) == "edge-us9:*.edge-us9.prod.dog"


def test_bootstrap_identifier_does_not_opt_in():
    certificate = cert(1)
    certificate.description = "[dc-bootstrap:edge-us9:*.edge-us9.prod.dog:RSA2048]"
    assert certificate_pair(certificate) is None


def test_due_member_adds_partner_once():
    rsa, ecc = cert(1), cert(2, "ECCPRIME256V1")
    assert paired_reissue_candidates([rsa], [rsa, ecc]) == [rsa, ecc]
    assert paired_reissue_candidates([rsa, ecc], [rsa, ecc]) == [rsa, ecc]


def test_unpaired_and_not_due_pairs_unchanged():
    ordinary = cert(3, pair=None)
    assert paired_reissue_candidates(
        [ordinary], [cert(1), cert(2, "ECCPRIME256V1")]
    ) == [ordinary]


@pytest.mark.parametrize(
    "peers",
    [[cert(1)], [cert(1), cert(2)], [cert(1), cert(2, "ECCPRIME256V1"), cert(3)]],
)
def test_ambiguous_pair_fails_before_issuance(peers):
    with pytest.raises(ValueError, match="one RSA and one ECC"):
        paired_reissue_candidates([peers[0]], peers)
