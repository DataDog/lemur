from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from lemur.certificates.service import rotation_group, get_all_pending_reissue


@pytest.fixture
def select_candidates():
    def select(pending, peers):
        with patch("lemur.certificates.service.Certificate") as model:
            current = model.query.filter.return_value.filter.return_value
            due = MagicMock()
            due.all.return_value = pending
            current.filter.side_effect = [due, peers]
            return get_all_pending_reissue()

    return select


def cert(cert_id, key_type="RSA2048", group="edge-us9-public"):
    return SimpleNamespace(
        id=cert_id,
        key_type=key_type,
        cn="*.edge-us9.prod.dog",
        description=f"[rotation-group:{group}]" if group else "ordinary certificate",
    )


def test_group_identifier_survives_reissue_description():
    certificate = cert(1)
    certificate.description = (
        "Reissued by Lemur for cert ID 100, "
        "[dc-bootstrap:edge-us9:*.edge-us9.prod.dog:RSA2048] " + certificate.description
    )
    assert rotation_group(certificate) == "edge-us9-public"


def test_bootstrap_identifier_does_not_opt_in():
    certificate = cert(1)
    certificate.description = "[dc-bootstrap:edge-us9:*.edge-us9.prod.dog:RSA2048]"
    assert rotation_group(certificate) is None


def test_due_member_adds_group_members_once(select_candidates):
    rsa, ecc = cert(1), cert(2, "ECCPRIME256V1")
    assert select_candidates([rsa], [rsa, ecc]) == [rsa, ecc]
    assert select_candidates([rsa, ecc], [rsa, ecc]) == [rsa, ecc]


def test_ungrouped_and_not_due_groups_unchanged(select_candidates):
    ordinary = cert(3, group=None)
    assert select_candidates(
        [ordinary], [cert(1), cert(2, "ECCPRIME256V1")]
    ) == [ordinary]


@pytest.mark.parametrize(
    "peers",
    [[cert(1)], [cert(1), cert(2)], [cert(1), cert(2, "ECCPRIME256V1"), cert(3)]],
)
def test_group_membership_is_defined_only_by_tag(peers, select_candidates):
    assert select_candidates([peers[0]], peers) == peers


def test_different_names_and_key_types_are_allowed(select_candidates):
    first, second = cert(1), cert(2, "ED25519")
    second.cn = "another.example.com"
    assert select_candidates([first], [first, second]) == [first, second]


def test_similar_identifier_does_not_match(select_candidates):
    first, other = cert(1, group="edge-us9"), cert(2, group="edge-us90")
    assert select_candidates([first], [first, other]) == [first]
