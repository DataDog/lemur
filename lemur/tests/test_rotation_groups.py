from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import arrow
import pytest

from lemur.certificates.service import (
    rotation_group,
    get_all_pending_reissue,
    include_grouped_certificates,
    reissue_certificate,
)


@pytest.fixture
def select_candidates(app):
    def select(pending, peers):
        with patch("lemur.certificates.service.Certificate") as model:
            due = MagicMock()
            due.filter.return_value = due
            due.all.return_value = pending
            peer_query = MagicMock()
            peer_query.filter.return_value = peer_query
            peer_query.__iter__.return_value = iter(peers)
            model.query.filter.side_effect = [due, peer_query]
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
    assert select_candidates([ordinary], [cert(1), cert(2, "ECCPRIME256V1")]) == [
        ordinary
    ]


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


def test_similar_identifier_does_not_match(app, select_candidates):
    first, other = cert(1, group="edge-us9"), cert(2, group="edge-us90")
    with patch.object(app.logger, "error") as error:
        assert select_candidates([first], [first, other]) == [first]
        error.assert_called_once()
        assert error.call_args.args[1:] == ("edge-us9", first.id)


@pytest.mark.parametrize("size", [2, 3])
def test_complete_groups_do_not_log_errors(app, select_candidates, size):
    members = [cert(i) for i in range(size)]
    with patch.object(app.logger, "error") as error:
        assert select_candidates(members, members) == members
        error.assert_not_called()


def test_singleton_logs_once_even_with_duplicate_query_rows(app, select_candidates):
    member = cert(1)
    with patch.object(app.logger, "error") as error:
        assert select_candidates([member], [member, member]) == [member]
        error.assert_called_once()
        assert error.call_args.args[1:] == ("edge-us9-public", member.id)


@pytest.mark.parametrize(
    "description",
    [
        None,
        "",
        "ordinary certificate",
        "[rotation-group:]",
        "[rotation-group:unfinished",
        "[rotation-group:has space]",
        "[rotation-group:has\ttab]",
        "[rotation-group:has\nnewline]",
        "[rotation-group:nested[bracket]]",
    ],
)
def test_invalid_group_tags_are_ignored(description):
    certificate = cert(1)
    certificate.description = description
    assert rotation_group(certificate) is None


def test_first_group_tag_wins():
    certificate = cert(1)
    certificate.description = "[rotation-group:first] [rotation-group:second]"
    assert rotation_group(certificate) == "first"


@pytest.mark.parametrize("pending", [[], [cert(1, group=None)]])
def test_no_group_skips_partner_lookup(pending):
    with patch("lemur.certificates.service.Certificate") as model:
        assert include_grouped_certificates(pending) == pending
        model.query.filter.assert_not_called()


def test_multiple_due_groups_expand_independently(select_candidates):
    first, second = cert(1, group="first"), cert(2, group="second")
    first_peer, second_peer = cert(3, group="first"), cert(4, group="second")
    unrelated = cert(5, group="unrelated")
    ordinary = cert(6, group=None)
    assert select_candidates(
        [first, second, ordinary],
        [first, first_peer, second, second_peer, unrelated],
    ) == [first, second, ordinary, first_peer, second_peer]


def test_group_query_excludes_disabled_and_replaced_members(session):
    from lemur.tests.factories import CertificateFactory, RotationPolicyFactory

    policy = RotationPolicyFactory(days=30)

    def member(days, rotation=True, group="eligibility-test"):
        certificate = CertificateFactory(
            rotation=rotation,
            rotation_policy=policy,
            description=f"[rotation-group:{group}]",
        )
        certificate.not_after = arrow.utcnow().shift(days=days)
        return certificate

    due = member(10)
    early = member(90)
    disabled = member(90, rotation=False)
    replaced = member(90)
    replacement = member(90)
    replacement.replaces.append(replaced)
    unrelated = member(90, group="other")
    session.flush()

    selected = get_all_pending_reissue()
    assert due in selected
    assert early in selected
    assert replacement in selected
    assert disabled not in selected
    assert replaced not in selected
    assert unrelated not in selected


@pytest.mark.parametrize("outcomes", [[False, True, True], [True, False, True]])
def test_group_failure_does_not_skip_remaining_members(
    app, select_candidates, outcomes
):
    from lemur.certificates import cli
    from lemur.constants import FAILURE_METRIC_STATUS

    members = [cert(1), cert(2), cert(3)]
    selected = select_candidates([members[0]], members)
    with (
        patch.object(cli, "validate_certificate", return_value=None),
        patch.object(cli, "get_all_pending_reissue", return_value=selected),
        patch.object(cli, "request_reissue", side_effect=outcomes) as request,
        patch.object(cli.metrics, "send") as metric,
    ):
        with pytest.raises(RuntimeError, match="Certificate reissuance failed"):
            cli.reissue(None, False, True)
        assert request.call_args_list == [
            call(member, False, True) for member in members
        ]
        metric.assert_called_once_with(
            "certificate_reissue_job",
            "counter",
            1,
            metric_tags={"status": FAILURE_METRIC_STATUS},
        )


def test_real_reissue_preserves_group_tag(
    issuer_plugin, crypto_authority, certificate, logged_in_user
):
    certificate.authority = crypto_authority
    certificate.description = "[dc-bootstrap:test] [rotation-group:renewal-test]"
    renewed = reissue_certificate(certificate, replace=True)
    assert rotation_group(renewed) == "renewal-test"
    assert "[dc-bootstrap:test]" in renewed.description
    assert certificate in renewed.replaces
