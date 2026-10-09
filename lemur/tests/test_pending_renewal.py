import json
import arrow
import pytest
from unittest.mock import patch

from lemur.certificates import cli, service
from lemur.pending_certificates import service as pending_service
from lemur.pending_certificates.models import PendingCertificate
from lemur.tests.factories import (
    CertificateFactory,
    PendingCertificateFactory,
    RotationPolicyFactory,
)
from lemur.users.models import User


def test_pending_renewal(app, session, crypto_authority, logged_in_user, monkeypatch):
    monkeypatch.setitem(app.config, "ACME_DISABLE_AUTORESOLVE", True)
    old = CertificateFactory(
        rotation=True, rotation_policy=RotationPolicyFactory(days=30)
    )
    old.authority = crypto_authority
    old.user = User.query.get(1)
    old.not_after = arrow.utcnow().shift(days=10)
    session.commit()
    assert old in service.get_all_pending_reissue()
    minted = []
    real_mint = service.mint

    def hold_issuance(**kwargs):
        body, key, chain, external_id, csr = real_mint(**kwargs)
        if not csr:
            csr, key = service.create_csr(**kwargs)
            # Mint again using this CSR so the key and signed certificate match.
            body, _, chain, external_id, _ = real_mint(**dict(kwargs, csr=csr))
        minted.append(dict(body=body, chain=chain, external_id=str(len(minted) + 1)))
        return None, key, chain, str(len(minted)), csr

    def snapshot(stage):
        session.expire_all()
        result = dict(
            stage=stage,
            pending_ids=[p.id for p in old.pending_cert if not p.resolved],
            replacement_ids=[c.id for c in old.replaced],
            eligible=old in service.get_all_pending_reissue(),
            mint_calls=len(minted),
        )
        print("RESULT " + json.dumps(result))
        return result

    with patch.object(service, "mint", side_effect=hold_issuance):
        cli.reissue(None, False, True)
        first = snapshot("after_first_run")
        assert len(first["pending_ids"]) == 1
        cli.reissue(None, False, True)
        second = snapshot("after_second_run")
        assert second["pending_ids"] == first["pending_ids"]
        pending = PendingCertificate.query.get(first["pending_ids"][0])
        completed = pending_service.create_certificate(pending, minted[0], old.user)
        pending_service.update(pending.id, resolved_cert_id=completed.id, resolved=True)
        before = snapshot("after_completion")
        cli.reissue(None, False, True)
        after = snapshot("after_third_run")
        assert after["mint_calls"] == before["mint_calls"]
        assert not after["eligible"]
        assert len(second["pending_ids"]) == 1


@pytest.mark.parametrize("resolved, eligible", [(False, False), (True, True)])
def test_pending_reissue_ignores_only_unresolved_replacements(
    session, resolved, eligible
):
    old = CertificateFactory(
        rotation=True, rotation_policy=RotationPolicyFactory(days=30)
    )
    other = CertificateFactory(
        rotation=True, rotation_policy=RotationPolicyFactory(days=30)
    )
    old.not_after = other.not_after = arrow.utcnow().shift(days=10)
    pending = PendingCertificateFactory()
    pending.resolved = resolved
    pending.replaces = [old]
    session.flush()
    candidates = service.get_all_pending_reissue()
    assert (old in candidates) is eligible
    assert other in candidates
