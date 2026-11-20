import json
from unittest.mock import Mock

import pytest
from celery.exceptions import SoftTimeLimitExceeded
from flask import Flask

from lemur.dns_providers.util import DNSResolveError
from lemur.plugins.lemur_acme import acme_handlers, azure, plugin


@pytest.fixture
def acme_app():
    with Flask("lemur_test_acme_failures").app_context():
        yield


def authorization(domain, target_domain=None):
    challenge = Mock()
    challenge.validation.return_value = "token"
    challenge.validation_domain_name.return_value = f"_acme-challenge.{domain}"
    return acme_handlers.AuthorizationRecord(
        domain,
        target_domain or domain,
        [],
        [challenge],
        ["change-id"],
        bool(target_domain),
    )


@pytest.mark.parametrize(
    "failure", [DNSResolveError("DNS query timed out"), SoftTimeLimitExceeded()]
)
@pytest.mark.parametrize("cleanup_error", [None, RuntimeError("DNS cleanup failed")])
def test_failed_order_preserves_error_and_cleans_up(
    acme_app, monkeypatch, caplog, failure, cleanup_error
):
    dns_provider = Mock(
        provider_type="azure", credentials=json.dumps({"subscription_id": "test"})
    )
    monkeypatch.setattr(
        acme_handlers.dns_provider_service,
        "get_all_dns_providers",
        lambda: [dns_provider],
    )
    monkeypatch.setattr(plugin.dns_provider_service, "get", lambda _: dns_provider)
    client = Mock()
    orders = [Mock(uri=f"https://acme.example/order/{i}") for i in (100, 101)]
    client.new_order.side_effect = orders
    monkeypatch.setattr(
        acme_handlers.AcmeHandler,
        "setup_acme_client",
        Mock(return_value=(client, None)),
    )
    monkeypatch.setattr(plugin, "csr_to_string", lambda csr: csr)
    monkeypatch.setattr(
        plugin.authorization_service, "get", lambda _: Mock(domains=["example.com"])
    )
    records = [authorization("example.com")]
    monkeypatch.setattr(
        acme_handlers.AcmeDnsHandler, "get_authorizations", Mock(return_value=records)
    )
    monkeypatch.setattr(
        acme_handlers.AcmeDnsHandler,
        "finalize_authorizations",
        Mock(side_effect=[failure, []]),
    )
    monkeypatch.setattr(
        acme_handlers.AcmeHandler,
        "request_certificate",
        Mock(return_value=("certificate", "chain")),
    )
    delete_record = Mock(side_effect=cleanup_error)
    monkeypatch.setattr(azure, "delete_txt_record", delete_record)
    pending = [Mock(id=i, external_id=i, dns_provider_id=1) for i in (100, 101)]

    results = plugin.ACMEIssuerPlugin().get_ordered_certificates(pending)

    assert results[0] == {
        "cert": False,
        "pending_cert": pending[0],
        "last_error": f"{failure}. Order URI: {orders[0].uri}",
    }
    assert results[1]["cert"] == {
        "body": "certificate",
        "chain": "chain",
        "external_id": "101",
    }
    delete_record.assert_called_once_with(
        ["change-id"],
        {"subscription_id": "test"},
        "_acme-challenge.example.com",
        "token",
    )
    assert f"Unable to resolve pending cert: {pending[0]}" in caplog.text
    assert orders[0].uri in caplog.text
    if cleanup_error:
        assert "Unable to clean up DNS challenge for domain example.com" in caplog.text


def test_cleanup_skips_missing_provider_and_continues(acme_app, monkeypatch, caplog):
    dns_provider = Mock(provider_type="azure", credentials="{}")
    monkeypatch.setattr(
        acme_handlers.dns_provider_service, "get_all_dns_providers", lambda: []
    )
    handler = acme_handlers.AcmeDnsHandler()
    target = "_acme-challenge.delegated.example.net"
    handler.dns_providers_for_domain[target] = [dns_provider]
    delete_record = Mock()
    monkeypatch.setattr(azure, "delete_txt_record", delete_record)

    handler.cleanup_dns_challenges(
        Mock(),
        [authorization("missing.example.com"), authorization("example.com", target)],
    )

    assert (
        "Skipping DNS challenge cleanup: no DNS providers found for domain missing.example.com"
        in caplog.text
    )
    delete_record.assert_called_once_with(["change-id"], {}, target, "token")
