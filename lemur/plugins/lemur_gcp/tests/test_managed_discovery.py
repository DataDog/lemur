from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from flask import Flask

from lemur.exceptions import CertificateNotManaged
from lemur.plugins.lemur_gcp import certificates
from lemur.plugins.lemur_gcp.plugin import GCPSourcePlugin
from lemur.sources import service


@pytest.mark.parametrize("region", [None, "europe-west3"])
@pytest.mark.parametrize("managed", [True, False])
def test_lookup_distinguishes_managed_certificates(region, managed):
    client_path = (
        "region_ssl_certificates.RegionSslCertificatesClient"
        if region
        else "ssl_certificates.SslCertificatesClient"
    )
    metadata = SimpleNamespace(type_="MANAGED" if managed else "SELF_MANAGED")
    with patch.object(certificates, "parse_certificate_meta") as parse, patch(
        "lemur.plugins.lemur_gcp.certificates." + client_path
    ) as client:
        client.return_value.get.return_value = metadata
        if managed:
            with pytest.raises(CertificateNotManaged):
                certificates.fetch_by_name("project", Mock(), "cert", region)
            parse.assert_not_called()
        else:
            assert (
                certificates.fetch_by_name("project", Mock(), "cert", region)
                == parse.return_value
            )
            parse.assert_called_once_with(metadata)


@pytest.mark.parametrize("managed", [True, False])
def test_plugin_preserves_skip_but_reports_api_errors(managed):
    plugin = GCPSourcePlugin()
    error = (
        CertificateNotManaged("Google-managed")
        if managed
        else RuntimeError("API failed")
    )
    with Flask(__name__).app_context(), patch(
        "lemur.plugins.lemur_gcp.plugin.auth.get_gcp_credentials"
    ), patch.object(plugin, "get_option"), patch(
        "lemur.plugins.lemur_gcp.plugin.certificates.fetch_by_name", side_effect=error
    ), patch(
        "lemur.plugins.lemur_gcp.plugin.current_app.logger.error"
    ) as log_error:
        if managed:
            with pytest.raises(CertificateNotManaged):
                plugin.get_certificate_by_name("cert", [])
            log_error.assert_not_called()
        else:
            with pytest.raises(Exception, match="API failed"):
                plugin.get_certificate_by_name("cert", [])
            log_error.assert_called_once()


@pytest.mark.parametrize("outcome", ["managed", "missing", "api_error"])
def test_endpoint_lookup_only_suppresses_explicit_managed_signal(outcome):
    source = SimpleNamespace(plugin_name="gcp-source", label="GCP test", options=[])
    plugin = Mock()
    if outcome == "managed":
        plugin.get_certificate_by_name.side_effect = CertificateNotManaged(
            "Google-managed"
        )
    elif outcome == "api_error":
        plugin.get_certificate_by_name.side_effect = RuntimeError("API failed")
    else:
        plugin.get_certificate_by_name.return_value = None
    with Flask(__name__).app_context(), patch.object(
        service.plugins, "get", return_value=plugin
    ), patch.object(
        service.certificate_service, "get_by_name", return_value=None
    ), patch.object(
        service.metrics, "send"
    ) as metric, patch.object(
        service.current_app.logger, "error"
    ) as error_log, patch.object(
        service.current_app.logger, "info"
    ) as info_log:
        if outcome == "api_error":
            with pytest.raises(RuntimeError, match="API failed"):
                service.get_cert_for_endpoint(source, {"name": "endpoint"}, "cert")
        else:
            assert service.get_cert_for_endpoint(
                source, {"name": "endpoint"}, "cert"
            ) == (None, 0)
            if outcome == "managed":
                info_log.assert_called_once()
                error_log.assert_not_called()
                metric.assert_not_called()
            else:
                error_log.assert_called_once()
                assert metric.call_args.args[0] == "endpoint.certificate.not.found"


@pytest.mark.parametrize("managed_primary", [True, False])
def test_sync_skips_managed_without_promoting_sni(managed_primary):
    source = SimpleNamespace(plugin_name="gcp-source", label="GCP test", options=[])
    primary = Mock()
    endpoint = {
        "name": "endpoint",
        "dnsname": "192.0.2.1",
        "port": 443,
        "primary_certificate": {"name": "primary", "path": "", "registry_type": "gcp"},
        "sni_certificates": [{"name": "sni", "path": ""}],
        "policy": {"name": "policy", "ciphers": []},
    }
    plugin = Mock()
    plugin.get_endpoints.return_value = [endpoint]
    lookup_results = [(None, 0)] if managed_primary else [(primary, 0), (None, 0)]
    with Flask(__name__).app_context(), patch.object(
        service.plugins, "get", return_value=plugin
    ), patch.object(
        service.endpoint_service, "get_by_dnsname_and_port", return_value=None
    ), patch.object(
        service, "get_cert_for_endpoint", side_effect=lookup_results
    ) as lookup, patch.object(
        service.endpoint_service, "get_or_create_policy"
    ), patch.object(
        service.endpoint_service, "create"
    ) as create:
        service.sync_endpoints(source)
        if managed_primary:
            create.assert_not_called()
            assert lookup.call_count == 1
        else:
            create.assert_called_once()
            assert (
                create.call_args.kwargs["primary_certificate"]["certificate"] is primary
            )
            assert create.call_args.kwargs["sni_certificates"] == []
