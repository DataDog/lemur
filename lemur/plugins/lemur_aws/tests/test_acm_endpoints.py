from copy import deepcopy
from types import SimpleNamespace
from unittest import mock

import pytest

from lemur.plugins.lemur_aws import plugin
from lemur.plugins.utils import set_plugin_option
from lemur.sources import service


ACCOUNT = "123456789012"
ARN = f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/primary"
SNI_ARN = f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/sni"


def options(region="us-east-1"):
    result = deepcopy(plugin.ACMSourcePlugin.options)
    set_plugin_option("accountNumber", ACCOUNT, result)
    set_plugin_option("region", region, result)
    return result


def endpoint(arn=ARN):
    return dict(name="test", dnsname="test.example.com", port=443, type="elbv2",
                primary_certificate=dict(name=arn, path="", registry_type="acm"),
                policy=dict(name="test", ciphers=[]))


def test_acm_discovery_reuses_helpers_and_keeps_full_arns(app):
    source = plugin.ACMSourcePlugin()
    alb = endpoint()
    alb["sni_certificates"] = [dict(name=SNI_ARN, path="", registry_type="acm")]
    distribution = dict(
        Id="distribution", DomainName="test.cloudfront.net",
        ViewerCertificate={"ACMCertificateArn": ARN},
        Aliases={"Items": ["alias.example.com"]},
    )
    with mock.patch.object(plugin.elb, "get_all_elbs", return_value=[{}]), \
            mock.patch.object(plugin.elb, "get_all_elbs_v2", return_value=[{}]), \
            mock.patch.object(plugin, "get_elb_endpoints", return_value=[endpoint()]) as classic, \
            mock.patch.object(plugin, "get_elb_endpoints_v2", return_value=[alb]) as v2, \
            mock.patch.object(plugin.cloudfront, "get_all_distributions", return_value=[distribution]), \
            mock.patch.object(plugin.acm, "get_imported_certificates", return_value=[
                {"arn": ARN}, {"arn": SNI_ARN}
            ]) as inventory:
        result = source.get_endpoints(options())
    assert len(result) == 3
    assert result[1]["sni_certificates"][0]["name"] == SNI_ARN
    assert result[2]["primary_certificate"]["name"] == ARN
    assert result[2]["aliases"] == ["alias.example.com"]
    classic.assert_called_once_with(ACCOUNT, "us-east-1", {}, preserve_arn=True)
    v2.assert_called_once_with(ACCOUNT, "us-east-1", {}, preserve_arn=True)
    inventory.assert_called_once_with(account_number=ACCOUNT, region="us-east-1")


def test_acm_discovery_skips_unmanaged_certificates_and_other_regions_cloudfront(app):
    with mock.patch.object(plugin.elb, "get_all_elbs", return_value=[{}]), \
            mock.patch.object(plugin.elb, "get_all_elbs_v2", return_value=[]), \
            mock.patch.object(plugin, "get_elb_endpoints", return_value=[endpoint()]), \
            mock.patch.object(plugin.cloudfront, "get_all_distributions") as cloudfront, \
            mock.patch.object(plugin.acm, "get_imported_certificates", return_value=[]):
        assert plugin.ACMSourcePlugin().get_endpoints(options("us-west-2")) == []
    cloudfront.assert_not_called()


def test_acm_discovery_failure_propagates(app):
    with mock.patch.object(plugin.elb, "get_all_elbs", side_effect=RuntimeError("denied")):
        with pytest.raises(RuntimeError, match="denied"):
            plugin.ACMSourcePlugin().get_endpoints(options())


def test_cloudfront_iam_behavior_unchanged(app):
    distribution = dict(Id="distribution", DomainName="test.cloudfront.net",
                        ViewerCertificate={"ACMCertificateArn": ARN})
    assert plugin.get_distribution_endpoint(ACCOUNT, {}, distribution) is None
    distribution["ViewerCertificate"] = {"IAMCertificateId": "iam-id"}
    iam_arn = f"arn:aws:iam::{ACCOUNT}:server-certificate/test"
    result = plugin.get_distribution_endpoint(ACCOUNT, {"iam-id": iam_arn}, distribution)
    assert result["primary_certificate"]["name"] == "test"
    assert plugin.get_distribution_endpoint(ACCOUNT, {}, distribution, acm_only=True) is None


def test_acm_lookup_reads_current_body_without_cached_inventory(app):
    source = plugin.ACMSourcePlugin()
    with mock.patch.object(plugin.acm, "get_certificate", side_effect=[
        {"body": "old"}, {"body": "new"}
    ]) as lookup:
        assert source.get_certificate_by_name(ARN, options())["body"] == "old"
        assert source.get_certificate_by_name(ARN, options())["body"] == "new"
    lookup.assert_called_with(ARN, account_number=ACCOUNT, region="us-east-1")
    with pytest.raises(ValueError):
        source.get_certificate_by_name(ARN, options("us-west-2"))


def test_acm_sync_does_not_touch_iam_owned_endpoint(app):
    source = SimpleNamespace(plugin_name="aws-acm-source", label="acm", options=[])
    existing = SimpleNamespace(source=SimpleNamespace(plugin_name="aws-source"))
    with mock.patch.object(service.plugins, "get") as plugins, \
            mock.patch.object(service.endpoint_service, "get_by_dnsname_and_port", return_value=existing), \
            mock.patch.object(service, "get_cert_for_endpoint") as resolve, \
            mock.patch.object(service.endpoint_service, "update") as update, \
            mock.patch.object(service.endpoint_service, "create") as create:
        plugins.return_value.get_endpoints.return_value = [endpoint()]
        assert service.sync_endpoints(source) == (0, 0, 0)
    resolve.assert_not_called()
    update.assert_not_called()
    create.assert_not_called()


def test_acm_sync_reassociates_existing_endpoint(app):
    source = SimpleNamespace(plugin_name="aws-acm-source", label="acm", options=[])
    replacement = object()
    existing = SimpleNamespace(id=42, source=source)
    with mock.patch.object(service.plugins, "get") as plugins, \
            mock.patch.object(service.endpoint_service, "get_by_dnsname_and_port", return_value=existing), \
            mock.patch.object(service, "get_cert_for_endpoint", return_value=(replacement, 1)), \
            mock.patch.object(service.endpoint_service, "get_or_create_policy"), \
            mock.patch.object(service.endpoint_service, "update") as update:
        plugins.return_value.get_endpoints.return_value = [endpoint()]
        assert service.sync_endpoints(source) == (0, 1, 1)
    assert update.call_args.kwargs["primary_certificate"]["certificate"] is replacement
    assert update.call_args.kwargs["source"] is source


def test_acm_endpoint_rotation_is_left_to_reimport_and_sync(app):
    from lemur.certificates import cli

    ep = SimpleNamespace(source=SimpleNamespace(plugin_name="aws-acm-source"))
    with mock.patch.object(cli.deployment_service, "rotate_certificate") as rotate:
        cli.request_rotation(ep, object(), object(), False, True)
    rotate.assert_not_called()


def test_listener_helpers_preserve_acm_arns_without_changing_iam_defaults(app):
    classic = dict(LoadBalancerName="classic", DNSName="classic.example.com",
                   ListenerDescriptions=[dict(
                       Listener=dict(SSLCertificateId=ARN, LoadBalancerPort=443),
                       PolicyNames=[],
                   )])
    assert plugin.get_elb_endpoints(ACCOUNT, "us-east-1", classic)[0][
        "primary_certificate"]["name"] == "primary"
    assert plugin.get_elb_endpoints(ACCOUNT, "us-east-1", classic, preserve_arn=True)[0][
        "primary_certificate"]["name"] == ARN

    alb = dict(LoadBalancerName="alb", DNSName="alb.example.com", LoadBalancerArn="lb")
    with mock.patch.object(plugin.elb, "describe_listeners_v2", return_value={
        "Listeners": [dict(Protocol="HTTP"), dict(
            Protocol="HTTPS", ListenerArn="listener", Port=443, SslPolicy=""
        )]
    }), mock.patch.object(plugin.elb, "describe_listener_certificates_v2", return_value={
        "Certificates": [dict(CertificateArn=ARN, IsDefault=True),
                         dict(CertificateArn=SNI_ARN, IsDefault=False)]
    }) as certificates:
        result = plugin.get_elb_endpoints_v2(ACCOUNT, "us-east-1", alb, preserve_arn=True)
    assert len(result) == 1
    assert result[0]["primary_certificate"]["name"] == ARN
    assert result[0]["sni_certificates"][0]["name"] == SNI_ARN
    certificates.assert_called_once()


def test_acm_sync_creates_unowned_endpoint(app):
    source = SimpleNamespace(plugin_name="aws-acm-source", label="acm", options=[])
    certificate = object()
    with mock.patch.object(service.plugins, "get") as plugins, \
            mock.patch.object(service.endpoint_service, "get_by_dnsname_and_port", return_value=None), \
            mock.patch.object(service, "get_cert_for_endpoint", return_value=(certificate, 1)), \
            mock.patch.object(service.endpoint_service, "get_or_create_policy"), \
            mock.patch.object(service.endpoint_service, "create") as create:
        plugins.return_value.get_endpoints.return_value = [endpoint()]
        assert service.sync_endpoints(source) == (1, 0, 1)
    assert create.call_args.kwargs["source"] is source
    assert create.call_args.kwargs["primary_certificate"]["certificate"] is certificate
