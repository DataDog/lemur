import boto3
from moto import mock_acm, mock_sts
from unittest import mock

ARN = "arn:aws:acm:us-east-1:123456789012:certificate/1a2b3c4d"


def test_has_managed_tag():
    """The lemur.managed guard tag is recognized only when explicitly true."""
    from lemur.plugins.lemur_aws.acm import _has_managed_tag

    assert _has_managed_tag([{"Key": "lemur.managed", "Value": "true"}]) is True
    assert _has_managed_tag([{"Key": "lemur.managed", "Value": "false"}]) is False
    assert _has_managed_tag([{"Key": "other", "Value": "true"}]) is False
    assert _has_managed_tag([]) is False


def test_get_acm_distribution_endpoint_managed(app):
    """A lemur-managed ACM distribution is surfaced as a cloudfront endpoint."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    distribution = {
        "Id": "E1234567890",
        "DomainName": "d123.cloudfront.net",
        "Aliases": {"Items": ["registry.example.com"]},
        "ViewerCertificate": {
            "ACMCertificateArn": ARN,
            "MinimumProtocolVersion": "TLSv1.2_2021",
        },
    }
    with mock.patch.object(aws_plugin.acm, "is_lemur_managed", return_value=True):
        endpoint = aws_plugin.get_acm_distribution_endpoint("123456789012", distribution)

    assert endpoint is not None
    assert endpoint["type"] == "cloudfront"
    assert endpoint["name"] == "E1234567890"
    # ARN is carried as the transient cert name; the sync resolves it to the lemur cert
    assert endpoint["primary_certificate"]["name"] == ARN
    assert endpoint["primary_certificate"]["registry_type"] == "acm"


def test_get_acm_distribution_endpoint_unmanaged_skipped(app):
    """An ACM distribution not tagged lemur.managed is skipped (no false not-found)."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    distribution = {
        "Id": "E9",
        "DomainName": "d9.cloudfront.net",
        "ViewerCertificate": {"ACMCertificateArn": ARN},
    }
    with mock.patch.object(aws_plugin.acm, "is_lemur_managed", return_value=False):
        endpoint = aws_plugin.get_acm_distribution_endpoint("123456789012", distribution)

    assert endpoint is None


def test_iam_get_distribution_endpoint_skips_acm(app):
    """The IAM source no longer surfaces ACM distributions (they belong to the ACM source)."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    distribution = {
        "Id": "E1",
        "DomainName": "d1.cloudfront.net",
        "ViewerCertificate": {"ACMCertificateArn": ARN},
    }
    assert aws_plugin.get_distribution_endpoint("123456789012", {}, distribution) is None


def test_acm_source_get_certificate_by_name_returns_body(app):
    """An ACM ARN resolves to the cert body so the sync's find_cert can match by serial."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    source = aws_plugin.ACMSourcePlugin()
    with mock.patch.object(
        aws_plugin.acm,
        "get_certificate",
        return_value={"Certificate": "BODY", "CertificateChain": "CHAIN"},
    ) as m_get:
        result = source.get_certificate_by_name(
            ARN, [{"name": "accountNumber", "value": "123456789012"}]
        )

    m_get.assert_called_once()
    assert result == {"body": "BODY", "chain": "CHAIN"}


def test_acm_source_update_endpoint_reimports(app):
    """Rotating an ACM cloudfront endpoint reimports into the distro's own ARN,
    with no UpdateDistribution (attach_certificate) call."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    source = aws_plugin.ACMSourcePlugin()
    endpoint = mock.Mock()
    endpoint.type = "cloudfront"
    endpoint.registry_type = "acm"
    endpoint.name = "E1234567890"
    endpoint.source.options = [{"name": "accountNumber", "value": "123456789012"}]
    certificate = mock.Mock()
    certificate.name = "cert-name"
    certificate.body = "BODY"
    certificate.private_key = "KEY"
    certificate.chain = "CHAIN"

    with mock.patch.object(
        aws_plugin.cloudfront,
        "get_distribution",
        return_value={"ViewerCertificate": {"ACMCertificateArn": ARN}},
    ), mock.patch.object(aws_plugin.acm, "upload_cert") as m_upload, \
            mock.patch.object(aws_plugin.cloudfront, "attach_certificate") as m_attach:
        source.update_endpoint(endpoint, certificate)

    m_upload.assert_called_once()
    _, kwargs = m_upload.call_args
    assert kwargs["certificate_arn"] == ARN
    assert not m_attach.called


def test_acm_destination_upload_imports(app):
    """The ACM destination imports the cert into ACM as a new cert (no certificate_arn)."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    dest = aws_plugin.ACMDestinationPlugin()
    options = [
        {"name": "accountNumber", "value": "123456789012"},
        {"name": "regions", "value": "us-east-1"},
    ]
    with mock.patch.object(aws_plugin.acm, "upload_cert") as m_upload:
        dest.upload("cert-name", "BODY", "KEY", "CHAIN", options)

    m_upload.assert_called_once()
    _, kwargs = m_upload.call_args
    assert kwargs["region"] == "us-east-1"
    # a fresh import must NOT pin an ARN; reimport-into-existing is the source's job
    assert "certificate_arn" not in kwargs


def test_acm_destination_upload_multi_region(app):
    """A destination with multiple regions imports the cert once per region."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    dest = aws_plugin.ACMDestinationPlugin()
    options = [
        {"name": "accountNumber", "value": "123456789012"},
        {"name": "regions", "value": "us-east-1, us-west-2"},  # whitespace tolerated
    ]
    with mock.patch.object(aws_plugin.acm, "upload_cert") as m_upload:
        dest.upload("cert-name", "BODY", "KEY", "CHAIN", options)

    assert m_upload.call_count == 2
    regions = sorted(kw["region"] for _, kw in m_upload.call_args_list)
    assert regions == ["us-east-1", "us-west-2"]


def test_find_managed_cert_arn_matches_by_name():
    """_find_managed_cert_arn returns the ARN whose tags are lemur.managed + our name."""
    from lemur.plugins.lemur_aws.acm import _find_managed_cert_arn

    other_arn = "arn:aws:acm:us-east-1:123456789012:certificate/other"
    client = mock.Mock()
    paginator = mock.Mock()
    paginator.paginate.return_value = [
        {"CertificateSummaryList": [{"CertificateArn": other_arn}, {"CertificateArn": ARN}]}
    ]
    client.get_paginator.return_value = paginator

    tags_by_arn = {
        # right name but not managed: must be ignored
        other_arn: [{"Key": "lemur.name", "Value": "my-cert"}],
        # managed and matching name
        ARN: [
            {"Key": "lemur.managed", "Value": "true"},
            {"Key": "lemur.name", "Value": "my-cert"},
        ],
    }
    client.list_tags_for_certificate.side_effect = lambda CertificateArn: {
        "Tags": tags_by_arn[CertificateArn]
    }

    assert _find_managed_cert_arn(client, "my-cert") == ARN
    # a name we never imported has no managed match
    assert _find_managed_cert_arn(client, "no-such-cert") is None

    # must list all key types, else ECC certs are skipped and re-imported as duplicates
    _, pag_kwargs = paginator.paginate.call_args
    assert "EC_prime256v1" in pag_kwargs["Includes"]["keyTypes"]


@mock_sts()
@mock_acm()
def test_acm_upload_cert_tags_then_reimports_in_place(app, aws_credentials):
    """First push tags the ACM import with lemur.managed + lemur.name; a second push of
    the same name reimports into the same ARN instead of creating a duplicate."""
    from lemur.plugins.lemur_aws import acm
    from lemur.tests.vectors import SAN_CERT_STR, SAN_CERT_KEY, INTERMEDIATE_CERT_STR

    kwargs = dict(account_number="123456789012", region="us-east-1")

    resp1 = acm.upload_cert(
        "my-cert", SAN_CERT_STR, SAN_CERT_KEY, cert_chain=INTERMEDIATE_CERT_STR, **kwargs
    )
    arn1 = resp1["CertificateArn"]

    client = boto3.client("acm", region_name="us-east-1")
    tags = {
        t["Key"]: t["Value"]
        for t in client.list_tags_for_certificate(CertificateArn=arn1)["Tags"]
    }
    assert tags.get("lemur.managed") == "true"
    assert tags.get("lemur.name") == "my-cert"

    # second push of the same name: reimport in place, no duplicate cert
    resp2 = acm.upload_cert(
        "my-cert", SAN_CERT_STR, SAN_CERT_KEY, cert_chain=INTERMEDIATE_CERT_STR, **kwargs
    )
    assert resp2["CertificateArn"] == arn1
    assert len(client.list_certificates()["CertificateSummaryList"]) == 1


def test_apigateway_region_from_dnsname():
    """Region is parsed from a regional API Gateway custom domain's dnsname."""
    from lemur.plugins.lemur_aws.plugin import _apigateway_region_from_dnsname

    assert (
        _apigateway_region_from_dnsname("d-abc123.execute-api.us-east-1.amazonaws.com")
        == "us-east-1"
    )


def test_get_acm_apigateway_endpoint_managed(app):
    """A lemur-managed REGIONAL API Gateway domain is surfaced as an apigateway endpoint."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    domain = {
        "domainName": "api.example.com",
        "regionalDomainName": "d-abc123.execute-api.us-east-1.amazonaws.com",
        "regionalCertificateArn": ARN,
        "securityPolicy": "TLS_1_2",
    }
    with mock.patch.object(aws_plugin.acm, "is_lemur_managed", return_value=True):
        endpoint = aws_plugin.get_acm_apigateway_endpoint("123456789012", domain)

    assert endpoint is not None
    assert endpoint["type"] == "apigateway"
    assert endpoint["name"] == "api.example.com"
    assert endpoint["dnsname"] == "d-abc123.execute-api.us-east-1.amazonaws.com"
    assert endpoint["port"] == 443
    # ARN is carried as the transient cert name; the sync resolves it to the lemur cert
    assert endpoint["primary_certificate"]["name"] == ARN
    assert endpoint["primary_certificate"]["registry_type"] == "acm"


def test_get_acm_apigateway_endpoint_unmanaged_skipped(app):
    """A REGIONAL domain whose cert is not tagged lemur.managed is skipped."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    domain = {
        "domainName": "api.example.com",
        "regionalDomainName": "d-abc123.execute-api.us-east-1.amazonaws.com",
        "regionalCertificateArn": ARN,
    }
    with mock.patch.object(aws_plugin.acm, "is_lemur_managed", return_value=False):
        assert aws_plugin.get_acm_apigateway_endpoint("123456789012", domain) is None


def test_get_acm_apigateway_endpoint_edge_skipped(app):
    """EDGE-optimized domains have no regionalCertificateArn and are skipped (no ACM call)."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    domain = {
        "domainName": "api.example.com",
        "distributionDomainName": "d123.cloudfront.net",
        "certificateArn": ARN,  # edge cert in us-east-1, not a regional cert
    }
    # is_lemur_managed is intentionally not patched: the guard must short-circuit first
    assert aws_plugin.get_acm_apigateway_endpoint("123456789012", domain) is None


def test_acm_source_update_endpoint_apigateway_reimports(app):
    """Rotating an ACM apigateway endpoint reimports into the domain's regional ARN,
    with no UpdateDomainName call."""
    from lemur.plugins.lemur_aws import plugin as aws_plugin

    source = aws_plugin.ACMSourcePlugin()
    endpoint = mock.Mock()
    endpoint.type = "apigateway"
    endpoint.registry_type = "acm"
    endpoint.name = "api.example.com"
    endpoint.dnsname = "d-abc123.execute-api.us-east-1.amazonaws.com"
    endpoint.source.options = [{"name": "accountNumber", "value": "123456789012"}]
    certificate = mock.Mock()
    certificate.name = "cert-name"
    certificate.body = "BODY"
    certificate.private_key = "KEY"
    certificate.chain = "CHAIN"

    with mock.patch.object(
        aws_plugin.apigateway,
        "get_domain_name",
        return_value={"regionalCertificateArn": ARN},
    ) as m_domain, mock.patch.object(aws_plugin.acm, "upload_cert") as m_upload:
        source.update_endpoint(endpoint, certificate)

    m_domain.assert_called_once()
    _, d_kwargs = m_domain.call_args
    assert d_kwargs["region"] == "us-east-1"  # region derived from the dnsname
    m_upload.assert_called_once()
    _, kwargs = m_upload.call_args
    assert kwargs["certificate_arn"] == ARN
    assert kwargs["region"] == "us-east-1"  # region derived from the ARN


def test_get_certificates_includes_ecc_and_large_rsa_key_types(app):
    """ACM ListCertificates defaults to RSA_1024/2048 only; the source must pass
    Includes.keyTypes so ECC and larger RSA certs are discovered too."""
    from lemur.plugins.lemur_aws import acm

    client = mock.Mock()
    client.list_certificates.return_value = {"CertificateSummaryList": []}
    acm._get_certificates(client=client)

    _, kwargs = client.list_certificates.call_args
    key_types = kwargs["Includes"]["keyTypes"]
    assert "EC_prime256v1" in key_types  # the case that silently returned nothing
    assert "RSA_4096" in key_types
    assert "RSA_2048" in key_types
