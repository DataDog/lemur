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
        {"name": "region", "value": "us-east-1"},
    ]
    with mock.patch.object(aws_plugin.acm, "upload_cert") as m_upload:
        dest.upload("cert-name", "BODY", "KEY", "CHAIN", options)

    m_upload.assert_called_once()
    _, kwargs = m_upload.call_args
    # a fresh import must NOT pin an ARN; reimport-into-existing is the source's job
    assert "certificate_arn" not in kwargs
