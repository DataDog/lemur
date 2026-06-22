# lemur/plugins/lemur_digicert_dcv/tests/test_route53.py
from unittest.mock import patch, Mock, MagicMock, call
import pytest


def _config(key, default=None):
    values = {
        "DIGICERT_DCV_DNS_ZONE": "acme-certs.prod.dog",
        "DIGICERT_DCV_ROUTE53_ROLE_ARN": "arn:aws:iam::911167910923:role/lemur",
        "DIGICERT_DCV_PROPAGATION_TIMEOUT_SECS": 5,  # short for tests
    }
    return values.get(key, default)


@patch("lemur.plugins.lemur_digicert_dcv.route53.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.route53.boto3")
def test_upsert_calls_change_resource_record_sets(mock_boto3, mock_app):
    mock_app.config.get.side_effect = _config

    from lemur.plugins.lemur_digicert_dcv.route53 import Route53DCVWriter
    from lemur.plugins.lemur_digicert_dcv.provider import DNSRecord

    mock_sts = Mock()
    mock_sts.assume_role.return_value = {
        "Credentials": {"AccessKeyId": "k", "SecretAccessKey": "s", "SessionToken": "t"}
    }
    mock_r53 = Mock()
    mock_r53.get_paginator.return_value.paginate.return_value = [
        {"HostedZones": [{"Name": "acme-certs.prod.dog.", "Id": "/hostedzone/Z123"}]}
    ]
    mock_boto3.client.side_effect = lambda svc, **kw: mock_sts if svc == "sts" else mock_r53

    writer = Route53DCVWriter()
    record = DNSRecord(name="_dv.ap3.prod.dog", value="tok123.dcv.digicert.com")
    writer.upsert(record)

    mock_r53.change_resource_record_sets.assert_called_once()
    args = mock_r53.change_resource_record_sets.call_args[1]
    change = args["ChangeBatch"]["Changes"][0]
    assert change["Action"] == "UPSERT"
    assert change["ResourceRecordSet"]["Type"] == "CNAME"
    assert change["ResourceRecordSet"]["ResourceRecords"][0]["Value"] == "tok123.dcv.digicert.com"


@patch("lemur.plugins.lemur_digicert_dcv.route53.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.route53.boto3")
@patch("lemur.plugins.lemur_digicert_dcv.route53.time.sleep", return_value=None)
@patch("lemur.plugins.lemur_digicert_dcv.route53.time.time")
def test_wait_for_propagation_raises_timeout(mock_time, mock_sleep, mock_boto3, mock_app):
    mock_app.config.get.side_effect = _config  # timeout = 5s
    mock_time.side_effect = [0, 10]  # immediately past deadline

    from lemur.plugins.lemur_digicert_dcv.route53 import Route53DCVWriter
    from lemur.plugins.lemur_digicert_dcv.provider import DNSRecord, DCVPropagationTimeout

    with patch("lemur.plugins.lemur_digicert_dcv.route53.Route53DCVWriter._is_propagated", return_value=False):
        writer = Route53DCVWriter()
        record = DNSRecord(name="_dv.ap3.prod.dog", value="tok.dcv.digicert.com")
        with pytest.raises(DCVPropagationTimeout):
            writer.wait_for_propagation(record)


@patch("lemur.plugins.lemur_digicert_dcv.route53.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.route53.boto3")
def test_wait_for_propagation_returns_when_propagated(mock_boto3, mock_app):
    mock_app.config.get.side_effect = _config

    from lemur.plugins.lemur_digicert_dcv.route53 import Route53DCVWriter
    from lemur.plugins.lemur_digicert_dcv.provider import DNSRecord

    with patch("lemur.plugins.lemur_digicert_dcv.route53.Route53DCVWriter._is_propagated", return_value=True):
        writer = Route53DCVWriter()
        record = DNSRecord(name="_dv.ap3.prod.dog", value="tok.dcv.digicert.com")
        writer.wait_for_propagation(record)  # should not raise


@patch("lemur.plugins.lemur_digicert_dcv.route53.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.route53.boto3")
def test_delete_removes_existing_record(mock_boto3, mock_app):
    mock_app.config.get.side_effect = _config

    from lemur.plugins.lemur_digicert_dcv.route53 import Route53DCVWriter

    mock_sts = Mock()
    mock_sts.assume_role.return_value = {
        "Credentials": {"AccessKeyId": "k", "SecretAccessKey": "s", "SessionToken": "t"}
    }
    mock_r53 = Mock()
    mock_r53.get_paginator.return_value.paginate.return_value = [
        {"HostedZones": [{"Name": "acme-certs.prod.dog.", "Id": "/hostedzone/Z123"}]}
    ]
    mock_r53.list_resource_record_sets.return_value = {
        "ResourceRecordSets": [
            {
                "Name": "_dv.ap3.prod.dog.",
                "Type": "CNAME",
                "TTL": 300,
                "ResourceRecords": [{"Value": "tok.dcv.digicert.com"}],
            }
        ]
    }
    mock_boto3.client.side_effect = lambda svc, **kw: mock_sts if svc == "sts" else mock_r53

    writer = Route53DCVWriter()
    writer.delete("_dv.ap3.prod.dog")

    mock_r53.change_resource_record_sets.assert_called_once()
    args = mock_r53.change_resource_record_sets.call_args[1]
    assert args["ChangeBatch"]["Changes"][0]["Action"] == "DELETE"


@patch("lemur.plugins.lemur_digicert_dcv.route53.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.route53.boto3")
def test_delete_silent_when_not_found(mock_boto3, mock_app):
    mock_app.config.get.side_effect = _config

    from lemur.plugins.lemur_digicert_dcv.route53 import Route53DCVWriter

    mock_sts = Mock()
    mock_sts.assume_role.return_value = {
        "Credentials": {"AccessKeyId": "k", "SecretAccessKey": "s", "SessionToken": "t"}
    }
    mock_r53 = Mock()
    mock_r53.get_paginator.return_value.paginate.return_value = [
        {"HostedZones": [{"Name": "acme-certs.prod.dog.", "Id": "/hostedzone/Z123"}]}
    ]
    mock_r53.list_resource_record_sets.return_value = {"ResourceRecordSets": []}
    mock_boto3.client.side_effect = lambda svc, **kw: mock_sts if svc == "sts" else mock_r53

    writer = Route53DCVWriter()
    writer.delete("_dv.nonexistent.prod.dog")  # should not raise

    mock_r53.change_resource_record_sets.assert_not_called()


@patch("lemur.plugins.lemur_digicert_dcv.route53.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.route53.boto3")
@patch("lemur.plugins.lemur_digicert_dcv.route53.dns.resolver.Resolver")
def test_is_propagated_returns_true_on_match(mock_resolver_cls, mock_boto3, mock_app):
    mock_app.config.get.side_effect = _config

    from lemur.plugins.lemur_digicert_dcv.route53 import Route53DCVWriter
    from lemur.plugins.lemur_digicert_dcv.provider import DNSRecord

    mock_rdata = Mock()
    mock_rdata.target = "tok123.dcv.digicert.com."
    mock_resolver_cls.return_value.resolve.return_value = [mock_rdata]

    writer = Route53DCVWriter()
    record = DNSRecord(name="_dv.ap3.prod.dog", value="tok123.dcv.digicert.com")
    assert writer._is_propagated(record) is True


@patch("lemur.plugins.lemur_digicert_dcv.route53.current_app")
@patch("lemur.plugins.lemur_digicert_dcv.route53.boto3")
@patch("lemur.plugins.lemur_digicert_dcv.route53.dns.resolver.Resolver")
def test_is_propagated_returns_false_on_dns_error(mock_resolver_cls, mock_boto3, mock_app):
    mock_app.config.get.side_effect = _config
    import dns.exception
    mock_resolver_cls.return_value.resolve.side_effect = dns.exception.DNSException()

    from lemur.plugins.lemur_digicert_dcv.route53 import Route53DCVWriter
    from lemur.plugins.lemur_digicert_dcv.provider import DNSRecord

    writer = Route53DCVWriter()
    record = DNSRecord(name="_dv.ap3.prod.dog", value="tok.dcv.digicert.com")
    assert writer._is_propagated(record) is False
