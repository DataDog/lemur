from copy import deepcopy
from unittest import mock

import pytest

from lemur.tests.vectors import (
    INTERMEDIATE_CERT_STR,
    ROOTCA_CERT_STR,
    SAN_CERT_KEY,
    SAN_CERT_STR,
)


def imported_summary(arn, status):
    return {"CertificateArn": arn, "Status": status, "Type": "IMPORTED"}


class ResourceNotFoundException(Exception):
    pass


def test_get_imported_certificates_paginates_all_statuses_and_key_types():
    from lemur.plugins.lemur_aws import acm

    client = mock.Mock()
    client.list_certificates.side_effect = [
        {
            "CertificateSummaryList": [
                imported_summary("arn:issued", "ISSUED"),
                {
                    "CertificateArn": "arn:amazon-issued",
                    "Status": "ISSUED",
                    "Type": "AMAZON_ISSUED",
                },
            ],
            "NextToken": "next-page",
        },
        {
            "CertificateSummaryList": [
                imported_summary("arn:expired", "EXPIRED"),
                imported_summary("arn:inactive", "INACTIVE"),
            ]
        },
    ]
    certificates = {
        "arn:issued": {"Certificate": SAN_CERT_STR, "CertificateChain": "chain"},
        "arn:expired": {"Certificate": ROOTCA_CERT_STR},
        "arn:inactive": {"Certificate": INTERMEDIATE_CERT_STR},
    }
    client.get_certificate.side_effect = lambda CertificateArn: certificates[
        CertificateArn
    ]

    result = acm._get_imported_certificates(client)

    assert [certificate["arn"] for certificate in result] == [
        "arn:issued",
        "arn:expired",
        "arn:inactive",
    ]
    assert result[0]["chain"] == "chain"
    assert result[1]["chain"] is None
    assert client.list_certificates.call_args_list == [
        mock.call(Includes={"keyTypes": acm.ACM_KEY_TYPES}),
        mock.call(
            Includes={"keyTypes": acm.ACM_KEY_TYPES}, NextToken="next-page"
        ),
    ]
    client.get_certificate.assert_has_calls(
        [
            mock.call(CertificateArn="arn:issued"),
            mock.call(CertificateArn="arn:expired"),
            mock.call(CertificateArn="arn:inactive"),
        ]
    )


def test_get_imported_certificates_requires_imported_type():
    from lemur.plugins.lemur_aws import acm

    client = mock.Mock()
    client.list_certificates.return_value = {
        "CertificateSummaryList": [
            {"CertificateArn": "arn:no-type", "Status": "ISSUED"},
            {"CertificateArn": "arn:private", "Type": "PRIVATE"},
            {"CertificateArn": "arn:amazon", "Type": "AMAZON_ISSUED"},
        ]
    }

    assert acm._get_imported_certificates(client) == []
    client.get_certificate.assert_not_called()


def test_get_imported_certificates_propagates_retrieval_failure():
    from lemur.plugins.lemur_aws import acm

    client = mock.Mock()
    client.list_certificates.return_value = {
        "CertificateSummaryList": [imported_summary("arn:broken", "EXPIRED")]
    }
    client.exceptions.ResourceNotFoundException = ResourceNotFoundException
    client.get_certificate.side_effect = RuntimeError("ACM unavailable")

    with pytest.raises(RuntimeError, match="ACM unavailable"):
        acm._get_imported_certificates(client)


def test_missing_certificate_policy():
    from lemur.plugins.lemur_aws import acm

    client = mock.Mock()
    client.exceptions.ResourceNotFoundException = ResourceNotFoundException
    client.list_certificates.return_value = {
        "CertificateSummaryList": [imported_summary("arn:deleted", "ISSUED")]
    }
    client.get_certificate.side_effect = ResourceNotFoundException()

    with pytest.raises(ResourceNotFoundException):
        acm._get_imported_certificates(client)

    assert acm._get_imported_certificates(client, skip_missing=True) == []


def test_upload_cert_is_noop_when_fingerprint_exists(app):
    from lemur.plugins.lemur_aws import acm

    client = mock.Mock()
    with mock.patch.object(
        acm,
        "_get_imported_certificates",
        return_value=[{"arn": "arn:existing", "body": SAN_CERT_STR, "chain": None}],
    ):
        response = acm.upload_cert.__wrapped__(
            SAN_CERT_STR, SAN_CERT_KEY, client=client
        )

    assert response == {"CertificateArn": "arn:existing", "AlreadyExists": True}
    client.import_certificate.assert_not_called()


def test_upload_cert_imports_new_fingerprint_without_tags(app):
    from lemur.plugins.lemur_aws import acm

    client = mock.Mock()
    client.import_certificate.return_value = {"CertificateArn": "arn:new"}
    with mock.patch.object(
        acm,
        "_get_imported_certificates",
        return_value=[{"arn": "arn:other", "body": ROOTCA_CERT_STR, "chain": None}],
    ):
        response = acm.upload_cert.__wrapped__(
            SAN_CERT_STR,
            SAN_CERT_KEY,
            cert_chain=INTERMEDIATE_CERT_STR,
            client=client,
        )

    assert response == {"CertificateArn": "arn:new"}
    client.import_certificate.assert_called_once_with(
        Certificate=SAN_CERT_STR.encode("utf-8"),
        PrivateKey=SAN_CERT_KEY.encode("utf-8"),
        CertificateChain=INTERMEDIATE_CERT_STR.encode("utf-8"),
    )


def test_upload_cert_does_not_import_after_inventory_failure(app):
    from lemur.plugins.lemur_aws import acm

    client = mock.Mock()
    with mock.patch.object(
        acm,
        "_get_imported_certificates",
        side_effect=RuntimeError("incomplete inventory"),
    ):
        with pytest.raises(RuntimeError, match="incomplete inventory"):
            acm.upload_cert.__wrapped__(SAN_CERT_STR, SAN_CERT_KEY, client=client)

    client.import_certificate.assert_not_called()


def test_acm_source_returns_only_certificate_material(app):
    from lemur.plugins.lemur_aws import acm
    from lemur.plugins.lemur_aws.plugin import ACMSourcePlugin
    from lemur.plugins.utils import set_plugin_option

    options = deepcopy(ACMSourcePlugin.options)
    set_plugin_option("accountNumber", "123456789012", options)
    set_plugin_option("region", "us-west-2", options)

    source = ACMSourcePlugin()
    with mock.patch.object(
        acm,
        "get_imported_certificates",
        return_value=[
            {
                "arn": "arn:aws:acm:us-west-2:123456789012:certificate/example",
                "body": SAN_CERT_STR,
                "chain": INTERMEDIATE_CERT_STR,
            }
        ],
    ) as get_certificates:
        result = source.get_certificates(options)

    assert result == [{"body": SAN_CERT_STR, "chain": INTERMEDIATE_CERT_STR}]
    assert source.get_endpoints(options) == []
    get_certificates.assert_called_once_with(
        account_number="123456789012", region="us-west-2"
    )


def test_acm_destination_is_a_single_region_paired_source(app):
    from lemur.plugins.lemur_aws import acm
    from lemur.plugins.lemur_aws.plugin import (
        ACMDestinationPlugin,
        ACMSourcePlugin,
    )
    from lemur.plugins.utils import set_plugin_option

    options = deepcopy(ACMDestinationPlugin.options)
    set_plugin_option("accountNumber", "123456789012", options)
    set_plugin_option("region", "eu-west-1", options)

    destination = ACMDestinationPlugin()
    with mock.patch.object(acm, "upload_cert", return_value={}) as upload:
        destination.upload(
            "ignored-lemur-name",
            SAN_CERT_STR,
            SAN_CERT_KEY,
            INTERMEDIATE_CERT_STR,
            options,
        )

    assert destination.sync_as_source is True
    assert destination.sync_as_source_name == ACMSourcePlugin.slug
    upload.assert_called_once_with(
        SAN_CERT_STR,
        SAN_CERT_KEY,
        cert_chain=INTERMEDIATE_CERT_STR,
        account_number="123456789012",
        region="eu-west-1",
    )


def test_acm_destination_creates_source_with_matching_options(app):
    from lemur.plugins.base import plugins
    from lemur.plugins.lemur_aws.plugin import (
        ACMDestinationPlugin,
        ACMSourcePlugin,
    )
    from lemur.plugins.utils import get_plugin_option, set_plugin_option
    from lemur.sources import service as source_service

    options = deepcopy(ACMDestinationPlugin.options)
    set_plugin_option("accountNumber", "123456789012", options)
    set_plugin_option("region", "ap-southeast-2", options)
    destination = mock.Mock(
        plugin_name=ACMDestinationPlugin.slug,
        label="acm-production",
        description="Production ACM",
        options=options,
    )
    plugin_by_slug = {
        ACMDestinationPlugin.slug: ACMDestinationPlugin(),
        ACMSourcePlugin.slug: ACMSourcePlugin(),
    }

    with mock.patch.object(
        plugins, "get", side_effect=lambda slug: plugin_by_slug[slug]
    ), mock.patch.object(source_service, "get_all", return_value=[]), mock.patch.object(
        source_service, "create"
    ) as create:
        assert source_service.add_destination_to_sources(destination) is True

    create.assert_called_once()
    source_options = create.call_args.kwargs["options"]
    assert create.call_args.kwargs["label"] == "acm-production"
    assert create.call_args.kwargs["plugin_name"] == ACMSourcePlugin.slug
    assert get_plugin_option("accountNumber", source_options) == "123456789012"
    assert get_plugin_option("region", source_options) == "ap-southeast-2"
