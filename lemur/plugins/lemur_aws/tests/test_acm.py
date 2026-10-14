from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from lemur.tests.vectors import (
    CSR_STR,
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
        mock.call(Includes={"keyTypes": acm.ACM_KEY_TYPES}, NextToken="next-page"),
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


def test_upload_cert_rejects_duplicate_fingerprint_without_predecessor(app):
    from lemur.plugins.lemur_aws import acm

    client = mock.Mock()
    with mock.patch.object(
        acm,
        "_get_imported_certificates",
        return_value=[
            {"arn": "arn:one", "body": SAN_CERT_STR},
            {"arn": "arn:two", "body": SAN_CERT_STR},
        ],
    ):
        with pytest.raises(ValueError, match="Multiple ACM ARNs match"):
            acm.upload_cert.__wrapped__(SAN_CERT_STR, SAN_CERT_KEY, client=client)

    client.import_certificate.assert_not_called()


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
        replaces=(),
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

    with (
        mock.patch.object(
            plugins, "get", side_effect=lambda slug: plugin_by_slug[slug]
        ),
        mock.patch.object(source_service, "get_all", return_value=[]),
        mock.patch.object(source_service, "create") as create,
    ):
        assert source_service.add_destination_to_sources(destination) is True

    create.assert_called_once()
    source_options = create.call_args.kwargs["options"]
    assert create.call_args.kwargs["label"] == "acm-production"
    assert create.call_args.kwargs["plugin_name"] == ACMSourcePlugin.slug
    assert get_plugin_option("accountNumber", source_options) == "123456789012"
    assert get_plugin_option("region", source_options) == "ap-southeast-2"


@pytest.fixture
def renewal_certificates():
    key = serialization.load_pem_private_key(SAN_CERT_KEY.encode(), password=None)

    def issue(days, names=("example.com", "www.example.com"), public_key=None):
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, names[0])])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(public_key or key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    return issue


def test_acm_reimports_twice_and_retries_at_the_same_arn(app, renewal_certificates):
    from lemur.plugins.lemur_aws import acm

    old, new, newest = [renewal_certificates(days) for days in (30, 90, 180)]
    client = mock.Mock()
    client.import_certificate.return_value = {"CertificateArn": "arn:stable"}
    inventory = [{"arn": "arn:stable", "body": old}]
    with mock.patch.object(acm, "_get_imported_certificates", return_value=inventory):
        for predecessor, replacement in ((old, new), (new, newest)):
            response = acm.upload_cert.__wrapped__(
                replacement,
                SAN_CERT_KEY,
                cert_chain=INTERMEDIATE_CERT_STR,
                replaces=[predecessor],
                client=client,
            )
            assert response["CertificateArn"] == "arn:stable"
            client.import_certificate.assert_called_with(
                CertificateArn="arn:stable",
                Certificate=replacement.encode(),
                PrivateKey=SAN_CERT_KEY.encode(),
                CertificateChain=INTERMEDIATE_CERT_STR.encode(),
            )
            inventory[0]["body"] = replacement
            retry = acm.upload_cert.__wrapped__(
                replacement,
                SAN_CERT_KEY,
                replaces=[predecessor],
                client=client,
            )
            assert retry == {"CertificateArn": "arn:stable", "AlreadyExists": True}

    assert client.import_certificate.call_count == 2


@pytest.mark.parametrize(
    "inventory_kind", ["missing", "duplicate", "old_and_new", "same_cn"]
)
def test_acm_reimport_rejects_missing_or_ambiguous_arn(
    app, renewal_certificates, inventory_kind
):
    from lemur.plugins.lemur_aws import acm

    old, new = renewal_certificates(30), renewal_certificates(90)
    inventories = {
        "missing": [],
        "same_cn": [{"arn": "arn:unrelated", "body": renewal_certificates(60)}],
        "duplicate": [{"arn": "arn:one", "body": old}, {"arn": "arn:two", "body": old}],
        "old_and_new": [
            {"arn": "arn:one", "body": old},
            {"arn": "arn:two", "body": new},
        ],
    }
    client = mock.Mock()
    with mock.patch.object(
        acm, "_get_imported_certificates", return_value=inventories[inventory_kind]
    ):
        message = (
            "Multiple ACM ARNs match"
            if inventory_kind in ("duplicate", "old_and_new")
            else "No ACM ARN matches"
        )
        with pytest.raises(ValueError, match=message):
            acm.upload_cert.__wrapped__(
                new,
                SAN_CERT_KEY,
                replaces=[old],
                client=client,
            )
    client.import_certificate.assert_not_called()


@pytest.mark.parametrize("change", ["domains", "key", "validity"])
def test_acm_reimport_leaves_certificate_constraints_to_aws(
    app, renewal_certificates, change
):
    from lemur.plugins.lemur_aws import acm

    old = renewal_certificates(30)
    if change == "domains":
        new = renewal_certificates(90, names=("example.com",))
    elif change == "key":
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        new = renewal_certificates(90, public_key=key.public_key())
    else:
        new = renewal_certificates(10)
    client = mock.Mock()
    with mock.patch.object(
        acm,
        "_get_imported_certificates",
        return_value=[{"arn": "arn:old", "body": old}],
    ):
        acm.upload_cert.__wrapped__(
            new,
            SAN_CERT_KEY,
            replaces=[old],
            client=client,
        )
    client.import_certificate.assert_called_once_with(
        CertificateArn="arn:old",
        Certificate=new.encode(),
        PrivateKey=SAN_CERT_KEY.encode(),
    )


def test_acm_reimport_does_not_fall_back_after_aws_rejection(app, renewal_certificates):
    from lemur.plugins.lemur_aws import acm

    old, new = renewal_certificates(30), renewal_certificates(90)
    client = mock.Mock()
    client.import_certificate.side_effect = RuntimeError("AWS rejected reimport")
    with mock.patch.object(
        acm,
        "_get_imported_certificates",
        return_value=[{"arn": "arn:old", "body": old}],
    ):
        with pytest.raises(RuntimeError, match="AWS rejected reimport"):
            acm.upload_cert.__wrapped__(
                new,
                SAN_CERT_KEY,
                replaces=[old],
                client=client,
            )
    assert client.import_certificate.call_count == 1
    assert client.import_certificate.call_args.kwargs["CertificateArn"] == "arn:old"


def test_destination_event_passes_predecessor_to_acm(app):
    from lemur.certificates.models import update_destinations
    from lemur.plugins.base import plugins
    from lemur.plugins.lemur_aws import acm
    from lemur.plugins.lemur_aws.plugin import ACMDestinationPlugin
    from lemur.plugins.utils import set_plugin_option

    options = deepcopy(ACMDestinationPlugin.options)
    set_plugin_option("accountNumber", "123456789012", options)
    set_plugin_option("region", "us-east-1", options)
    destination = SimpleNamespace(
        plugin_name="aws-acm-destination", options=options, label="test", description=""
    )
    certificate = SimpleNamespace(
        name="renewal",
        body=SAN_CERT_STR,
        private_key=SAN_CERT_KEY,
        chain=INTERMEDIATE_CERT_STR,
        expired=False,
        replaces=[SimpleNamespace(body=ROOTCA_CERT_STR)],
    )
    with (
        mock.patch.object(plugins, "get", return_value=ACMDestinationPlugin()),
        mock.patch.object(acm, "upload_cert") as upload,
    ):
        update_destinations(certificate, destination, None)
    assert upload.call_args.kwargs["replaces"] == [ROOTCA_CERT_STR]
    assert upload.call_args.kwargs["account_number"] == "123456789012"
    assert upload.call_args.kwargs["region"] == "us-east-1"


def test_acm_reimport_rejects_multiple_predecessors(app):
    from lemur.plugins.lemur_aws import acm

    client = mock.Mock()
    with pytest.raises(ValueError, match="Multiple predecessors may map to different ACM ARNs"):
        acm.upload_cert.__wrapped__(
            SAN_CERT_STR,
            SAN_CERT_KEY,
            replaces=[ROOTCA_CERT_STR, INTERMEDIATE_CERT_STR],
            client=client,
        )
    client.list_certificates.assert_not_called()
    client.import_certificate.assert_not_called()


def test_acm_source_sync_unlinks_old_certificate_without_deleting_arn(app):
    from lemur import database
    from lemur.certificates import service as certificates
    from lemur.destinations import service as destinations
    from lemur.plugins.base import plugins
    from lemur.plugins.lemur_aws import acm
    from lemur.plugins.lemur_aws.plugin import ACMSourcePlugin
    from lemur.sources import service as sources

    source = SimpleNamespace(
        id=1, label="acm", plugin_name="aws-acm-source", options=[]
    )
    destination = SimpleNamespace(label="acm")
    old = SimpleNamespace(
        id=1, name="old", sources=[source], destinations=[destination]
    )
    new = SimpleNamespace(id=2, name="new", sources=[], destinations=[destination])
    with (
        mock.patch.object(plugins, "get", return_value=ACMSourcePlugin()),
        mock.patch.object(
            acm,
            "get_imported_certificates",
            return_value=[{"arn": "arn:stable", "body": SAN_CERT_STR}],
        ),
        mock.patch.object(
            certificates, "get_all_valid_certificates_with_source", return_value=[old]
        ) as existing,
        mock.patch.object(sources, "find_cert", return_value=([new], 0)),
        mock.patch.object(destinations, "get_by_label", return_value=destination),
        mock.patch.object(database, "update"),
        mock.patch.object(certificates, "remove_from_destination") as remote_delete,
    ):
        sources.sync_certificates(source, SimpleNamespace(email="test@example.com"))

    existing.assert_called_once_with(source.id, include_replaced=True)
    assert old.sources == []
    assert old.destinations == []
    assert new.sources == [source]
    assert new.destinations == [destination]
    remote_delete.assert_not_called()


def test_acm_retry_after_timeout_when_aws_already_accepted(app, renewal_certificates):
    from lemur.plugins.lemur_aws import acm

    old, new = renewal_certificates(30), renewal_certificates(90)
    inventory = [{"arn": "arn:stable", "body": old}]
    client = mock.Mock()

    def accept_then_timeout(**kwargs):
        inventory[0]["body"] = kwargs["Certificate"].decode()
        raise TimeoutError("response lost after AWS accepted import")

    client.import_certificate.side_effect = accept_then_timeout
    with mock.patch.object(acm, "_get_imported_certificates", return_value=inventory):
        with pytest.raises(TimeoutError):
            acm.upload_cert.__wrapped__(
                new,
                SAN_CERT_KEY,
                replaces=[old],
                client=client,
            )
        result = acm.upload_cert.__wrapped__(
            new,
            SAN_CERT_KEY,
            replaces=[old],
            client=client,
        )

    assert result == {"CertificateArn": "arn:stable", "AlreadyExists": True}
    client.import_certificate.assert_called_once()


def test_acm_stale_retry_cannot_overwrite_visible_newer_generation(
    app, renewal_certificates
):
    from lemur.plugins.lemur_aws import acm

    old, new, newest = [renewal_certificates(days) for days in (30, 90, 180)]
    client = mock.Mock()
    with mock.patch.object(
        acm,
        "_get_imported_certificates",
        return_value=[{"arn": "arn:stable", "body": newest}],
    ):
        with pytest.raises(ValueError, match="No ACM ARN matches"):
            acm.upload_cert.__wrapped__(
                new,
                SAN_CERT_KEY,
                replaces=[old],
                client=client,
            )
    client.import_certificate.assert_not_called()


def test_acm_renewal_preserves_unrelated_same_hostname_certificate(
    app, renewal_certificates
):
    from lemur.plugins.lemur_aws import acm

    old, unrelated, new = [renewal_certificates(days) for days in (30, 60, 90)]
    client = mock.Mock()
    with mock.patch.object(
        acm,
        "_get_imported_certificates",
        return_value=[
            {"arn": "arn:unrelated", "body": unrelated},
            {"arn": "arn:managed", "body": old},
        ],
    ):
        acm.upload_cert.__wrapped__(
            new,
            SAN_CERT_KEY,
            replaces=[old],
            client=client,
        )
    client.import_certificate.assert_called_once()
    assert client.import_certificate.call_args.kwargs["CertificateArn"] == "arn:managed"


def test_acm_renewal_allows_additional_sans(app, renewal_certificates):
    from lemur.plugins.lemur_aws import acm

    old = renewal_certificates(30)
    new = renewal_certificates(
        90, names=("example.com", "www.example.com", "api.example.com")
    )
    client = mock.Mock()
    with mock.patch.object(
        acm,
        "_get_imported_certificates",
        return_value=[
            {"arn": "arn:stable", "body": old},
        ],
    ):
        acm.upload_cert.__wrapped__(
            new,
            SAN_CERT_KEY,
            replaces=[old],
            client=client,
        )
    assert client.import_certificate.call_args.kwargs["CertificateArn"] == "arn:stable"


def test_acm_source_failure_does_not_remove_associations(app):
    from lemur.certificates import service as certificates
    from lemur.plugins.base import plugins
    from lemur.sources import service as sources

    source = SimpleNamespace(
        id=1, label="acm", plugin_name="aws-acm-source", options=[]
    )
    plugin = mock.Mock()
    plugin.get_certificates.side_effect = RuntimeError("ACM inventory unavailable")
    with (
        mock.patch.object(plugins, "get", return_value=plugin),
        mock.patch.object(certificates, "remove_source_association") as remove_source,
        mock.patch.object(
            certificates, "remove_destination_association"
        ) as remove_destination,
    ):
        with pytest.raises(RuntimeError, match="inventory unavailable"):
            sources.sync_certificates(source, SimpleNamespace(email="test@example.com"))
    remove_source.assert_not_called()
    remove_destination.assert_not_called()


@pytest.mark.parametrize("plugin_name", ["aws-source", "aws-acm-source"])
def test_only_acm_source_includes_replaced_certificates(app, plugin_name):
    from lemur.certificates import service as certificates
    from lemur.destinations import service as destinations
    from lemur.plugins.base import plugins
    from lemur.plugins.lemur_aws.plugin import ACMSourcePlugin, AWSSourcePlugin
    from lemur.sources import service as sources

    plugin = ACMSourcePlugin() if plugin_name == "aws-acm-source" else AWSSourcePlugin()
    source = SimpleNamespace(id=1, label="test", plugin_name=plugin_name, options=[])
    with (
        mock.patch.object(plugins, "get", return_value=plugin),
        mock.patch.object(plugin, "get_certificates", return_value=[]),
        mock.patch.object(
            certificates, "get_all_valid_certificates_with_source", return_value=[]
        ) as existing,
        mock.patch.object(destinations, "get_by_label", return_value=None),
    ):
        sources.sync_certificates(source, SimpleNamespace(email="test@example.com"))
    existing.assert_called_once_with(
        1, include_replaced=plugin_name == "aws-acm-source"
    )


@pytest.mark.parametrize("entry_point", ["create", "upload", "acme"])
@pytest.mark.parametrize("failure", ["later_destination", "commit_after_acm"])
def test_acm_renewal_survives_delivery_failure(
    app, session, authority, renewal_certificates, entry_point, failure
):
    from lemur import database
    from lemur.certificates import service
    from lemur.certificates.models import Certificate
    from lemur.pending_certificates import service as pending_service
    from lemur.plugins.base import plugins
    from lemur.plugins.lemur_aws import acm
    from lemur.plugins.lemur_aws.plugin import ACMDestinationPlugin
    from lemur.tests.factories import (
        CertificateFactory,
        DestinationFactory,
        RoleFactory,
        UserFactory,
    )

    old_body, new_body = (
        renewal_certificates(30).strip(),
        renewal_certificates(90).strip(),
    )
    user = UserFactory()
    RoleFactory(name=user.email)
    old = CertificateFactory(body=old_body, chain=None, authority=authority, user=user)
    options = deepcopy(ACMDestinationPlugin.options)
    acm_destination = DestinationFactory(
        plugin_name="aws-acm-destination", options=options
    )
    other_destination = DestinationFactory(options=[])
    unattempted_destination = DestinationFactory(options=[])
    session.commit()
    old_id, authority_id = old.id, authority.id
    destinations = [acm_destination, other_destination, unattempted_destination]
    destination_ids = [destination.id for destination in destinations]
    inventory = [{"arn": "arn:stable", "body": old_body}]
    client = mock.Mock()
    other_plugin = mock.Mock(requires_key=True)
    pending = None
    real_commit = database.commit

    def accept_import(**kwargs):
        # Use a separate connection to prove persistence, not just an ORM flush.
        from sqlalchemy import select

        with database.db.engine.connect() as connection:
            saved = connection.execute(
                select([Certificate.id]).where(Certificate.body == new_body)
            ).scalar()
        assert saved is not None
        inventory[0]["body"] = kwargs["Certificate"].decode()
        return {"CertificateArn": "arn:stable"}

    def fail_commit_after_upload():
        if failure == "commit_after_acm" and inventory[0]["body"] == new_body:
            raise RuntimeError("simulated database failure")
        real_commit()

    client.import_certificate.side_effect = accept_import
    if failure == "later_destination":
        other_plugin.upload.side_effect = RuntimeError("simulated destination failure")
    uploader = acm.upload_cert.__wrapped__

    def upload_to_fake_acm(*args, **kwargs):
        return uploader(*args, **kwargs, client=client)

    data = dict(
        body=new_body,
        private_key=SAN_CERT_KEY,
        chain=None,
        owner=user.email,
        creator=user,
        authority=authority,
        replaces=[old],
        destinations=destinations,
        common_name="example.com",
        key_type="RSA2048",
        rotation=True,
    )
    with (
        mock.patch.object(service, "create_certificate_roles", return_value=[]),
        mock.patch.object(
            plugins,
            "get",
            side_effect=lambda name: (
                ACMDestinationPlugin()
                if name == "aws-acm-destination"
                else other_plugin
            ),
        ),
        mock.patch.object(acm, "_get_imported_certificates", return_value=inventory),
        mock.patch.object(acm, "upload_cert", side_effect=upload_to_fake_acm),
    ):
        if entry_point == "acme":
            with (
                mock.patch.dict(app.config, ACME_DISABLE_AUTORESOLVE=True),
                mock.patch.object(
                    service,
                    "mint",
                    return_value=(None, SAN_CERT_KEY, None, "pending-order", CSR_STR),
                ),
            ):
                pending = service.create(**data)
                session.refresh(pending)

        with (
            mock.patch.object(database, "commit", side_effect=fail_commit_after_upload),
            mock.patch.object(
                service,
                "mint",
                return_value=(new_body, SAN_CERT_KEY, None, "issued-order", None),
            ),
            pytest.raises(
                RuntimeError, match="Do not reissue another certificate"
            ) as error,
        ):
            if entry_point == "acme":
                pending_service.create_certificate(
                    pending,
                    dict(body=new_body, chain=None, external_id="issued-order"),
                    user,
                )
            else:
                getattr(service, entry_point)(**data)

        assert client.import_certificate.call_count == 1, repr(error.value.__cause__)
        assert "simulated" in str(error.value.__cause__), repr(error.value.__cause__)
        session.expire_all()
        saved = Certificate.query.filter_by(body=new_body).one()
        assert saved.private_key == SAN_CERT_KEY.strip()
        assert saved.authority_id == authority_id
        assert [certificate.id for certificate in saved.replaces] == [old_id]
        assert f"certificate ID {saved.id}" in str(error.value)
        assert "Delivery will not be retried automatically" in str(error.value)
        expected_ids = (
            destination_ids[1:] if failure == "later_destination" else destination_ids
        )
        for destination_id in expected_ids:
            assert f"ID {destination_id}" in str(error.value)
        assert [destination.id for destination in saved.destinations] == (
            [destination_ids[0]] if failure == "later_destination" else []
        )
        if pending is not None:
            assert pending.resolved
            assert pending.resolved_cert_id == saved.id

        # Retry delivery using the saved material, without calling the issuer again.
        other_plugin.upload.side_effect = None
        missing = [
            destination
            for destination in destinations
            if destination.id in expected_ids
        ]
        service.upload_saved_renewal(saved, missing)
        assert {destination.id for destination in saved.destinations} == set(
            destination_ids
        )
        assert Certificate.query.filter_by(body=new_body).count() == 1
        assert inventory[0]["body"] == new_body
        client.import_certificate.assert_called_once()
