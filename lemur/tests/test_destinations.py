import pytest

from lemur.destinations.views import *  # noqa


from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)


def test_destination_input_schema(client, destination_plugin, destination):
    from lemur.destinations.schemas import DestinationInputSchema

    input_data = {
        "label": "destination1",
        "options": {},
        "description": "my destination",
        "active": True,
        "plugin": {"slug": "test-destination"},
    }

    data, errors = DestinationInputSchema().load(input_data)

    assert not errors


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 404),
        (VALID_ADMIN_HEADER_TOKEN, 404),
        (VALID_ADMIN_API_TOKEN, 404),
        ("", 401),
    ],
)
def test_destination_get(client, token, status):
    assert (
        client.get(
            api.url_for(Destinations, destination_id=1), headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_destination_post_(client, token, status):
    assert (
        client.post(
            api.url_for(Destinations, destination_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_destination_put(client, token, status):
    assert (
        client.put(
            api.url_for(Destinations, destination_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_destination_delete(client, token, status):
    assert (
        client.delete(
            api.url_for(Destinations, destination_id=1), headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_destination_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(Destinations, destination_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 403),
        (VALID_ADMIN_HEADER_TOKEN, 400),
        (VALID_ADMIN_API_TOKEN, 400),
        ("", 401),
    ],
)
def test_destination_list_post_(client, token, status):
    assert (
        client.post(api.url_for(DestinationsList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_destination_list_get(client, token, status):
    assert (
        client.get(api.url_for(DestinationsList), headers=token).status_code == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_destination_list_delete(client, token, status):
    assert (
        client.delete(api.url_for(DestinationsList), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_destination_list_patch(client, token, status):
    assert (
        client.patch(api.url_for(DestinationsList), data={}, headers=token).status_code
        == status
    )


def _aws_destination_options(path="/"):
    return [
        {"name": "accountNumber", "type": "str", "value": "123456789012"},
        {"name": "path", "type": "str", "value": path},
    ]


def test_update_destination_renames_paired_source(session):
    from lemur.destinations import service as destination_service
    from lemur.plugins.utils import get_plugin_option
    from lemur.sources import service as source_service
    from lemur.sources.models import Source

    destination = destination_service.create(
        "rename-old", "aws-destination", _aws_destination_options(), "old"
    )
    source = source_service.get_by_label("rename-old")
    source_count = session.query(Source).count()

    destination_service.update(
        destination.id,
        "rename-new",
        "aws-destination",
        _aws_destination_options(path="/new/"),
        "new",
    )

    assert session.query(Source).count() == source_count
    assert not source_service.get_by_label("rename-old")
    renamed = source_service.get_by_label("rename-new")
    assert renamed.id == source.id
    assert renamed.description == "new"
    assert get_plugin_option("path", renamed.options) == "/new/"
    # options match what syncing the destination as a new source would have produced
    created = destination_service.create(
        "rename-fresh", "aws-destination", _aws_destination_options(path="/new/")
    )
    assert renamed.options == source_service.get_by_label(created.label).options


def test_update_destination_creates_missing_source(session):
    from lemur.destinations import service as destination_service
    from lemur.sources import service as source_service
    from lemur.tests.factories import DestinationFactory

    destination = DestinationFactory(
        label="unpaired-old",
        plugin_name="aws-destination",
        options=_aws_destination_options(),
    )
    session.commit()

    destination_service.update(
        destination.id, "unpaired-new", "aws-destination", _aws_destination_options(), None
    )

    assert not source_service.get_by_label("unpaired-old")
    assert source_service.get_by_label("unpaired-new").plugin_name == "aws-source"


def test_update_destination_after_source_renamed(session):
    from lemur.destinations import service as destination_service
    from lemur.sources import service as source_service
    from lemur.sources.models import Source

    destination = destination_service.create(
        "manual-old", "aws-destination", _aws_destination_options()
    )
    source = source_service.get_by_label("manual-old")
    source_service.update(
        source.id, "manual-new", source.plugin_name, source.options, source.description
    )
    source_count = session.query(Source).count()

    destination_service.update(
        destination.id, "manual-new", "aws-destination", _aws_destination_options(), None
    )

    assert session.query(Source).count() == source_count
    assert source_service.get_by_label("manual-new").id == source.id


def test_update_destination_keeps_source_of_other_destination(session):
    from lemur.destinations import service as destination_service
    from lemur.sources import service as source_service

    destination = destination_service.create(
        "shared-label", "aws-destination", _aws_destination_options()
    )
    destination_service.create("shared-label", "aws-destination", _aws_destination_options())
    shared_source = source_service.get_by_label("shared-label")

    destination_service.update(
        destination.id, "split-label", "aws-destination", _aws_destination_options(), None
    )

    assert source_service.get_by_label("shared-label").id == shared_source.id
    assert source_service.get_by_label("split-label").id != shared_source.id
