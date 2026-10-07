import pytest
from unittest.mock import Mock

from lemur.plugins.bases.destination import DestinationPlugin

from lemur.destinations.views import *  # noqa


from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)


@pytest.mark.parametrize(
    "error,status",
    [
        (None, 200),
        (NotImplementedError(), 501),
        (TimeoutError(), 504),
        (RuntimeError("secret upstream response"), 502),
    ],
)
def test_destination_check(client, destination, monkeypatch, error, status):
    plugin = Mock()
    plugin.check_connection.side_effect = error
    monkeypatch.setattr(type(destination), "plugin", property(lambda self: plugin))
    response = client.post(
        api.url_for(DestinationCheck, destination_id=destination.id),
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert response.status_code == status
    plugin.check_connection.assert_called_once_with(destination.options)
    plugin.upload.assert_not_called()
    assert "secret upstream response" not in response.get_data(as_text=True)


@pytest.mark.parametrize("plugin", [DestinationPlugin(), object()])
def test_destination_check_unsupported(client, destination, monkeypatch, plugin):
    monkeypatch.setattr(type(destination), "plugin", property(lambda self: plugin))
    response = client.post(
        api.url_for(DestinationCheck, destination_id=destination.id),
        headers=VALID_ADMIN_HEADER_TOKEN,
    )
    assert response.status_code == 501


@pytest.mark.parametrize(
    "token,status",
    [(VALID_USER_HEADER_TOKEN, 403), (VALID_ADMIN_HEADER_TOKEN, 404), ("", 401)],
)
def test_destination_check_access(client, token, status):
    response = client.post(
        api.url_for(DestinationCheck, destination_id=999999), headers=token
    )
    assert response.status_code == status


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
