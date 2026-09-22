from unittest.mock import Mock, patch

from lemur.plugins.lemur_acme import gcp

OPTIONS = {
    "projectID": "datadog-staging",
    "authenticationMethod": "vault",
    "vaultMountPoint": "cloud-iam/gcp/datadog-staging/impersonated-account/lemur",
}


def zone(name, dns_name, public=True):
    result = Mock()
    result.name = name
    result.dns_name = dns_name
    result.name_servers = ["ns-cloud.example."] if public else None
    return result


def txt_record(name, values, ttl=60):
    result = Mock()
    result.record_type = "TXT"
    result.name = name
    result.ttl = ttl
    result.rrdatas = values
    return result


@patch("lemur.plugins.lemur_acme.gcp._get_client")
def test_get_zones_returns_public_zones(mock_get_client):
    mock_get_client.return_value.list_zones.return_value = [
        zone("example", "example.com."),
        zone("private", "private.example.com.", public=False),
    ]

    assert gcp.get_zones(OPTIONS) == ["example.com"]


@patch("lemur.plugins.lemur_acme.gcp._get_client")
def test_create_txt_record_uses_most_specific_zone_and_preserves_records(
    mock_get_client,
):
    parent_zone = zone("parent", "example.com.")
    child_zone = zone("child", "sub.example.com.")
    existing = txt_record(
        "_acme-challenge.test.sub.example.com.",
        ['"existing-token"'],
    )
    child_zone.list_resource_record_sets.return_value = [existing]
    replacement = child_zone.resource_record_set.return_value
    mock_get_client.return_value.list_zones.return_value = [parent_zone, child_zone]

    change_id = gcp.create_txt_record(
        "_acme-challenge.test.sub.example.com", "new-token", OPTIONS
    )

    assert change_id == (
        "child",
        "sub.example.com",
        "_acme-challenge.test.sub.example.com",
        "new-token",
    )
    child_zone.resource_record_set.assert_called_once_with(
        "_acme-challenge.test.sub.example.com.",
        "TXT",
        60,
        ['"existing-token"', '"new-token"'],
    )
    changes = child_zone.changes.return_value
    changes.delete_record_set.assert_called_once_with(existing)
    changes.add_record_set.assert_called_once_with(replacement)
    changes.create.assert_called_once_with()


@patch("lemur.plugins.lemur_acme.gcp._get_client")
def test_create_txt_record_creates_missing_record_set(mock_get_client):
    managed_zone = zone("example", "example.com.")
    managed_zone.list_resource_record_sets.return_value = []
    mock_get_client.return_value.list_zones.return_value = [managed_zone]

    gcp.create_txt_record("_acme-challenge.test.example.com", "new-token", OPTIONS)

    managed_zone.resource_record_set.assert_called_once_with(
        "_acme-challenge.test.example.com.", "TXT", 300, ['"new-token"']
    )
    managed_zone.changes.return_value.delete_record_set.assert_not_called()


@patch("lemur.plugins.lemur_acme.gcp._get_client")
def test_delete_txt_record_preserves_other_values(mock_get_client):
    managed_zone = zone("example", "example.com.")
    existing = txt_record(
        "_acme-challenge.test.example.com.",
        ['"old-token"', '"other-token"'],
    )
    managed_zone.list_resource_record_sets.return_value = [existing]
    replacement = managed_zone.resource_record_set.return_value
    mock_get_client.return_value.zone.return_value = managed_zone

    gcp.delete_txt_record(
        ("example", "example.com", "_acme-challenge.test.example.com", "old-token"),
        OPTIONS,
        "_acme-challenge.test.example.com",
        "old-token",
    )

    managed_zone.resource_record_set.assert_called_once_with(
        "_acme-challenge.test.example.com.", "TXT", 60, ['"other-token"']
    )
    changes = managed_zone.changes.return_value
    changes.delete_record_set.assert_called_once_with(existing)
    changes.add_record_set.assert_called_once_with(replacement)
    changes.create.assert_called_once_with()


@patch("lemur.plugins.lemur_acme.gcp._get_client")
def test_delete_txt_record_deletes_empty_record_set(mock_get_client):
    managed_zone = zone("example", "example.com.")
    existing = txt_record(
        "_acme-challenge.test.example.com.",
        ['"old-token"'],
    )
    managed_zone.list_resource_record_sets.return_value = [existing]
    mock_get_client.return_value.zone.return_value = managed_zone

    gcp.delete_txt_record(
        [("example", "example.com", "_acme-challenge.test.example.com", "old-token")],
        OPTIONS,
        "_acme-challenge.test.example.com",
        "old-token",
    )

    changes = managed_zone.changes.return_value
    changes.delete_record_set.assert_called_once_with(existing)
    changes.add_record_set.assert_not_called()
    changes.create.assert_called_once_with()


@patch("lemur.plugins.lemur_acme.gcp.time.sleep")
@patch("lemur.plugins.lemur_acme.gcp.dnsutil.get_dns_records")
@patch("lemur.plugins.lemur_acme.gcp.dnsutil.get_authoritative_nameserver")
def test_wait_for_dns_change(mock_get_nameserver, mock_get_dns_records, mock_sleep):
    mock_get_nameserver.return_value = "192.0.2.53"
    mock_get_dns_records.side_effect = [[], ["new-token"]]
    change_id = (
        "example",
        "example.com",
        "_acme-challenge.test.example.com",
        "new-token",
    )

    gcp.wait_for_dns_change(change_id, OPTIONS)

    mock_get_nameserver.assert_called_once_with("example.com")
    assert mock_get_dns_records.call_count == 2
    mock_get_dns_records.assert_called_with(
        "_acme-challenge.test.example.com", "TXT", "192.0.2.53"
    )
    mock_sleep.assert_called_once_with(5)
