from unittest.mock import Mock, patch

from azure.core.exceptions import ResourceNotFoundError
from azure.mgmt.dns.models import RecordSet, TxtRecord

from lemur.plugins.lemur_acme import azure

OPTIONS = {
    "subscription_id": "subscription-id",
    "authenticationMethod": "hashicorpVault",
    "azureTenant": "tenant-id",
    "hashicorpVaultMountPoint": "azure",
    "hashicorpVaultRoleName": "lemur",
}


def zone(name, resource_group):
    result = Mock()
    result.name = name
    result.id = (
        f"/subscriptions/subscription-id/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Network/dnsZones/{name}"
    )
    return result


@patch("lemur.plugins.lemur_acme.azure._get_client")
def test_get_zones(mock_get_client):
    mock_get_client.return_value.zones.list.return_value = [
        zone("example.com", "example"),
        zone("sub.example.com", "sub"),
    ]

    assert azure.get_zones(OPTIONS) == ["example.com", "sub.example.com"]


@patch("lemur.plugins.lemur_acme.azure._get_client")
def test_create_txt_record_uses_most_specific_zone_and_preserves_records(
    mock_get_client,
):
    client = mock_get_client.return_value
    client.zones.list.return_value = [
        zone("example.com", "example"),
        zone("sub.example.com.", "sub"),
    ]
    client.record_sets.get.return_value = RecordSet(
        ttl=60, txt_records=[TxtRecord(value=["existing-token"])]
    )

    change_id = azure.create_txt_record(
        "_acme-challenge.test.sub.example.com", "new-token", OPTIONS
    )

    assert change_id == (
        "sub",
        "sub.example.com",
        "_acme-challenge.test",
        "_acme-challenge.test.sub.example.com",
        "new-token",
    )
    record_set = client.record_sets.create_or_update.call_args.args[4]
    assert record_set.ttl == 60
    assert [record.value for record in record_set.txt_records] == [
        ["existing-token"],
        ["new-token"],
    ]


@patch("lemur.plugins.lemur_acme.azure._get_client")
def test_create_txt_record_creates_missing_record_set(mock_get_client):
    client = mock_get_client.return_value
    client.zones.list.return_value = [zone("example.com", "example")]
    client.record_sets.get.side_effect = ResourceNotFoundError("missing")

    azure.create_txt_record("_acme-challenge.test.example.com", "new-token", OPTIONS)

    record_set = client.record_sets.create_or_update.call_args.args[4]
    assert record_set.ttl == 300
    assert [record.value for record in record_set.txt_records] == [["new-token"]]


@patch("lemur.plugins.lemur_acme.azure._get_client")
def test_delete_txt_record_preserves_other_values(mock_get_client):
    client = mock_get_client.return_value
    client.record_sets.get.return_value = RecordSet(
        ttl=60,
        txt_records=[
            TxtRecord(value=["old-token"]),
            TxtRecord(value=["other-token"]),
        ],
    )
    change_ids = [
        (
            "sub",
            "sub.example.com",
            "_acme-challenge.test",
            "_acme-challenge.test.sub.example.com",
            "old-token",
        )
    ]

    azure.delete_txt_record(
        change_ids,
        OPTIONS,
        "_acme-challenge.test.sub.example.com",
        "old-token",
    )

    record_set = client.record_sets.create_or_update.call_args.args[4]
    assert [record.value for record in record_set.txt_records] == [["other-token"]]
    client.record_sets.delete.assert_not_called()


@patch("lemur.plugins.lemur_acme.azure._get_client")
def test_delete_txt_record_deletes_empty_record_set(mock_get_client):
    client = mock_get_client.return_value
    client.record_sets.get.return_value = RecordSet(
        ttl=60, txt_records=[TxtRecord(value=["old-token"])]
    )
    change_ids = [
        (
            "sub",
            "sub.example.com",
            "_acme-challenge.test",
            "_acme-challenge.test.sub.example.com",
            "old-token",
        )
    ]

    azure.delete_txt_record(
        change_ids,
        OPTIONS,
        "_acme-challenge.test.sub.example.com",
        "old-token",
    )

    client.record_sets.delete.assert_called_once_with(
        "sub", "sub.example.com", "_acme-challenge.test", "TXT"
    )


@patch("lemur.plugins.lemur_acme.azure._get_client")
def test_delete_txt_record_accepts_single_change_tuple(mock_get_client):
    client = mock_get_client.return_value
    client.record_sets.get.return_value = RecordSet(
        ttl=60, txt_records=[TxtRecord(value=["old-token"])]
    )
    change_id = (
        "sub",
        "sub.example.com",
        "_acme-challenge.test",
        "_acme-challenge.test.sub.example.com",
        "old-token",
    )

    azure.delete_txt_record(
        change_id,
        OPTIONS,
        "_acme-challenge.test.sub.example.com",
        "old-token",
    )

    client.record_sets.delete.assert_called_once_with(
        "sub", "sub.example.com", "_acme-challenge.test", "TXT"
    )
    client.record_sets.create_or_update.assert_not_called()


@patch("lemur.plugins.lemur_acme.azure.time.sleep")
@patch("lemur.plugins.lemur_acme.azure.dnsutil.get_dns_records")
@patch("lemur.plugins.lemur_acme.azure.dnsutil.get_authoritative_nameserver")
def test_wait_for_dns_change(mock_get_nameserver, mock_get_dns_records, mock_sleep):
    mock_get_nameserver.return_value = "192.0.2.53"
    mock_get_dns_records.side_effect = [[], ["new-token"]]
    change_id = (
        "sub",
        "sub.example.com",
        "_acme-challenge.test",
        "_acme-challenge.test.sub.example.com",
        "new-token",
    )

    azure.wait_for_dns_change(change_id, OPTIONS)

    mock_get_nameserver.assert_called_once_with("sub.example.com")
    assert mock_get_dns_records.call_count == 2
    mock_get_dns_records.assert_called_with(
        "_acme-challenge.test.sub.example.com", "TXT", "192.0.2.53"
    )
    mock_sleep.assert_called_once_with(5)
