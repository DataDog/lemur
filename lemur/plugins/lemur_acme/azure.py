import time

from azure.core.exceptions import ResourceNotFoundError
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet, TxtRecord
import dns.exception
import dns.resolver

from lemur.plugins.lemur_azure.auth import get_azure_credential_from_options

AZURE_MANAGEMENT_AUDIENCE = "https://management.azure.com/"


def _get_client(options):
    credential = get_azure_credential_from_options(AZURE_MANAGEMENT_AUDIENCE, options)
    return DnsManagementClient(credential, options["subscription_id"])


def _resource_group(resource_id):
    parts = resource_id.strip("/").split("/")
    return parts[parts.index("resourceGroups") + 1]


def _find_zone(host, client):
    matching_zones = [
        zone
        for zone in client.zones.list()
        if host == zone.name or host.endswith("." + zone.name)
    ]
    if not matching_zones:
        raise ValueError(f"Unable to find an Azure DNS zone for {host}")

    zone = max(matching_zones, key=lambda candidate: len(candidate.name))
    return _resource_group(zone.id), zone.name


def _relative_name(host, zone):
    if host == zone:
        return "@"
    return host[: -(len(zone) + 1)]


def get_zones(account_number=None):
    return [zone.name.rstrip(".") for zone in _get_client(account_number).zones.list()]


def create_txt_record(host, value, account_number):
    client = _get_client(account_number)
    resource_group, zone = _find_zone(host, client)
    relative_name = _relative_name(host, zone)

    try:
        record_set = client.record_sets.get(resource_group, zone, relative_name, "TXT")
    except ResourceNotFoundError:
        record_set = RecordSet(ttl=300, txt_records=[])

    txt_records = record_set.txt_records or []
    if not any("".join(record.value or []) == value for record in txt_records):
        txt_records.append(TxtRecord(value=[value]))

    client.record_sets.create_or_update(
        resource_group,
        zone,
        relative_name,
        "TXT",
        RecordSet(ttl=record_set.ttl or 300, txt_records=txt_records),
    )
    return resource_group, zone, relative_name, host, value


def wait_for_dns_change(change_id, account_number=None):
    _, _, _, host, value = change_id
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    for _ in range(12):
        try:
            records = resolver.resolve(host, "TXT")
            if any(
                value == "".join(part.decode("utf-8") for part in record.strings)
                for record in records
            ):
                return
        except dns.exception.DNSException:
            pass
        time.sleep(5)
    raise RuntimeError(f"Azure DNS TXT record did not propagate for {host}")


def delete_txt_record(change_ids, account_number, host, value):
    client = _get_client(account_number)
    for resource_group, zone, relative_name, _, _ in change_ids:
        try:
            record_set = client.record_sets.get(
                resource_group, zone, relative_name, "TXT"
            )
        except ResourceNotFoundError:
            continue

        remaining = [
            record
            for record in record_set.txt_records or []
            if "".join(record.value or []) != value
        ]
        if remaining:
            client.record_sets.create_or_update(
                resource_group,
                zone,
                relative_name,
                "TXT",
                RecordSet(ttl=record_set.ttl or 300, txt_records=remaining),
            )
        else:
            client.record_sets.delete(resource_group, zone, relative_name, "TXT")
