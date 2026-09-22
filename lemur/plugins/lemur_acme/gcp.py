import time

from google.cloud import dns

import lemur.dns_providers.util as dnsutil
from lemur.plugins.lemur_gcp.auth import get_gcp_credentials_from_options


def _get_client(options):
    return dns.Client(
        project=options["projectID"],
        credentials=get_gcp_credentials_from_options(options),
    )


def _public_zones(client):
    return [zone for zone in client.list_zones() if zone.name_servers]


def _find_zone(host, client):
    matching_zones = []
    for zone in _public_zones(client):
        zone_name = zone.dns_name.rstrip(".")
        if host == zone_name or host.endswith("." + zone_name):
            matching_zones.append((zone, zone_name))

    if not matching_zones:
        raise ValueError(f"Unable to find a GCP Cloud DNS zone for {host}")

    return max(matching_zones, key=lambda candidate: len(candidate[1]))


def _find_txt_record(zone, host):
    fqdn = host.rstrip(".") + "."
    for record in zone.list_resource_record_sets():
        if record.record_type == "TXT" and record.name == fqdn:
            return record
    return None


def _matches_value(rrdata, value):
    return rrdata == value or rrdata == f'"{value}"'


def get_zones(account_number=None):
    return [
        zone.dns_name.rstrip(".") for zone in _public_zones(_get_client(account_number))
    ]


def create_txt_record(host, value, account_number):
    zone, zone_name = _find_zone(host, _get_client(account_number))
    existing = _find_txt_record(zone, host)
    values = list(existing.rrdatas) if existing else []
    if not any(_matches_value(rrdata, value) for rrdata in values):
        values.append(f'"{value}"')

        changes = zone.changes()
        if existing:
            changes.delete_record_set(existing)
        changes.add_record_set(
            zone.resource_record_set(
                host.rstrip(".") + ".",
                "TXT",
                existing.ttl if existing else 300,
                values,
            )
        )
        changes.create()

    return zone.name, zone_name, host, value


def wait_for_dns_change(change_id, account_number=None):
    _, zone_name, host, value = change_id
    nameserver = dnsutil.get_authoritative_nameserver(zone_name)
    for _ in range(12):
        if value in dnsutil.get_dns_records(host, "TXT", nameserver):
            return
        time.sleep(5)
    raise RuntimeError(f"GCP Cloud DNS TXT record did not propagate for {host}")


def delete_txt_record(change_ids, account_number, host, value):
    if isinstance(change_ids, tuple):
        change_ids = [change_ids]

    client = _get_client(account_number)
    for zone_id, _, _, _ in change_ids:
        zone = client.zone(zone_id)
        existing = _find_txt_record(zone, host)
        if not existing:
            continue

        remaining = [
            rrdata for rrdata in existing.rrdatas if not _matches_value(rrdata, value)
        ]
        if len(remaining) == len(existing.rrdatas):
            continue

        changes = zone.changes()
        changes.delete_record_set(existing)
        if remaining:
            changes.add_record_set(
                zone.resource_record_set(
                    existing.name,
                    "TXT",
                    existing.ttl,
                    remaining,
                )
            )
        changes.create()
