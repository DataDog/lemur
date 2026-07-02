import time

import boto3
import dns.exception
import dns.resolver
from flask import current_app

from lemur.plugins.lemur_digicert_dcv.provider import DCVPropagationTimeout, DNSRecord


class Route53DCVWriter:
    def _client(self):
        sts = boto3.client("sts")
        role_arn = current_app.config.get("DIGICERT_DCV_ROUTE53_ROLE_ARN")
        if not role_arn:
            raise ValueError("DIGICERT_DCV_ROUTE53_ROLE_ARN not configured")
        role = sts.assume_role(RoleArn=role_arn, RoleSessionName="lemur-dcv")
        creds = role["Credentials"]
        return boto3.client(
            "route53",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    def _zone_id(self, client) -> str:
        zone_name = current_app.config.get("DIGICERT_DCV_DNS_ZONE", "acme-certs.prod.dog")
        paginator = client.get_paginator("list_hosted_zones")
        for page in paginator.paginate():
            for zone in page["HostedZones"]:
                if zone["Name"].rstrip(".") == zone_name:
                    return zone["Id"]
        raise ValueError(f"Route53 hosted zone {zone_name!r} not found")

    def upsert(self, record: DNSRecord) -> None:
        client = self._client()
        zone_id = self._zone_id(client)
        client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [{
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": record.name,
                        "Type": "CNAME",
                        "TTL": 300,
                        "ResourceRecords": [{"Value": record.value}],
                    },
                }]
            },
        )

    def delete(self, record_name: str) -> None:
        """Delete the CNAME record for record_name. Silent if not found."""
        client = self._client()
        zone_id = self._zone_id(client)
        resp = client.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordName=record_name,
            StartRecordType="CNAME",
            MaxItems="1",
        )
        for rrs in resp.get("ResourceRecordSets", []):
            if rrs["Name"].rstrip(".") == record_name.rstrip(".") and rrs["Type"] == "CNAME":
                client.change_resource_record_sets(
                    HostedZoneId=zone_id,
                    ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
                )
                return

    def wait_for_propagation(self, record: DNSRecord) -> None:
        timeout_secs = current_app.config.get("DIGICERT_DCV_PROPAGATION_TIMEOUT_SECS", 600)
        deadline = time.time() + timeout_secs
        while time.time() < deadline:
            if self._is_propagated(record):
                return
            remaining = deadline - time.time()
            if remaining > 0:
                time.sleep(min(10, remaining))
        raise DCVPropagationTimeout(domain=record.name, record_name=record.name)

    def _is_propagated(self, record: DNSRecord) -> bool:
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(record.name, "CNAME")
            for rdata in answers:
                if str(rdata.target).rstrip(".") == record.value.rstrip("."):
                    return True
        except dns.exception.DNSException:
            pass
        return False
