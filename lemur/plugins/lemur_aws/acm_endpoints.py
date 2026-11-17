"""Read-only ACM endpoint inventory, independent of IAM discovery and deployment."""

from lemur.plugins.lemur_aws import elb


def certificate_reference(arn):
    return dict(name=arn, path="", registry_type="acm")


def is_acm(arn):
    parts = (arn or "").split(":", 5)
    return len(parts) == 6 and parts[0] == "arn" and parts[2] == "acm"


def get_elb_endpoints(account_number, region, load_balancer):
    endpoints = []
    for description in load_balancer["ListenerDescriptions"]:
        listener = description["Listener"]
        arn = listener.get("SSLCertificateId")
        if not is_acm(arn):
            continue
        policy = dict(name="elb-none", ciphers=[])
        if description["PolicyNames"]:
            response = elb.describe_load_balancer_policies(
                load_balancer["LoadBalancerName"], description["PolicyNames"],
                account_number=account_number, region=region,
            )
            for item in response["PolicyDescriptions"]:
                for attribute in item["PolicyAttributeDescriptions"]:
                    if attribute["AttributeName"] == "Reference-Security-Policy":
                        policy["name"] = attribute["AttributeValue"]
                    elif attribute["AttributeValue"] == "true":
                        policy["ciphers"].append(attribute["AttributeName"])
        endpoints.append(dict(
            name=load_balancer["LoadBalancerName"], dnsname=load_balancer["DNSName"],
            type="elb", port=listener["LoadBalancerPort"],
            primary_certificate=certificate_reference(arn), policy=policy,
        ))
    return endpoints


def get_elb_endpoints_v2(account_number, region, load_balancer):
    # Gateway Load Balancers do not terminate TLS or expose listener protocols.
    if load_balancer.get("Type") == "gateway":
        return []
    endpoints = []
    response = elb.describe_listeners_v2(
        account_number=account_number, region=region,
        LoadBalancerArn=load_balancer["LoadBalancerArn"],
    )
    for listener in response["Listeners"]:
        if listener["Protocol"] not in ("HTTPS", "TLS"):
            continue
        certificates = elb.describe_listener_certificates_v2(
            account_number=account_number, region=region,
            ListenerArn=listener["ListenerArn"],
        ).get("Certificates", [])
        # Mixed IAM/ACM listeners are outside ACM inventory's scope.
        if not certificates or not all(is_acm(cert["CertificateArn"]) for cert in certificates):
            continue
        primary = [cert for cert in certificates if cert.get("IsDefault", False)]
        if len(primary) > 1:
            raise ValueError("Multiple default certificates on an ACM listener")
        policy = dict(name="elbv2-none", ciphers=[])
        if listener.get("SslPolicy"):
            policies = elb.describe_ssl_policies_v2(
                [listener["SslPolicy"]], account_number=account_number, region=region,
            )["SslPolicies"]
            for item in policies:
                policy["name"] = item["Name"]
                policy["ciphers"].extend(cipher["Name"] for cipher in item["Ciphers"])
        endpoint = dict(
            name=load_balancer["LoadBalancerName"], dnsname=load_balancer["DNSName"],
            type="elbv2", port=listener["Port"], policy=policy,
            sni_certificates=[certificate_reference(cert["CertificateArn"])
                              for cert in certificates if not cert.get("IsDefault", False)],
        )
        if primary:
            endpoint["primary_certificate"] = certificate_reference(primary[0]["CertificateArn"])
        endpoints.append(endpoint)
    return endpoints


def get_distribution_endpoint(distribution):
    viewer = distribution.get("ViewerCertificate") or {}
    arn = viewer.get("ACMCertificateArn")
    if viewer.get("CloudFrontDefaultCertificate") or not is_acm(arn):
        return None
    minimum_version = viewer.get("MinimumProtocolVersion")
    return dict(
        name=distribution["Id"], dnsname=distribution["DomainName"],
        aliases=distribution.get("Aliases", {}).get("Items", []), type="cloudfront", port=443,
        primary_certificate=certificate_reference(arn),
        policy=dict(name=f"cloudfront-{minimum_version}" if minimum_version else "cloudfront-none",
                    ciphers=[minimum_version] if minimum_version else []),
    )
