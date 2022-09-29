from collections import defaultdict
from google.cloud.compute_v1.services import ssl_certificates, ssl_policies, \
    global_forwarding_rules, target_https_proxies, target_ssl_proxies
from google.cloud.compute_v1 import TargetHttpsProxiesSetSslCertificatesRequest, \
    TargetSslProxiesSetSslCertificatesRequest


def fetch_target_proxies(project_id, credentials):
    """
    Fetches HTTPs target proxies for L7 traffic and SSL target proxies for L4 traffic.

    :param project_id:
    :param credentials:
    :return:
    """
    endpoints = []
    forwarding_rules_map = fetch_global_forwarding_rules_map(project_id, credentials)
    http_proxies_client = target_https_proxies.TargetHttpsProxiesClient(credentials=credentials)
    ssl_policies_client = ssl_policies.SslPoliciesClient(credentials=credentials)
    ssl_client = ssl_certificates.SslCertificatesClient(credentials=credentials)
    for proxy in http_proxies_client.list(project=project_id):
        endpoint = get_endpoint_from_proxy(project_id, proxy, ssl_policies_client, ssl_client, forwarding_rules_map)
        if endpoint:
            endpoints.append(endpoint)
    ssl_proxies_client = target_ssl_proxies.TargetSslProxiesClient(credentials=credentials)
    for proxy in ssl_proxies_client.list(project=project_id):
        endpoint = get_endpoint_from_proxy(project_id, proxy, ssl_policies_client, ssl_client, forwarding_rules_map)
        if endpoint:
            endpoints.append(endpoint)
    return endpoints


def get_endpoint_from_proxy(project_id, proxy, ssl_policies_client, ssl_client, forwarding_rules_map):
    """
    Converts a proxy (either HTTPs or SSL) into a Lemur endpoint.
    :param project_id:
    :param proxy:
    :param ssl_policies_client:
    :param ssl_client:
    :param forwarding_rules_map:
    :return:
    """
    kind = proxy.kind.split("#")[-1].lower()
    if kind not in ("targethttpsproxy", "targetsslproxy"):
        return None
    if len(proxy.ssl_certificates) == 0:
        return None
    fw_rules = forwarding_rules_map.get(proxy.self_link, None)
    if not fw_rules:
        return None
    # The first certificate is the primary.
    # See https://cloud.google.com/sdk/gcloud/reference/compute/target-https-proxies/update
    ssl_cert_name = get_name_from_self_link(proxy.ssl_certificates[0])
    cert = ssl_client.get(project=project_id, ssl_certificate=ssl_cert_name)
    primary_certificate = dict(
        name=cert.name,
        registry_type="gcp",
        path="",
    )
    fw_rule_ingresses = []
    for rule in fw_rules:
        ip = rule.I_p_address
        port = rule.port_range.split("-")[0]
        fw_rule_ingresses.append((ip, port))
    fw_rule_ingresses.sort()
    primary_ip, primary_port = fw_rule_ingresses[0][0], fw_rule_ingresses[0][1]
    endpoint = dict(
        name=proxy.name,
        type=kind,
        primary_certificate=primary_certificate,
        dnsname=primary_ip,
        port=primary_port,
        policy=dict(
            name="",
            ciphers=[],
        ),
    )
    if len(fw_rule_ingresses) > 1:
        endpoint["aliases"] = [info[0] for info in fw_rule_ingresses[1:]]
    if proxy.ssl_policy:
        policy = ssl_policies_client.get(
            project=project_id,
            ssl_policy=get_name_from_self_link(proxy.ssl_policy))
        endpoint["policy"] = format_ssl_policy(policy)
    return endpoint


def update_target_proxy_cert(project_id, credentials, endpoint, certificate):
    kind = endpoint.type
    if kind not in ("targethttpsproxy", "targetsslproxy") or endpoint.registry_type != "gcp":
        raise NotImplementedError()
    if kind == "targethttpsproxy":
        client = target_https_proxies.TargetHttpsProxiesClient(credentials=credentials)
        proxy = client.get(project=project_id, target_https_proxy=endpoint.name)
        if len(proxy.ssl_certificates) > 1:
            raise NotImplementedError("GCP endpoints with multiple certificates for SNI are not supported currently.")
        req = TargetHttpsProxiesSetSslCertificatesRequest()
        req.ssl_certificates = [certificate.name]
        print("req=", req)
        operation = client.set_ssl_certificates(
            project=project_id,
            target_https_proxy=endpoint.name,
            target_https_proxies_set_ssl_certificates_request_resource=req,
        )
        print("result=", operation.result())
    elif kind == "targetsslproxy":
        client = target_ssl_proxies.TargetSslProxiesClient(credentials=credentials)
        proxy = client.get(project=project_id, target_ssl_proxy=endpoint.name)
        if len(proxy.ssl_certificates) > 1:
            raise NotImplementedError("GCP endpoints with multiple certificates for SNI are not supported currently.")
        req = TargetSslProxiesSetSslCertificatesRequest()
        req.ssl_certificates = [certificate.name]
        operation = client.set_ssl_certificates(
            project=project_id,
            target_ssl_proxy=endpoint.name,
            target_ssl_proxies_set_ssl_certificates_request_resource=req,
        )
        print("result=", operation.result())


def fetch_global_forwarding_rules_map(project_id, credentials):
    """
    Gets the global forwarding rules for the project, keyed by target name.
    :param project_id:
    :param credentials:
    :return:
    """
    forwarding_rules_client = global_forwarding_rules.GlobalForwardingRulesClient(credentials=credentials)
    forwarding_rules_map = defaultdict(list)
    # Multiple forwarding rules can reference the same target proxy
    # Construct a mapping of targets -> list of forwarding rules that use the target
    for rule in forwarding_rules_client.list(project=project_id):
        forwarding_rules_map[rule.target].append(rule)
    return forwarding_rules_map


def get_name_from_self_link(self_link):
    """
    Returns the resource name from a self_link name.
    :param self_link:
    :return:
    """
    return self_link.split("/")[-1]


def format_ssl_policy(policy):
    """
    Format cipher policy information for an HTTPs target proxy into a common format.
    :param policy:
    :return:
    """
    if not policy:
        return dict(name="", ciphers=[])
    return dict(name=policy.name, ciphers=[cipher for cipher in policy.enabled_features])
