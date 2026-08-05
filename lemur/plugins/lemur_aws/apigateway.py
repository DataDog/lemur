"""
.. module: lemur.plugins.lemur_aws.apigateway
    :synopsis: Helper code for discovering API Gateway custom-domain endpoints

.. moduleauthor:: <lemur@datadoghq.com>
"""

from sentry_sdk import capture_exception

from lemur.extensions import metrics
from lemur.plugins.lemur_aws.sts import sts_client


@sts_client("apigateway")
def get_all_domain_names(**kwargs):
    """
    Fetches all API Gateway custom domain names for a given account/region.

    :param kwargs:
        account_number: AWS account number
        region: AWS region
    :return: list of domain-name dicts
    """
    client = kwargs.pop("client")
    domains = []
    try:
        paginator = client.get_paginator("get_domain_names")
        for page in paginator.paginate():
            domains += page.get("items", [])
        return domains
    except Exception:  # noqa
        metrics.send("list_all_apigateway_domain_names_error", "counter", 1)
        capture_exception()
        raise


@sts_client("apigateway")
def get_domain_name(domain_name, **kwargs):
    """
    Fetches a single API Gateway custom domain by name.

    :param domain_name: the custom domain name (e.g. api.example.com)
    :param kwargs:
        account_number: AWS account number
        region: AWS region
    :return: the domain-name dict
    """
    client = kwargs.pop("client")
    try:
        return client.get_domain_name(domainName=domain_name)
    except Exception:  # noqa
        metrics.send("get_apigateway_domain_name_error", "counter", 1)
        capture_exception()
        raise
