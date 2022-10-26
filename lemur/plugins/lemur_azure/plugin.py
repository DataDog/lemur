"""
.. module: lemur.plugins.lemur_azure.plugin
    :platform: Unix
    :copyright: (c) 2019
    :license: Apache, see LICENCE for more details.

    Plugin for uploading certificates and private key as secret to azure key-vault
     that can be pulled down by end point nodes.

.. moduleauthor:: sirferl
"""
from flask import current_app
from azure.keyvault.certificates import CertificateClient, CertificatePolicy
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.subscription import SubscriptionClient

from lemur.common.defaults import common_name, issuer, bitstrength
from lemur.common.utils import parse_certificate, parse_private_key, check_validation
from lemur.plugins.bases import DestinationPlugin, SourcePlugin
from lemur.plugins.lemur_azure.auth import get_azure_credential

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import requests
import json
import sys


def handle_response(my_response):
    """
    Helper function for parsing responses from the Entrust API.
    :param my_response:
    :return: :raise Exception:
    """
    msg = {
        200: "The request was successful.",
        400: "Keyvault Error"
    }

    try:
        data = json.loads(my_response.content)
    except ValueError:
        # catch an empty jason object here
        data = {'response': 'No detailed message'}
    status_code = my_response.status_code
    if status_code > 399:
        raise Exception(f"AZURE error: {msg.get(status_code, status_code)}\n{data}")

    log_data = {
        "function": f"{__name__}.{sys._getframe().f_code.co_name}",
        "message": "Response",
        "status": status_code,
        "response": data
    }
    current_app.logger.info(log_data)
    if data == {'response': 'No detailed message'}:
        # status if no data
        return status_code
    else:
        #  return data from the response
        return data


class AzureDestinationPlugin(DestinationPlugin):
    """Azure Keyvault Destination plugin for Lemur"""

    title = "Azure"
    slug = "azure-keyvault-destination"
    description = "Allow the uploading of certificates to Azure key vault"

    author = "Sirferl"
    author_url = "https://github.com/sirferl/lemur"

    options = [
        {
            "name": "azureKeyVaultUrl",
            "type": "str",
            "required": True,
            "validation": check_validation("^https?://[a-zA-Z0-9.:-]+$"),
            "helpMessage": "Valid URL to Azure key vault instance",
        },
        {
            "name": "authenticationMethod",
            "type": "select",
            "value": "azureApp",
            "required": True,
            "available": ["hashicorpVault", "azureApp"],
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "azureTenant",
            "type": "str",
            "required": True,
            "validation": check_validation("^([a-zA-Z0-9-?])+$"),
            "helpMessage": "Tenant for the Azure Key Vault.",
        },
        {
            "name": "azureAppID",
            "type": "str",
            "required": False,
            "validation": check_validation("^([a-zA-Z0-9-?]?)+$"),
            "helpMessage": "AppID for the Azure Key Vault. Required if authentication method is 'azureApp'.",
        },
        {
            "name": "azurePassword",
            "type": "str",
            "required": False,
            "validation": check_validation("([0-9a-zA-Z.:_-~]?)+"),
            "helpMessage": "Tenant password for the Azure Key Vault. Required if authentication method is 'azureApp'.",
        },
        {
            "name": "hashicorpVaultMountPoint",
            "type": "str",
            "required": False,
            "helpMessage": "Path the Azure secrets engine was mounted on. Required if authentication "
                           "method is 'hashicorpVault'.",
        },
        {
            "name": "hashicorpVaultRoleName",
            "type": "str",
            "required": False,
            "helpMessage": "Name of the role to fetch credentials for. Required if authentication "
                           "method is 'hashicorpVault'.",
        },
    ]

    def __init__(self, *args, **kwargs):
        self.session = requests.Session()
        super(AzureDestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):
        """
        Upload certificate and private key

        :param private_key:
        :param cert_chain:
        :return:
        """

        # we use the common name to identify the certificate
        # Azure does not allow "." in the certificate name we replace them with "-"
        cert = parse_certificate(body)
        ca_certs = parse_certificate(cert_chain)
        certificate_name = f"{common_name(cert).replace('.', '-')}-{issuer(cert)}"

        certificate_client = CertificateClient(
            credential=get_azure_credential(self, options),
            vault_url=self.get_option("azureKeyVaultUrl", options),
        )
        certificate_client.import_certificate(
            certificate_name=certificate_name,
            certificate_bytes=pkcs12.serialize_key_and_certificates(
                name=certificate_name.encode(),
                key=parse_private_key(private_key),
                cert=cert,
                cas=[ca_certs],
                encryption_algorithm=serialization.NoEncryption()
            ),
            enabled=True,
            policy=CertificatePolicy(
                exportable=True,
                key_type="RSA",
                key_size=bitstrength(cert),
                reuse_key=True,
                content_type="application/x-pkcs12",
            ),
            tags={"lemur.managed": "true"},
        )


class AzureSourcePlugin(SourcePlugin):
    title = "Azure"
    slug = "azure-source"
    description = "Discovers all certificates and Application Gateways within an Azure tenant"

    author = "Bob Shannon"
    author_url = "https://github.com/datadog/lemur"

    options = [
        {
            "name": "authenticationMethod",
            "type": "select",
            "value": "azureApp",
            "required": True,
            "available": ["hashicorpVault", "azureApp"],
            "helpMessage": "Authentication method to use",
        },
        {
            "name": "azureTenant",
            "type": "str",
            "required": True,
            "validation": check_validation("^([a-zA-Z0-9-?])+$"),
            "helpMessage": "Tenant to discover Azure resources from.",
        },
        {
            "name": "azureAppID",
            "type": "str",
            "required": False,
            "validation": check_validation("^([a-zA-Z0-9-?]?)+$"),
            "helpMessage": "AppID for the Azure Key Vault. Required if authentication method is 'azureApp'.",
        },
        {
            "name": "azurePassword",
            "type": "str",
            "required": False,
            "validation": check_validation("([0-9a-zA-Z.:_-~]?)+"),
            "helpMessage": "Tenant password for the Azure Key Vault. Required if authentication method is 'azureApp'.",
        },
        {
            "name": "hashicorpVaultMountPoint",
            "type": "str",
            "required": False,
            "helpMessage": "Path the Azure secrets engine was mounted on. Required if authentication "
                           "method is 'hashicorpVault'.",
        },
        {
            "name": "hashicorpVaultRoleName",
            "type": "str",
            "required": False,
            "helpMessage": "Name of the role to fetch credentials for. Required if authentication "
                           "method is 'hashicorpVault'.",
        },
    ]

    def __init__(self, *args, **kwargs):
        super(AzureSourcePlugin, self).__init__(*args, **kwargs)

    def get_certificates(self, options, **kwargs):
        # TODO(EDGE-1725) Support discovering endpoints and certificates in Azure source plugin
        pass

    def get_endpoints(self, options, **kwargs):
        credential = get_azure_credential(self, options)

        endpoints = []
        for subscription in SubscriptionClient(credential=credential).subscriptions.list():
            network_client = NetworkManagementClient(credential=credential, subscription_id=subscription.subscription_id)
            for appgw in network_client.application_gateways.list_all():
                ep = dict(
                    name=appgw.name,
                    type="applicationgateway",
                    port=appgw.frontend_ports[0].port,
                    sni_certificates=[],
                )
                certs = []
                for crt in appgw.ssl_certificates:
                    certs.append(
                        dict(
                            name=crt.name,
                            path="",
                            registry_type="keyvault",
                        )
                    )
                if certs:
                    ep["primary_certificate"] = certs[0]
                    ep["sni_certificates"] = certs[1:]
                endpoints.append(ep)

        return endpoints

    @staticmethod
    def update_endpoint(endpoint, certificate):
        current_app.logger.info({
            "message": "No explicit action required to rotate endpoint, Azure will automatically perform the rotation "
                       "after the new certificate is uploaded to its Key Vault",
            "endpoint": endpoint.name,
            "certificate": certificate.name,

        })
        return

    @staticmethod
    def replace_sni_certificate(endpoint, old_cert, new_cert):
        current_app.logger.info({
            "message": "No explicit action required to rotate endpoint, Azure will automatically perform the rotation "
                       "after the new certificate is uploaded to its Key Vault",
            "endpoint": endpoint.name,
            "old_certificate": old_cert.name,
            "new_certificate": new_cert.name,
        })
