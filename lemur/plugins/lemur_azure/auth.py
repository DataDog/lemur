from azure.core.credentials import AccessToken, TokenCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import ClientSecretCredential, CredentialUnavailableError
from flask import current_app

import hvac
import os


class VaultTokenCredential(TokenCredential):
    def __init__(self, audience, client, mount_point, role_name):
        if not audience:
            self.audience="https://management.azure.com/.default"
        else:
            self.audience = audience
        self.client = client
        self.mount_point = mount_point
        self.role_name = role_name

    def get_token(self, *scopes, claims=None, tenant_id=None, **kwargs):
        data = self.client.read(
            path="{mount_point}/token/{role_name}?resource={audience}".format(
                audience=self.audience, mount_point=self.mount_point, role_name=self.role_name
            )
        )["data"]
        return AccessToken(
            token=data["access_token"],
            expires_on=data["expires_on"],
        )


def get_azure_credential(audience, plugin, options):
    """
    Fetches a credential used for authenticating with the Azure API.
    A new credential will be created if one does not already exist.
    If a credential already exists and is valid, then it will be re-used.
    When an existing credential is determined to be invalid, it will be replaced with a new one.

    :param plugin: source or destination plugin
    :param options: options set for the plugin
    :return: an Azure credential
    """
    tenant = plugin.get_option("azureTenant", options)
    auth_method = plugin.get_option("authenticationMethod", options)

    if auth_method == "hashicorpVault":
        mount_point = plugin.get_option("hashicorpVaultMountPoint", options)
        role_name = plugin.get_option("hashicorpVaultRoleName", options)
        client = hvac.Client(url=os.environ["VAULT_ADDR"])

        plugin.credential = VaultTokenCredential(audience, client, mount_point, role_name)
        return plugin.credential
    elif auth_method == "azureApp":
        app_id = plugin.get_option("azureAppID", options)
        password = plugin.get_option("azurePassword", options)

        plugin.credential = ClientSecretCredential(
            tenant_id=tenant,
            client_id=app_id,
            client_secret=password,
        )
        return plugin.credential

    raise Exception("No supported way to authenticate with Azure")
