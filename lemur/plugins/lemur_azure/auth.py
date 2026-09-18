from azure.core.credentials import AccessToken, TokenCredential
from azure.identity import ClientSecretCredential

import hvac
import os


class VaultTokenCredential(TokenCredential):
    def __init__(self, audience, client, mount_point, role_name):
        if not audience:
            self.audience = "https://management.azure.com/"
        else:
            self.audience = audience
        self.client = client
        self.mount_point = mount_point
        self.role_name = role_name

    def __eq__(self, other):
        return (
            self.audience == other.audience
            and self.client == other.client
            and self.mount_point == other.mount_point
            and self.role_name == other.role_name
        )

    def get_token(self, *scopes, claims=None, tenant_id=None, **kwargs):
        payload = {"resource": self.audience}
        data = self.client.adapter.get(
            "/v1/{mount_point}/token/{role_name}".format(
                mount_point=self.mount_point,
                role_name=self.role_name,
            ),
            params=payload,
        )["data"]
        return AccessToken(
            token=data["access_token"],
            expires_on=data["expires_on"],
        )


def get_azure_credential_from_options(audience, options):
    tenant = options.get("azureTenant")
    auth_method = options.get("authenticationMethod")

    if auth_method == "hashicorpVault":
        client = hvac.Client(url=os.environ["VAULT_ADDR"])
        return VaultTokenCredential(
            audience=audience,
            client=client,
            mount_point=options.get("hashicorpVaultMountPoint"),
            role_name=options.get("hashicorpVaultRoleName"),
        )
    if auth_method == "azureApp":
        return ClientSecretCredential(
            tenant_id=tenant,
            client_id=options.get("azureAppID"),
            client_secret=options.get("azurePassword"),
        )

    raise Exception("No supported way to authenticate with Azure")


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
    option_values = {
        name: plugin.get_option(name, options)
        for name in (
            "azureTenant",
            "authenticationMethod",
            "azureAppID",
            "azurePassword",
            "hashicorpVaultMountPoint",
            "hashicorpVaultRoleName",
        )
    }
    plugin.credential = get_azure_credential_from_options(audience, option_values)
    return plugin.credential
