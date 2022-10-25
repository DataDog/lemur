from flask import current_app

import hvac
import os
import requests
import json

from retrying import retry


def get_azure_credentials(plugin, options):
    tenant = plugin.get_option("azureTenant", options)
    auth_method = plugin.get_option("authenticationMethod", options)

    if auth_method == "hashicorpVault":
        mount_point = plugin.get_option("hashicorpVaultMountPoint", options)
        role_name = plugin.get_option("hashicorpVaultRoleName", options)
        client_id, client_secret = get_oauth_credentials_from_hashicorp_vault(mount_point, role_name)

        # It may take up-to 10 minutes for the generated OAuth credentials to become usable due
        # to AD replication delay. To account for this, the call to get_access_token is continuously
        # re-tried until it succeeds or 10 minutes elapse.
        access_token = get_access_token(plugin, tenant, client_id, client_secret)
    elif auth_method == "azureApp":
        app_id = plugin.get_option("azureAppID", options)
        password = plugin.get_option("azurePassword", options)
        access_token = get_access_token(plugin, tenant, app_id, password)
    else:
        raise Exception("No supported way to authenticate with Azure")

    return access_token


def get_oauth_credentials_from_hashicorp_vault(mount_point, role_name):
    """
    Retrieves OAuth credentials from Hashicorp Vault's Azure secrets engine.

    :param mount_point: Path the Azure secrets engine is mounted on
    :param role_name: Name of the role to fetch credentials for
    :returns:
        - client_id - OAuth client ID
        - client_secret - OAuth client secret
    """
    client = hvac.Client(url=os.environ["VAULT_ADDR"])
    creds = client.secrets.azure.generate_credentials(
        mount_point=mount_point,
        name=role_name,
    )
    return creds["client_id"], creds["client_secret"]


@retry(wait_fixed=1000, stop_max_delay=600000)
def get_access_token(plugin, tenant, client_id, client_secret):
    """
    Gets the access token for the client_id and the client_secret and returns it

    Improvement option: we can try to save it and renew it only when necessary

    :param tenant: Tenant used
    :param client_id: Client ID to use for fetching an access token
    :param client_secret: Client Secret to use for fetching an access token
    :return: Access token to post to the keyvault
    """
    # prepare the call for the access_token
    auth_url = f"https://login.microsoftonline.com/{tenant}/oauth2/token"
    post_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': 'https://vault.azure.net'
    }
    try:
        response = plugin.session.post(auth_url, data=post_data)
    except requests.exceptions.RequestException as e:
        current_app.logger.exception(f"AZURE: Error for POST {e}")

    access_token = json.loads(response.content)["access_token"]
    return access_token
