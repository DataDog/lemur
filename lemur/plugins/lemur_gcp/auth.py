import hvac
import os

from google.oauth2 import service_account
from google.oauth2.credentials import Credentials


def _get_gcp_credentials_from_vault_mount_point(mount_point):
    service_token = (
        hvac.Client(os.environ["VAULT_ADDR"])
        .secrets.gcp.generate_oauth2_access_token(roleset="", mount_point=mount_point)[
            "data"
        ]["token"]
        .rstrip(".")
    )

    return Credentials(service_token)


def get_gcp_credentials(plugin, options):
    if plugin.get_option("authenticationMethod", options) == "vault":
        # make a request to vault for GCP token
        return get_gcp_credentials_from_vault(plugin, options)
    elif plugin.get_option("authenticationMethod", options) == "serviceAccountToken":
        if plugin.get_option("serviceAccountTokenPath", options) is not None:
            return service_account.Credentials.from_service_account_file(
                plugin.get_option("serviceAccountTokenPath", options)
            )
    raise Exception("No supported way to authenticate with GCP")


def get_gcp_credentials_from_vault(plugin, options):
    return _get_gcp_credentials_from_vault_mount_point(
        plugin.get_option("vaultMountPoint", options)
    )


def get_gcp_credentials_from_options(options):
    authentication_method = options.get("authenticationMethod")
    if authentication_method == "vault":
        return _get_gcp_credentials_from_vault_mount_point(options["vaultMountPoint"])
    if authentication_method == "serviceAccountToken":
        return service_account.Credentials.from_service_account_file(
            options["serviceAccountTokenPath"]
        )
    raise Exception("No supported way to authenticate with GCP")
