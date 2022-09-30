import hvac
import os

from google.oauth2 import service_account
from google.oauth2.credentials import Credentials


def get_gcp_credentials(self, options):
    if self.get_option('authenticationMethod', options) == "vault":
        # make a request to vault for GCP token
        return get_gcp_credentials_from_vault(self, options)
    elif self.get_option('authenticationMethod', options) == "serviceAccountToken":
        if self.get_option('serviceAccountTokenPath', options) is not None:
            return service_account.Credentials.from_service_account_file(
                self.get_option('serviceAccountTokenPath', options)
            )
    print('method=',self.get_option('authenticationMethod'))
    raise Exception("No supported way to authenticate with GCP")


def get_gcp_credentials_from_vault(self, options):
    service_token = hvac.Client(os.environ['VAULT_ADDR']) \
        .secrets.gcp \
        .generate_oauth2_access_token(
        roleset="",
        mount_point=f"{self.get_option('vaultMountPoint', options)}"
    )["data"]["token"].rstrip(".")

    credentials = Credentials(service_token)

    return credentials
