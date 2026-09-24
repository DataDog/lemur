from unittest.mock import patch

from lemur.plugins.lemur_gcp.auth import get_gcp_credentials_from_options


@patch("lemur.plugins.lemur_gcp.auth._get_gcp_credentials_from_vault_mount_point")
def test_get_gcp_credentials_from_options_uses_vault(mock_get_credentials):
    options = {
        "authenticationMethod": "vault",
        "vaultMountPoint": "cloud-iam/gcp/project/impersonated-account/lemur",
    }

    assert (
        get_gcp_credentials_from_options(options) == mock_get_credentials.return_value
    )
    mock_get_credentials.assert_called_once_with(options["vaultMountPoint"])


@patch("lemur.plugins.lemur_gcp.auth.service_account.Credentials")
def test_get_gcp_credentials_from_options_uses_service_account(mock_credentials):
    options = {
        "authenticationMethod": "serviceAccountToken",
        "serviceAccountTokenPath": "/var/run/secrets/gcp.json",
    }

    assert get_gcp_credentials_from_options(options) == (
        mock_credentials.from_service_account_file.return_value
    )
    mock_credentials.from_service_account_file.assert_called_once_with(
        options["serviceAccountTokenPath"]
    )
