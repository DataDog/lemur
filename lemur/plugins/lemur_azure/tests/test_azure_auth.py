import os
import unittest
from unittest.mock import patch
from azure.core.credentials import AccessToken
from lemur.plugins.lemur_azure.auth import VaultTokenCredential
from flask import Flask


class TestAzureAuth(unittest.TestCase):
    def setUp(self):
        _app = Flask("lemur_test_azure_auth")
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    @patch.dict(os.environ, {"VAULT_ADDR": "https://fakevaultinstance:8200"})
    @patch("hvac.Client")
    def test_vault_token_credential(self, hvac_client_mock):
        client = hvac_client_mock()
        client.read.return_value = {
            "request_id": "f7dcd09c-dde9-fa0d-e98e-e4f238dfe66e",
            "lease_id": "",
            "renewable": False,
            "lease_duration": 0,
            "data": {
                "access_token": "faketoken123",
                "expires_in": 14399,
                "expires_on": 1717182214,
                "not_before": 1717167514,
                "refresh_token": "",
                "resource": "https://management.azure.com/",
                "token_type": "Bearer",
            },
            "wrap_info": None,
            "warnings": None,
            "auth": None,
        }
        access_token = VaultTokenCredential(
            client=client,
            mount_point="/azure",
            role_name="mockedRole",
        ).get_token()
        client.read.assert_called_with(path="/azure/token/mockedRole")
        assert access_token == AccessToken(
            token="faketoken123",
            expires_on=1717182214,
        )
