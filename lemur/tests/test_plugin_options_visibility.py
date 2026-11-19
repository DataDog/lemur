import copy
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from flask import Flask, g
from flask_principal import Identity, RoleNeed

from lemur.certificates.schemas import CertificateOutputSchema
from lemur.destinations.schemas import DestinationOutputSchema
from lemur.sources.schemas import SourceOutputSchema


@pytest.mark.parametrize("roles", [[], ["reader"], ["operator"], ["admin"]])
@pytest.mark.parametrize("many", [False, True])
@pytest.mark.parametrize(
    "schema_class,relationship",
    [(SourceOutputSchema, "sources"), (DestinationOutputSchema, "destinations")],
)
def test_plugin_options_visibility(roles, many, schema_class, relationship):
    options = [
        {"name": "host", "type": "str", "value": "example.com"},
        {"name": "privateKeyPath", "type": "str", "value": "/keys/test.pem"},
        {
            "name": "password",
            "type": "str",
            "value": "secret-sentinel",
            "default": "default-secret",
            "sensitive": False,
        },
        {
            "name": "export",
            "type": "export-plugin",
            "value": {
                "slug": "test-export",
                "plugin_options": [{"name": "passphrase", "value": "nested-secret"}],
                "pluginOptions": [{"name": "passphrase", "value": "nested-secret"}],
            },
        },
    ]
    original = copy.deepcopy(options)
    record = SimpleNamespace(
        id=1,
        label="test",
        description="test configuration",
        active=True,
        options=options,
        plugin=SimpleNamespace(slug="test-plugin", options=options),
    )
    definitions = {
        "test-plugin": SimpleNamespace(
            options=[
                {"name": "host"},
                {"name": "privateKeyPath"},
                {"name": "password", "sensitive": True},
                {"name": "export", "type": "export-plugin"},
            ]
        ),
        "test-export": SimpleNamespace(
            options=[{"name": "passphrase", "sensitive": True}]
        ),
    }
    with Flask(__name__).test_request_context(), patch(
        "lemur.plugins.utils.plugins.get", side_effect=definitions.__getitem__
    ):
        g.identity = Identity(1)
        g.identity.provides.update(RoleNeed(role) for role in roles)
        result, errors = schema_class(many=many).dump([record] if many else record)
        assert not errors
        output = result[0] if many else result
        can_write = bool(set(roles) & {"operator", "admin"})
        assert output["options"][0] == original[0]
        assert output["options"][1] == original[1]
        assert output["plugin"]["pluginOptions"] == output["options"]
        expected = "secret-sentinel" if can_write else "[REDACTED]"
        assert output["options"][2]["value"] == expected

        nested, errors = CertificateOutputSchema(only=(relationship,)).dump(
            {relationship: [record]}
        )
        assert not errors
        assert nested[relationship][0]["options"] == output["options"]
        assert nested[relationship][0]["plugin"]["pluginOptions"] == output["options"]
        if not can_write:
            for payload in (result, nested):
                assert "secret-sentinel" not in json.dumps(payload)
                assert "nested-secret" not in json.dumps(payload)
                assert "default-secret" not in json.dumps(payload)
            assert options == original
        else:
            for payload in (result, nested):
                assert "secret-sentinel" in json.dumps(payload)
                assert "nested-secret" in json.dumps(payload)


@pytest.mark.parametrize(
    "module_name,class_name,secret_names",
    [
        ("lemur_azure", "AzureDestinationPlugin", {"azurePassword"}),
        ("lemur_azure", "AzureSourcePlugin", {"azurePassword"}),
        ("lemur_sftp", "SFTPDestinationPlugin", {"password", "privateKeyPass"}),
        ("lemur_kubernetes", "KubernetesDestinationPlugin", {"kubernetesAuthToken"}),
        ("lemur_jks", "JavaTruststoreExportPlugin", {"passphrase"}),
        ("lemur_jks", "JavaKeystoreExportPlugin", {"passphrase"}),
        ("lemur_openssl", "OpenSSLExportPlugin", {"passphrase"}),
    ],
)
def test_secret_option_definitions(module_name, class_name, secret_names):
    from importlib import import_module
    from lemur.plugins.utils import redact_plugin_options

    plugin = getattr(import_module("lemur.plugins." + module_name + ".plugin"), class_name)
    marked = {option["name"] for option in plugin.options if option.get("sensitive")}
    assert marked == secret_names
    options = [
        {"name": name, "value": "secret-sentinel", "sensitive": False}
        for name in secret_names
    ]
    with patch("lemur.plugins.utils.plugins.get", return_value=plugin):
        result = redact_plugin_options(plugin.slug, options)
    assert all(option["value"] == "[REDACTED]" for option in result)
    assert all(option["value"] == "secret-sentinel" for option in options)
