import copy
import json
from types import SimpleNamespace

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
        {"name": "password", "type": "str", "value": "secret-sentinel"},
        {
            "name": "export",
            "type": "export-plugin",
            "value": {
                "plugin_options": [{"name": "password", "value": "nested-secret"}]
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
    with Flask(__name__).test_request_context():
        g.identity = Identity(1)
        g.identity.provides.update(RoleNeed(role) for role in roles)
        result, errors = schema_class(many=many).dump([record] if many else record)
        assert not errors
        output = result[0] if many else result
        can_write = bool(set(roles) & {"operator", "admin"})
        assert bool(output["options"]) == can_write
        assert bool(output["plugin"]["pluginOptions"]) == can_write

        nested, errors = CertificateOutputSchema(only=(relationship,)).dump(
            {relationship: [record]}
        )
        assert not errors
        assert bool(nested[relationship][0]["options"]) == can_write
        assert bool(nested[relationship][0]["plugin"]["pluginOptions"]) == can_write
        if not can_write:
            for payload in (result, nested):
                assert "secret-sentinel" not in json.dumps(payload)
                assert "nested-secret" not in json.dumps(payload)
            assert options == original
        else:
            for payload in (result, nested):
                assert "secret-sentinel" in json.dumps(payload)
                assert "nested-secret" in json.dumps(payload)
