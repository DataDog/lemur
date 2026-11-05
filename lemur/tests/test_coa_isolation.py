import pytest
from flask import Flask
from werkzeug.exceptions import BadRequest

from lemur.common.coa_isolation import SANDBOX_COA_PREFIX, validate_coa_paths


@pytest.mark.parametrize("plugin", ["cert-orchestration-adapter-dest", "coa-source"])
@pytest.mark.parametrize(
    "path",
    [
        None,
        "",
        "/kv/data/managed-certificates/k8s/ingress-haproxy",
        "/kv/data/k8s/cert-orchestration/isp/public-certificates",
        SANDBOX_COA_PREFIX,
        SANDBOX_COA_PREFIX + "../ingress-haproxy",
        SANDBOX_COA_PREFIX + "dest-49/../../other",
        SANDBOX_COA_PREFIX + "dest-49,",
        SANDBOX_COA_PREFIX + "dest-49,/other",
        SANDBOX_COA_PREFIX + "dest-49//other",
        SANDBOX_COA_PREFIX + "dest-49%2f..",
        SANDBOX_COA_PREFIX + "dest-49\\other",
        SANDBOX_COA_PREFIX + "dest-49\n",
        SANDBOX_COA_PREFIX.rstrip("/") + "-other/dest-49",
        123,
    ],
)
def test_rejects_unsafe_paths(plugin, path):
    app = Flask(__name__)
    app.config["SANDBOX_COA_PATH_ISOLATION"] = True
    with app.app_context(), pytest.raises(BadRequest, match="Sandbox COA paths"):
        validate_coa_paths(plugin, [{"name": "paths", "value": path}])


@pytest.mark.parametrize(
    "options",
    [
        None,
        [],
        [
            {"name": "paths", "value": SANDBOX_COA_PREFIX + "dest-49"},
            {"name": "paths", "value": "/other"},
        ],
    ],
)
def test_rejects_missing_or_duplicate_options(options):
    app = Flask(__name__)
    app.config["SANDBOX_COA_PATH_ISOLATION"] = True
    with app.app_context(), pytest.raises(BadRequest):
        validate_coa_paths("coa-source", options)


@pytest.mark.parametrize("plugin", ["cert-orchestration-adapter-dest", "coa-source"])
def test_allows_isolated_paths_without_modifying_options(plugin):
    app = Flask(__name__)
    app.config["SANDBOX_COA_PATH_ISOLATION"] = True
    value = SANDBOX_COA_PREFIX + "dest-49," + SANDBOX_COA_PREFIX + "dest-60"
    options = [{"name": "paths", "value": value}]
    with app.app_context():
        validate_coa_paths(plugin, options)
    assert options == [{"name": "paths", "value": value}]


def test_disabled_by_default_and_other_plugins_unaffected():
    app = Flask(__name__)
    with app.app_context():
        validate_coa_paths("coa-source", [])
        app.config["SANDBOX_COA_PATH_ISOLATION"] = True
        validate_coa_paths("aws-destination", [])


def test_api_returns_validation_error():
    from lemur.common.schema import validate_schema

    app = Flask(__name__)
    app.config["SANDBOX_COA_PATH_ISOLATION"] = True

    @validate_schema(None, None)
    def save():
        validate_coa_paths("coa-source", [])

    with app.test_request_context():
        body, status = save()
    assert status == 400
    assert "Sandbox COA paths" in body["message"]


@pytest.mark.parametrize("kind", ["sources", "destinations"])
@pytest.mark.parametrize("operation", ["create", "update"])
def test_configuration_rejected_before_database_access(monkeypatch, kind, operation):
    from importlib import import_module

    service = import_module("lemur." + kind + ".service")
    app = Flask(__name__)
    app.config["SANDBOX_COA_PATH_ISOLATION"] = True
    plugin = "coa-source" if kind == "sources" else "cert-orchestration-adapter-dest"

    def unexpected(*args, **kwargs):
        pytest.fail("Invalid configuration reached the database")

    monkeypatch.setattr(service, "get", unexpected)
    monkeypatch.setattr(service.database, "create", unexpected)
    with app.app_context(), pytest.raises(BadRequest):
        args = ("test", plugin, [], "test")
        if operation == "update":
            args = (1,) + args
        getattr(service, operation)(*args)


@pytest.mark.parametrize("operation", ["sync_certificates", "sync_endpoints", "upload"])
def test_runtime_guard_blocks_existing_records(monkeypatch, operation):
    from types import SimpleNamespace
    from lemur.sources import service
    from lemur.certificates import models

    app = Flask(__name__)
    app.config["SANDBOX_COA_PATH_ISOLATION"] = True

    def unexpected(*args, **kwargs):
        pytest.fail("Invalid configuration reached the plugin")

    monkeypatch.setattr(service.plugins, "get", unexpected)
    record = SimpleNamespace(plugin_name="coa-source", options=[])
    with app.app_context(), pytest.raises(BadRequest):
        if operation == "upload":
            record.plugin_name = "cert-orchestration-adapter-dest"
            models.update_destinations(None, record, None)
        elif operation == "sync_certificates":
            service.sync_certificates(record, None)
        else:
            service.sync_endpoints(record)
