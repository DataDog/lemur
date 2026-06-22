"""
Root conftest.py — pre-stubs the Lemur/Flask application stack so that
lemur_digicert_dcv tests (which depend only on stdlib) can run without
installing the full application dependencies.

This stub is a no-op when Flask and the full stack are already installed;
it only fills gaps when they are absent.
"""
import sys
import types
from pathlib import Path

_REPO = str(Path(__file__).parent)


def _stub(name, **attrs):
    """Register a stub module only if the real one isn't available."""
    if name in sys.modules:
        return sys.modules[name]
    m = types.ModuleType(name)
    m.__path__ = []  # mark as package
    for k, v in attrs.items():
        setattr(m, k, v)
    sys.modules[name] = m
    return m


def _try_import(name):
    """Return True if the module can be imported for real."""
    try:
        __import__(name)
        return True
    except ImportError:
        return False


# Only install stubs if Flask is not available (avoids interfering with
# the full test suite when run in an environment that has all deps).
if not _try_import("flask"):
    _stub("flask", g=object(), request=None, current_app=None,
          jsonify=lambda *a, **k: None)
    _stub("werkzeug")
    _stub("werkzeug.exceptions", HTTPException=Exception)
    _stub("flask_principal",
          identity_changed=lambda *a, **k: None,
          Identity=type("Identity", (object,), {}))
    _stub("OpenSSL")
    _stub("OpenSSL.crypto")

    _stub("lemur.factory")
    _stub("lemur.extensions", metrics=object())
    _stub("lemur.common")
    _stub("lemur.common.utils", check_validation=lambda *a, **k: None)
    _stub("lemur.__about__",
          __author__="", __copyright__="", __email__="",
          __license__="", __summary__="", __title__="",
          __uri__="", __version__="")

    for _n in (
        "lemur.users.views", "lemur.roles.views", "lemur.auth.views",
        "lemur.domains.views", "lemur.destinations.views",
        "lemur.authorities.views", "lemur.certificates.views",
        "lemur.defaults.views", "lemur.plugins.views",
        "lemur.notifications.views", "lemur.sources.views",
        "lemur.endpoints.views", "lemur.logs.views", "lemur.api_keys.views",
        "lemur.pending_certificates.views", "lemur.dns_providers.views",
    ):
        _stub(_n, mod=None)

    # lemur.plugins — stub with real __path__ for sub-package discovery, but
    # we must prevent lemur/plugins/__init__.py from executing.
    # Strategy: register the package stub BEFORE Python can find the real __init__.
    _stub("lemur.common.managers", InstanceManager=object)

    for _n in (
        "lemur.plugins.base",
        "lemur.plugins.base.manager",
        "lemur.plugins.bases",
        "lemur.plugins.bases.notification",
        "lemur.plugins.bases.destination",
        "lemur.plugins.bases.source",
        "lemur.plugins.bases.issuer",
        "lemur.plugins.bases.export",
        "lemur.plugins.bases.dns_provider",
        "lemur.plugins.bases.metric",
        "lemur.plugins.service",
    ):
        _stub(_n,
              PluginManager=object,
              NotificationPlugin=object,
              ExpirationNotificationPlugin=object,
              DestinationPlugin=object,
              SourcePlugin=object,
              IssuerPlugin=object,
              ExportPlugin=object,
              DNSProviderPlugin=object,
              MetricPlugin=object,
              InstanceManager=object)

    # Stub the plugins package itself so its __init__.py (`from .base import *`)
    # never runs.  We give it a real __path__ so Python can still discover
    # sub-packages (lemur_digicert_dcv etc.) by directory walk.
    plugins_pkg = types.ModuleType("lemur.plugins")
    plugins_pkg.__path__ = [_REPO + "/lemur/plugins"]
    plugins_pkg.__package__ = "lemur.plugins"
    plugins_pkg.__file__ = _REPO + "/lemur/plugins/__init__.py"
    # Mark as already initialized — Python will not re-run __init__.py
    # as long as the module is in sys.modules before the real import occurs.
    sys.modules["lemur.plugins"] = plugins_pkg
