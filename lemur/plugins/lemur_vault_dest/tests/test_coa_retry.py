"""
Unit tests for the gRPC retry helpers in lemur_vault_dest/plugin.py:
  - _is_retriable_grpc_error
  - _upload_with_retry

Strategy: we load plugin.py directly via importlib (bypassing the lemur package
init chain) after pre-populating sys.modules with lightweight stubs for every
import that plugin.py touches.  This means the test is self-contained and does
not require a Postgres database, LDAP server, or the full Lemur application
stack.
"""

import importlib.util
import os
import sys
import types
from unittest.mock import MagicMock, patch

import grpc
import pytest


# ---------------------------------------------------------------------------
# Pre-populate sys.modules with stubs for everything plugin.py imports
# ---------------------------------------------------------------------------

def _stub(name, **attrs):
    """Register a stub module with optional attributes."""
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod
    return mod


def _ensure_parents(dotted):
    """Make sure every parent package of *dotted* is also a stub."""
    parts = dotted.split(".")
    for i in range(1, len(parts) + 1):
        fqn = ".".join(parts[:i])
        if fqn not in sys.modules:
            _stub(fqn)


_STUB_SPECS = {
    # lemur internals that plugin.py imports at module level
    "lemur.common.defaults": dict(
        common_name=MagicMock(),
        country=MagicMock(),
        state=MagicMock(),
        location=MagicMock(),
        organizational_unit=MagicMock(),
        organization=MagicMock(),
    ),
    "lemur.common.utils": dict(
        parse_certificate=MagicMock(),
        check_validation=MagicMock(return_value=True),
    ),
    "lemur.plugins.bases": dict(
        DestinationPlugin=type("DestinationPlugin", (), {
            "__init__": lambda self, *a, **kw: None,
            "get_option": lambda self, name, opts: None,
        }),
        SourcePlugin=type("SourcePlugin", (), {
            "__init__": lambda self, *a, **kw: None,
            "get_option": lambda self, name, opts: None,
        }),
    ),
    # third-party / optional deps
    "hvac": dict(Client=MagicMock()),
    "validators": {},
    "validators.url": dict(url=lambda u: True),
    "cryptography": {},
    "cryptography.x509": dict(
        load_pem_x509_certificate=MagicMock(),
        DNSName=MagicMock(),
        oid=MagicMock(),
        extensions=types.SimpleNamespace(ExtensionNotFound=Exception),
    ),
    "cryptography.hazmat": {},
    "cryptography.hazmat.backends": dict(default_backend=MagicMock()),
    # Flask — we only need the current_app proxy; tests will patch it
    "flask": dict(current_app=MagicMock()),
    # COA adapter — plugin.py imports grpc INSIDE the try/except block that
    # also imports these COA symbols.  If any import in the block fails the
    # except handler sets grpc=None, disabling all retry logic.  We therefore
    # provide real-looking stubs for every symbol the try block imports so the
    # try succeeds and grpc remains the real module.
    "cert_orchestration_adapter": {},
    "cert_orchestration_adapter.plugin": dict(
        create_coa_connection=MagicMock(),
        parse_ca_vendor=MagicMock(),
        parse_certificate=MagicMock(),
        common_name=MagicMock(),
        get_key_type_from_certificate=MagicMock(),
    ),
    "domains": {},
    "domains.cert_orchestration": {},
    "domains.cert_orchestration.libs": {},
    "domains.cert_orchestration.libs.pb": {},
    "domains.cert_orchestration.libs.pb.cert_orchestration_adapter": {},
    "domains.cert_orchestration.libs.pb.cert_orchestration_adapter.service_pb2": dict(
        CertificateUploadRequest=MagicMock(),
    ),
}

for _fqn, _attrs in _STUB_SPECS.items():
    _ensure_parents(_fqn)
    _stub(_fqn, **_attrs)

# Also ensure grpc is the real module (not stubbed)
assert "grpc" in sys.modules or importlib.util.find_spec("grpc") is not None


# ---------------------------------------------------------------------------
# Load plugin.py directly (without going through lemur's package __init__)
# ---------------------------------------------------------------------------

_PLUGIN_PATH = os.path.join(
    os.path.dirname(__file__),  # …/lemur_vault_dest/tests/
    "..",                       # …/lemur_vault_dest/
    "plugin.py",
)
_PLUGIN_PATH = os.path.abspath(_PLUGIN_PATH)

_spec = importlib.util.spec_from_file_location(
    "lemur_vault_dest_plugin_under_test", _PLUGIN_PATH
)
_plugin_mod = importlib.util.module_from_spec(_spec)
# Register in sys.modules so that patch() can look it up by name.
sys.modules[_spec.name] = _plugin_mod
_spec.loader.exec_module(_plugin_mod)

_is_retriable_grpc_error = _plugin_mod._is_retriable_grpc_error
_upload_with_retry = _plugin_mod._upload_with_retry

# Convenience references for patching inside the loaded module.
# patch() resolves "module_name.attr" via sys.modules, so the module must be
# registered (done above).  For nested attributes like time.sleep we patch
# the attribute on the `time` module object that the plugin holds.
_plugin_time = _plugin_mod.time   # the `time` module as imported by plugin.py


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeRpcError(grpc.RpcError):
    """Minimal grpc.RpcError subclass whose code() and details() are controllable.

    grpc.RpcError itself only inherits from Exception — it has no code() or
    details() methods.  Real gRPC errors inherit from both grpc.RpcError and
    grpc.Call (which adds those methods).  Using MagicMock(spec=grpc.RpcError)
    blocks .code() calls because that attribute isn't on grpc.RpcError.

    Subclassing grpc.RpcError directly (rather than using MagicMock) means
    isinstance(exc, grpc.RpcError) returns True and .code()/.details() work.
    """

    def __init__(self, code, detail):
        self._code = code
        self._detail = detail

    def code(self):
        return self._code

    def details(self):
        return self._detail


def make_rpc_error(code, detail):
    """Build a grpc.RpcError instance with the given status code and detail."""
    return _FakeRpcError(code, detail)


# ---------------------------------------------------------------------------
# _is_retriable_grpc_error tests
# ---------------------------------------------------------------------------

class TestIsRetriableGrpcError:

    def test_unavailable_no_healthy_upstream_returns_true(self):
        err = make_rpc_error(grpc.StatusCode.UNAVAILABLE, "no healthy upstream")
        assert _is_retriable_grpc_error(err) is True

    def test_unavailable_upstream_connect_error_returns_true(self):
        err = make_rpc_error(
            grpc.StatusCode.UNAVAILABLE,
            "upstream connect error or disconnect/reset before headers",
        )
        assert _is_retriable_grpc_error(err) is True

    def test_unavailable_connection_refused_returns_true(self):
        err = make_rpc_error(grpc.StatusCode.UNAVAILABLE, "connection refused")
        assert _is_retriable_grpc_error(err) is True

    def test_unavailable_failed_to_connect_returns_true(self):
        err = make_rpc_error(
            grpc.StatusCode.UNAVAILABLE, "failed to connect to all addresses"
        )
        assert _is_retriable_grpc_error(err) is True

    def test_unavailable_mixed_case_returns_true(self):
        """Detail matching is case-insensitive."""
        err = make_rpc_error(grpc.StatusCode.UNAVAILABLE, "No Healthy Upstream")
        assert _is_retriable_grpc_error(err) is True

    def test_unavailable_unrelated_detail_returns_false(self):
        err = make_rpc_error(grpc.StatusCode.UNAVAILABLE, "quota exceeded")
        assert _is_retriable_grpc_error(err) is False

    def test_unauthenticated_returns_false(self):
        err = make_rpc_error(grpc.StatusCode.UNAUTHENTICATED, "no healthy upstream")
        assert _is_retriable_grpc_error(err) is False

    def test_permission_denied_returns_false(self):
        err = make_rpc_error(grpc.StatusCode.PERMISSION_DENIED, "no healthy upstream")
        assert _is_retriable_grpc_error(err) is False

    def test_internal_returns_false(self):
        err = make_rpc_error(grpc.StatusCode.INTERNAL, "no healthy upstream")
        assert _is_retriable_grpc_error(err) is False

    def test_non_grpc_exception_returns_false(self):
        assert _is_retriable_grpc_error(ValueError("something went wrong")) is False

    def test_plain_exception_returns_false(self):
        assert _is_retriable_grpc_error(Exception("connection refused")) is False


# ---------------------------------------------------------------------------
# _upload_with_retry tests
# ---------------------------------------------------------------------------

# We patch current_app directly on the module object (not by name), because the
# plugin is loaded under a synthetic module name that may not be in sys.modules
# under every pytest import mode.  patch.object is always safe regardless of
# sys.modules state.

class TestUploadWithRetry:

    AUTH_TOKEN = ("authorization", "Bearer tok")

    def _monotonic_seq(self, n=50):
        """Return a list of n monotonically increasing float values starting at 0.0.

        The plugin calls time.monotonic() in multiple places:
          - Once at start to record `start` and compute `deadline`.
          - Twice per failure: once for `elapsed = monotonic() - start` and
            once for the deadline check `monotonic() >= deadline`.
          - Once on success after ≥1 retry: for the success log message.
        We always pass more values than needed so tests never hit StopIteration.
        """
        return [float(i) for i in range(n)]

    def test_success_on_first_attempt(self):
        """stub.Upload called exactly once; no sleep.

        First attempt succeeds (attempt==0), so the success log is not emitted
        and monotonic() is called only once (for `start`).
        """
        stub = MagicMock()
        stub.Upload.side_effect = [MagicMock()]
        request = MagicMock()

        with patch.object(_plugin_mod, "current_app"):
            with patch.object(_plugin_time, "sleep") as mock_sleep:
                with patch.object(_plugin_time, "monotonic", side_effect=self._monotonic_seq()):
                    _upload_with_retry(
                        stub, request, self.AUTH_TOKEN,
                        retry_timeout_seconds=10, initial_wait_seconds=1,
                    )

        stub.Upload.assert_called_once_with(request=request, metadata=[self.AUTH_TOKEN])
        mock_sleep.assert_not_called()

    def test_succeeds_after_two_unavailable_failures(self):
        """stub.Upload called 3 times when first two raise retriable UNAVAILABLE.

        monotonic() call pattern (deadline=9999):
          [0] start; [1] now (failure 1); [2] now (failure 2); [3] success log.
        """
        unavailable_err = make_rpc_error(grpc.StatusCode.UNAVAILABLE, "no healthy upstream")
        stub = MagicMock()
        stub.Upload.side_effect = [unavailable_err, unavailable_err, MagicMock()]
        request = MagicMock()

        with patch.object(_plugin_mod, "current_app"):
            with patch.object(_plugin_time, "sleep") as mock_sleep:
                with patch.object(_plugin_time, "monotonic", side_effect=self._monotonic_seq()):
                    _upload_with_retry(
                        stub, request, self.AUTH_TOKEN,
                        retry_timeout_seconds=9999, initial_wait_seconds=1,
                    )

        assert stub.Upload.call_count == 3
        assert mock_sleep.call_count == 2

    def test_non_retriable_error_raises_immediately(self):
        """UNAUTHENTICATED propagates after one call — no retry, no sleep."""
        unauth_err = make_rpc_error(grpc.StatusCode.UNAUTHENTICATED, "invalid token")
        stub = MagicMock()
        stub.Upload.side_effect = unauth_err
        request = MagicMock()

        with patch.object(_plugin_mod, "current_app"):
            with patch.object(_plugin_time, "sleep") as mock_sleep:
                with pytest.raises(grpc.RpcError):
                    _upload_with_retry(
                        stub, request, self.AUTH_TOKEN,
                        retry_timeout_seconds=10, initial_wait_seconds=1,
                    )

        stub.Upload.assert_called_once()
        mock_sleep.assert_not_called()

    def test_timeout_raises_last_grpc_error(self):
        """After the deadline passes the last retriable error is re-raised.

        monotonic() call pattern (deadline = start + 5 = 5):
          [0] start → deadline=5;
          [1] now (failure 1): elapsed=1.0, 1.0 < 5 → not expired → sleep → retry
          [2] now (failure 2): elapsed=6.0, 6.0 >= 5 → EXPIRED → raise
        """
        unavailable_err = make_rpc_error(grpc.StatusCode.UNAVAILABLE, "no healthy upstream")
        stub = MagicMock()
        stub.Upload.side_effect = unavailable_err
        request = MagicMock()

        monotonic_values = [0.0, 1.0, 6.0] + [10.0] * 5

        with patch.object(_plugin_mod, "current_app"):
            with patch.object(_plugin_time, "sleep"):
                with patch.object(_plugin_time, "monotonic", side_effect=monotonic_values):
                    with pytest.raises(grpc.RpcError):
                        _upload_with_retry(
                            stub, request, self.AUTH_TOKEN,
                            retry_timeout_seconds=5, initial_wait_seconds=1,
                        )

        # Two Upload calls: first fails+retries, second fails+times out.
        assert stub.Upload.call_count == 2

    def test_exponential_backoff_with_cap(self):
        """sleep() called with 1→2→4→8→16 for 5 retriable failures then success.

        monotonic() calls: 1 (start) + 5*2 (per failure: elapsed+deadline check) +
        1 (success log, because attempt>0) = 12 total.
        """
        unavailable_err = make_rpc_error(grpc.StatusCode.UNAVAILABLE, "no healthy upstream")
        stub = MagicMock()
        stub.Upload.side_effect = [
            unavailable_err,
            unavailable_err,
            unavailable_err,
            unavailable_err,
            unavailable_err,
            MagicMock(),
        ]
        request = MagicMock()

        with patch.object(_plugin_mod, "current_app"):
            with patch.object(_plugin_time, "sleep") as mock_sleep:
                with patch.object(_plugin_time, "monotonic", side_effect=self._monotonic_seq()):
                    _upload_with_retry(
                        stub, request, self.AUTH_TOKEN,
                        retry_timeout_seconds=9999, initial_wait_seconds=1,
                    )

        sleep_args = [c.args[0] for c in mock_sleep.call_args_list]
        assert sleep_args == [1.0, 2.0, 4.0, 8.0, 16.0]

    def test_exponential_backoff_caps_at_60(self):
        """Wait time never exceeds 60 s regardless of retry count.

        8 failures → expected waits: 1, 2, 4, 8, 16, 32, 60, 60.
        monotonic() calls: 1 (start) + 8*2 (per failure) + 1 (success log) = 18 total.
        """
        unavailable_err = make_rpc_error(grpc.StatusCode.UNAVAILABLE, "no healthy upstream")
        stub = MagicMock()
        stub.Upload.side_effect = [unavailable_err] * 8 + [MagicMock()]
        request = MagicMock()

        with patch.object(_plugin_mod, "current_app"):
            with patch.object(_plugin_time, "sleep") as mock_sleep:
                with patch.object(_plugin_time, "monotonic", side_effect=self._monotonic_seq()):
                    _upload_with_retry(
                        stub, request, self.AUTH_TOKEN,
                        retry_timeout_seconds=9999, initial_wait_seconds=1,
                    )

        sleep_args = [c.args[0] for c in mock_sleep.call_args_list]
        assert sleep_args == [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0]
        assert all(v <= 60.0 for v in sleep_args)
