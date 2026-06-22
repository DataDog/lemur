import json
from unittest.mock import patch, Mock


@patch("lemur.plugins.lemur_digicert_dcv.views.DigiCertDCVProvider")
def test_register_endpoint_returns_200_on_success(mock_provider_cls):
    from lemur.plugins.lemur_digicert_dcv.views import DomainDCVRegister
    from flask import Flask

    app = Flask(__name__)
    with app.test_request_context(
        "/domains/dcv/register",
        method="POST",
        data=json.dumps({"domain": "ap3.prod.dog"}),
        content_type="application/json",
    ):
        mock_provider_cls.return_value.register_domain.return_value = None

        resource = DomainDCVRegister()
        result = resource._register("ap3.prod.dog")

        assert result[1] == 200
        assert result[0]["domain"] == "ap3.prod.dog"
        assert result[0]["status"] == "registered"


@patch("lemur.plugins.lemur_digicert_dcv.views.DigiCertDCVProvider")
def test_register_endpoint_returns_422_on_registration_error(mock_provider_cls):
    from lemur.plugins.lemur_digicert_dcv.views import DomainDCVRegister
    from lemur.plugins.lemur_digicert_dcv.provider import DCVRegistrationError
    from flask import Flask

    app = Flask(__name__)
    with app.test_request_context(
        "/domains/dcv/register",
        method="POST",
        data=json.dumps({"domain": "bad.prod.dog"}),
        content_type="application/json",
    ):
        mock_provider_cls.return_value.register_domain.side_effect = DCVRegistrationError(
            domain="bad.prod.dog", reason="API error"
        )

        resource = DomainDCVRegister()
        result = resource._register("bad.prod.dog")

        assert result[1] == 422
        assert result[0]["domain"] == "bad.prod.dog"


def test_register_endpoint_returns_400_when_domain_missing():
    from lemur.plugins.lemur_digicert_dcv.views import DomainDCVRegister
    from flask import Flask

    app = Flask(__name__)
    with app.test_request_context(
        "/domains/dcv/register",
        method="POST",
        data=json.dumps({}),
        content_type="application/json",
    ):
        resource = DomainDCVRegister()
        result = resource._register(None)

        assert result[1] == 400


@patch("lemur.plugins.lemur_digicert_dcv.views.DigiCertDCVProvider")
def test_register_endpoint_returns_500_on_api_error(mock_provider_cls):
    from lemur.plugins.lemur_digicert_dcv.views import DomainDCVRegister
    from lemur.plugins.lemur_digicert_dcv.provider import DCVAPIError
    from flask import Flask

    app = Flask(__name__)
    with app.test_request_context(
        "/domains/dcv/register",
        method="POST",
        data=json.dumps({"domain": "ap3.prod.dog"}),
        content_type="application/json",
    ):
        mock_provider_cls.return_value.register_domain.side_effect = DCVAPIError(
            domain="ap3.prod.dog", ca="digicert", reason="500 Server Error"
        )
        resource = DomainDCVRegister()
        result = resource._register("ap3.prod.dog")

        assert result[1] == 500
        # Must NOT expose raw DigiCert error detail
        assert "500 Server Error" not in result[0]["message"]
        # Must return a safe generic message about DCV
        assert "DCV" in result[0]["message"] or "server" in result[0]["message"].lower()


def test_register_endpoint_post_dispatch():
    """Integration: exercises the full post() -> _register() dispatch path."""
    import json as _json
    from unittest.mock import patch
    from flask import Flask
    from flask_restful import Api

    # Patch DigiCertDCVProvider before the view is used
    with patch("lemur.plugins.lemur_digicert_dcv.views.DigiCertDCVProvider") as mock_cls:
        mock_cls.return_value.register_domain.return_value = None

        from lemur.plugins.lemur_digicert_dcv.views import DomainDCVRegister

        # Build a minimal Flask + flask_restful app, bypassing Lemur's login_required
        # decorator by temporarily clearing method_decorators on AuthenticatedResource.
        with patch.object(DomainDCVRegister, "method_decorators", []):
            app = Flask(__name__)
            api = Api(app)
            api.add_resource(DomainDCVRegister, "/domains/dcv/register")

            client = app.test_client()
            resp = client.post(
                "/domains/dcv/register",
                data=_json.dumps({"domain": "ap3.prod.dog"}),
                content_type="application/json",
            )

            assert resp.status_code == 200
            data = _json.loads(resp.data)
            assert data["domain"] == "ap3.prod.dog"
            assert data["status"] == "registered"
