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
