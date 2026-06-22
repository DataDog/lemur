from flask import Blueprint, request
from flask_restful import Api

from lemur.auth.service import AuthenticatedResource
from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider
from lemur.plugins.lemur_digicert_dcv.provider import DCVRegistrationError

mod = Blueprint("dcv", __name__)
api = Api(mod)


class DomainDCVRegister(AuthenticatedResource):
    def post(self):
        data = request.get_json(force=True, silent=True) or {}
        domain = data.get("domain")
        return self._register(domain)

    def _register(self, domain):
        if not domain:
            return {"message": "domain is required"}, 400
        try:
            provider = DigiCertDCVProvider()
            provider.register_domain(domain)
            return {"domain": domain, "status": "registered"}, 200
        except DCVRegistrationError as e:
            return {"message": str(e), "domain": e.domain}, 422
        except Exception as e:
            return {"message": str(e)}, 500


api.add_resource(DomainDCVRegister, "/domains/dcv/register", endpoint="domainDCVRegister")
