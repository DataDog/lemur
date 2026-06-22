from flask import Blueprint, current_app, request
from flask_restful import Api

from lemur.auth.service import AuthenticatedResource
from lemur.plugins.lemur_digicert_dcv.digicert import DigiCertDCVProvider
from lemur.plugins.lemur_digicert_dcv.provider import DCVAPIError, DCVPropagationTimeout, DCVRegistrationError

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
        except (DCVAPIError, DCVPropagationTimeout) as e:
            current_app.logger.exception(
                "DCV register_domain failed for %s",
                e.domain if hasattr(e, "domain") else domain,
            )
            return {"message": "DCV validation failed; see server logs"}, 500
        except Exception:
            current_app.logger.exception(
                "Unexpected error in DomainDCVRegister for domain %s", domain
            )
            return {"message": "Internal server error"}, 500


api.add_resource(DomainDCVRegister, "/domains/dcv/register", endpoint="domainDCVRegister")
