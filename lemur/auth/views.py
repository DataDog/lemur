"""
.. module: lemur.auth.views
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

import jwt
import base64
import requests
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

from lemur.auth.vault_jwt_auth import JWTAuthenticator
from lemur.auth.isa_vault_service import ISAVaultValidator

from flask import Blueprint, current_app

from flask_restful import reqparse, Resource, Api
from flask_principal import Identity, identity_changed

from lemur.constants import SUCCESS_METRIC_STATUS, FAILURE_METRIC_STATUS
from lemur.extensions import metrics
from lemur.common.utils import get_psuedo_random_string, get_state_token_secret

from lemur.users import service as user_service
from lemur.roles import service as role_service
from lemur.logs import service as log_service
from lemur.auth.service import create_token, fetch_token_header, get_rsa_public_key
from lemur.auth import ldap
from lemur.plugins.base import plugins

mod = Blueprint("auth", __name__)
api = Api(mod)


def exchange_for_access_token(
    code, redirect_uri, client_id, secret, access_token_url=None, verify_cert=True
):
    """
    Exchanges authorization code for access token.

    :param code:
    :param redirect_uri:
    :param client_id:
    :param secret:
    :param access_token_url:
    :param verify_cert:
    :return:
    :return:
    """
    # take the information we have received from the provider to create a new request
    params = {
        "grant_type": "authorization_code",
        "scope": "openid email profile address",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    }

    # the secret and cliendId will be given to you when you signup for the provider
    token = "{0}:{1}".format(client_id, secret)

    basic = base64.b64encode(bytes(token, "utf-8"))
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    if current_app.config.get("TOKEN_AUTH_HEADER_CASE_SENSITIVE"):
        headers["Authorization"] = "Basic {0}".format(basic.decode("utf-8"))
    else:
        headers["authorization"] = "basic {0}".format(basic.decode("utf-8"))

    # exchange authorization code for access token.
    r = requests.post(
        access_token_url, headers=headers, params=params, verify=verify_cert
    )
    if r.status_code == 400:
        r = requests.post(
            access_token_url, headers=headers, data=params, verify=verify_cert
        )
    id_token = r.json()["id_token"]
    access_token = r.json()["access_token"]

    return id_token, access_token


def validate_id_token(id_token, client_id, jwks_url):
    """
    Ensures that the token we receive is valid.

    :param id_token:
    :param client_id:
    :param jwks_url:
    :return:
    """
    # fetch token public key
    header_data = fetch_token_header(id_token)

    # retrieve the key material as specified by the token header
    r = requests.get(jwks_url)
    for key in r.json()["keys"]:
        if key["kid"] == header_data["kid"]:
            secret = get_rsa_public_key(key["n"], key["e"])
            algo = header_data["alg"]
            break
    else:
        return dict(message="Key not found"), 401

    # validate your token based on the key it was signed with
    try:
        jwt.decode(
            id_token, secret.decode("utf-8"), algorithms=[algo], audience=client_id
        )
    except jwt.DecodeError:
        return dict(message="Token is invalid"), 401
    except jwt.ExpiredSignatureError:
        return dict(message="Token has expired"), 401
    except jwt.InvalidTokenError:
        return dict(message="Token is invalid"), 401


def retrieve_user(user_api_url, access_token):
    """
    Fetch user information from provided user api_url.

    :param user_api_url:
    :param access_token:
    :return:
    """
    user_params = dict(access_token=access_token, schema="profile")

    headers = {}

    if current_app.config.get("PING_INCLUDE_BEARER_TOKEN"):
        headers = {"Authorization": f"Bearer {access_token}"}

    # retrieve information about the current user.
    r = requests.get(user_api_url, params=user_params, headers=headers)
    # Some IDPs, like "Keycloak", require a POST instead of a GET
    if r.status_code == 400:
        r = requests.post(user_api_url, data=user_params, headers=headers)

    profile = r.json()

    user = user_service.get_by_email(profile["email"])
    return user, profile


def retrieve_user_memberships(user_api_url, user_membership_provider, access_token):
    user, profile = retrieve_user(user_api_url, access_token)

    if user_membership_provider is None:
        return user, profile
    """
    Unaware of the usage of this code across the community, current implementation is config driven.
    Without USER_MEMBERSHIP_PROVIDER configured, it is backward compatible. Please define a plugin
    for custom implementation.
    """
    membership_provider = plugins.get(user_membership_provider)
    user_membership = {
        "email": profile["email"],
        "thumbnailPhotoUrl": profile["thumbnailPhotoUrl"],
        "googleGroups": membership_provider.retrieve_user_memberships(
            profile["userId"]
        ),
    }

    return user, user_membership


def create_user_roles(profile):
    """Creates new roles based on profile information.

    :param profile:
    :return:
    """
    roles = []

    # update their google 'roles'
    if "googleGroups" in profile:
        for group in profile["googleGroups"]:
            role = role_service.get_by_name(group)
            if not role:
                role = role_service.create(
                    group,
                    description="This is a google group based role created by Lemur",
                    third_party=True,
                )
            if (group != "admin") and (not role.third_party):
                role = role_service.set_third_party(role.id, third_party_status=True)
            roles.append(role)
    else:
        current_app.logger.warning(
            "'googleGroups' not sent by identity provider, no specific roles will assigned to the user."
        )

    role = role_service.get_by_name(profile["email"])

    if not role:
        role = role_service.create(
            profile["email"],
            description="This is a user specific role",
            third_party=True,
        )
    if not role.third_party:
        role = role_service.set_third_party(role.id, third_party_status=True)

    roles.append(role)

    # every user is an operator (tied to a default role)
    if current_app.config.get("LEMUR_DEFAULT_ROLE"):
        default = role_service.get_by_name(current_app.config["LEMUR_DEFAULT_ROLE"])
        if not default:
            default = role_service.create(
                current_app.config["LEMUR_DEFAULT_ROLE"],
                description="This is the default Lemur role.",
            )
        if not default.third_party:
            role_service.set_third_party(default.id, third_party_status=True)
        roles.append(default)

    return roles


def update_user(user, profile, roles):
    """Updates user with current profile information and associated roles.

    :param user:
    :param profile:
    :param roles:
    """
    # if we get an sso user create them an account
    if not user:
        user = user_service.create(
            profile["email"],
            get_psuedo_random_string(),
            profile["email"],
            True,
            profile.get("thumbnailPhotoUrl"),
            roles,
        )

    else:
        # we add 'lemur' specific roles, so they do not get marked as removed
        removed_roles = []
        for ur in user.roles:
            if not ur.third_party:
                roles.append(ur)
            elif ur not in roles:
                # This is a role assigned in lemur, but not returned by sso during current login
                removed_roles.append(ur.name)

        if removed_roles:
            log_service.audit_log(
                "unassign_role", user.username, f"Un-assigning roles {removed_roles}"
            )
        # update any changes to the user
        user_service.update(
            user.id,
            profile["email"],
            profile["email"],
            True,
            profile.get("thumbnailPhotoUrl"),  # profile isn't google+ enabled
            roles,
        )

    return user


def build_hmac():
    key = current_app.config.get("OAUTH_STATE_TOKEN_SECRET", None)
    if not key:
        current_app.logger.warning(
            "OAuth State Token Secret not discovered in config. Generating one."
        )
        key = get_state_token_secret()
        current_app.config["OAUTH_STATE_TOKEN_SECRET"] = (
            key  # store for remainder of Flask session
        )

    try:
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    except TypeError:
        current_app.logger.error("OAuth State Token Secret must be bytes-like.")
        return None
    return h


def generate_state_token():
    t = int(time.time())
    ts = hex(t)[2:].encode("ascii")
    h = build_hmac()
    h.update(ts)
    digest = base64.b64encode(h.finalize())
    state = ts + b":" + digest
    return state.decode("utf-8")


def verify_state_token(token):
    stale_seconds = current_app.config.get(
        "OAUTH_STATE_TOKEN_STALE_TOLERANCE_SECONDS", 15
    )
    try:
        state = token.encode("utf-8")
        ts, digest = state.split(b":")
        timestamp = int(ts, 16)
        if float(time.time() - timestamp) > stale_seconds:
            current_app.logger.warning("OAuth State token is too stale.")
            return False
        digest = base64.b64decode(digest)
    except ValueError as e:
        current_app.logger.warning(f"Error while parsing OAuth State token: {e}")
        return False

    try:
        h = build_hmac()
        h.update(ts)
        h.verify(digest)
        return True
    except InvalidSignature:
        current_app.logger.warning("OAuth State token is invalid.")
        return False
    except Exception as e:
        current_app.logger.warning(f"Error while parsing OAuth State token: {e}")
        return False


class Login(Resource):
    """
    Provides an endpoint for Lemur's basic authentication. It takes a username and password
    combination and returns a JWT token.

    This token token is required for each API request and must be provided in the Authorization Header for the request.
    ::

        Authorization:Bearer <token>

    Tokens have a set expiration date. You can inspect the token expiration by base64 decoding the token and inspecting
    it's contents.

    .. note:: It is recommended that the token expiration is fairly short lived (hours not days). This will largely depend \
    on your uses cases but. It is important to not that there is currently no build in method to revoke a users token \
    and force re-authentication.
    """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Login, self).__init__()

    def post(self):
        """
        .. http:post:: /auth/login

           Login with username:password

           **Example request**:

           .. sourcecode:: http

              POST /auth/login HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "username": "test",
                "password": "test"
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "token": "12343243243"
              }

           :arg username: username
           :arg password: password
           :statuscode 401: invalid credentials
           :statuscode 200: no error
        """
        self.reqparse.add_argument("username", type=str, required=True, location="json")
        self.reqparse.add_argument("password", type=str, required=True, location="json")

        args = self.reqparse.parse_args()

        if "@" in args["username"]:
            user = user_service.get_by_email(args["username"])
        else:
            user = user_service.get_by_username(args["username"])

        # default to local authentication
        if user and user.check_password(args["password"]) and user.active:
            # Tell Flask-Principal the identity changed
            identity_changed.send(
                current_app._get_current_object(), identity=Identity(user.id)
            )

            metrics.send(
                "login", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
            )
            return dict(token=create_token(user))

        # try ldap login
        if current_app.config.get("LDAP_AUTH"):
            try:
                ldap_principal = ldap.LdapPrincipal(args)
                user = ldap_principal.authenticate()
                if user and user.active:
                    # Tell Flask-Principal the identity changed
                    identity_changed.send(
                        current_app._get_current_object(), identity=Identity(user.id)
                    )
                    metrics.send(
                        "login",
                        "counter",
                        1,
                        metric_tags={"status": SUCCESS_METRIC_STATUS},
                    )
                    return dict(token=create_token(user))
            except Exception as e:
                current_app.logger.error("ldap error: {0}".format(e))
                ldap_message = "ldap error: %s" % e
                metrics.send(
                    "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
                )
                return dict(message=ldap_message), 403

        # if not valid user - no certificates for you
        metrics.send(
            "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
        )
        return dict(message="The supplied credentials are invalid"), 403


class Ping(Resource):
    """
    This class serves as an example of how one might implement an SSO provider for use with Lemur. In
    this example we use an OpenIDConnect authentication flow, that is essentially OAuth2 underneath. If you have an
    OAuth2 provider you want to use Lemur there would be two steps:

    1. Define your own class that inherits from :class:`flask_restful.Resource` and create the HTTP methods the \
    provider uses for its callbacks.
    2. Add or change the Lemur AngularJS Configuration to point to your new provider
    """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Ping, self).__init__()

    def get(self):
        return "Redirecting..."

    def post(self):
        self.reqparse.add_argument("clientId", type=str, required=True, location="json")
        self.reqparse.add_argument(
            "redirectUri", type=str, required=True, location="json"
        )
        self.reqparse.add_argument("code", type=str, required=True, location="json")

        args = self.reqparse.parse_args()

        # you can either discover these dynamically or simply configure them
        access_token_url = current_app.config.get("PING_ACCESS_TOKEN_URL")

        secret = current_app.config.get("PING_SECRET")

        id_token, access_token = exchange_for_access_token(
            args["code"],
            args["redirectUri"],
            args["clientId"],
            secret,
            access_token_url=access_token_url,
        )

        jwks_url = current_app.config.get("PING_JWKS_URL")
        error_code = validate_id_token(id_token, args["clientId"], jwks_url)
        if error_code:
            return error_code

        user, profile = retrieve_user_memberships(
            current_app.config.get("PING_USER_API_URL"),
            current_app.config.get("USER_MEMBERSHIP_PROVIDER"),
            access_token,
        )
        roles = create_user_roles(profile)
        user = update_user(user, profile, roles)

        if not user or not user.active:
            metrics.send(
                "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
            )
            return dict(message="The supplied credentials are invalid"), 403

        # Tell Flask-Principal the identity changed
        identity_changed.send(
            current_app._get_current_object(), identity=Identity(user.id)
        )

        metrics.send(
            "login", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
        )
        return dict(token=create_token(user))


class OAuth2(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(OAuth2, self).__init__()

    def get(self):
        return "Redirecting..."

    def post(self):
        self.reqparse.add_argument("clientId", type=str, required=True, location="json")
        self.reqparse.add_argument(
            "redirectUri", type=str, required=True, location="json"
        )
        self.reqparse.add_argument("code", type=str, required=True, location="json")
        self.reqparse.add_argument("state", type=str, required=True, location="json")

        args = self.reqparse.parse_args()
        if not verify_state_token(args["state"]):
            return dict(message="The supplied credentials are invalid"), 403

        # you can either discover these dynamically or simply configure them
        access_token_url = current_app.config.get("OAUTH2_ACCESS_TOKEN_URL")
        user_api_url = current_app.config.get("OAUTH2_USER_API_URL")
        verify_cert = current_app.config.get("OAUTH2_VERIFY_CERT")

        secret = current_app.config.get("OAUTH2_SECRET")

        id_token, access_token = exchange_for_access_token(
            args["code"],
            args["redirectUri"],
            args["clientId"],
            secret,
            access_token_url=access_token_url,
            verify_cert=verify_cert,
        )

        jwks_url = current_app.config.get("OAUTH2_JWKS_URL")
        error_code = validate_id_token(id_token, args["clientId"], jwks_url)
        if error_code:
            return error_code

        user, profile = retrieve_user(user_api_url, access_token)
        roles = create_user_roles(profile)
        user = update_user(user, profile, roles)

        if not user.active:
            metrics.send(
                "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
            )
            return dict(message="The supplied credentials are invalid"), 403

        # Tell Flask-Principal the identity changed
        identity_changed.send(
            current_app._get_current_object(), identity=Identity(user.id)
        )

        metrics.send(
            "login", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
        )

        return dict(token=create_token(user))


class Google(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Google, self).__init__()

    def post(self):
        access_token_url = "https://accounts.google.com/o/oauth2/token"
        user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"

        self.reqparse.add_argument("clientId", type=str, required=True, location="json")
        self.reqparse.add_argument(
            "redirectUri", type=str, required=True, location="json"
        )
        self.reqparse.add_argument("code", type=str, required=True, location="json")

        args = self.reqparse.parse_args()

        # Step 1. Exchange authorization code for access token
        payload = {
            "client_id": args["clientId"],
            "grant_type": "authorization_code",
            "redirect_uri": args["redirectUri"],
            "code": args["code"],
            "client_secret": current_app.config.get("GOOGLE_SECRET"),
            "scope": "email",
        }

        r = requests.post(access_token_url, data=payload)
        token = r.json()

        # Step 2. Retrieve information about the current user
        headers = {"Authorization": "Bearer {0}".format(token["access_token"])}

        r = requests.get(user_info_url, headers=headers)
        profile = r.json()

        user = user_service.get_by_email(profile["email"])

        if not (user and user.active):
            metrics.send(
                "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
            )
            return dict(message="The supplied credentials are invalid."), 403

        if user:
            metrics.send(
                "login", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
            )
            return dict(token=create_token(user))

        metrics.send(
            "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
        )


class Vault(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(Vault, self).__init__()

    def get(self):
        return "Redirecting..."

    def post(self):
        self.reqparse.add_argument("id_token", type=str, required=True, location="json")
        args = self.reqparse.parse_args()
        id_token = args["id_token"]
        authenticator = JWTAuthenticator.instance(
            name="lemur_vault_authenticator",
            audience=current_app.config.get("VAULT_CLIENT_ID"),
            issuers=[
                current_app.config.get("VAULT_ISSUER_URL"),
            ],
            timeout=1,
        )
        profile = authenticator.authenticate(id_token)

        user_has_authorized_email = profile["email"] in current_app.config.get(
            "VAULT_AUTHORIZED_EMAILS"
        )
        user_in_authorized_group = False
        for group in current_app.config.get("VAULT_AUTHORIZED_GROUPS"):
            if group in profile["groups"]:
                user_in_authorized_group = True
                break

        if not user_has_authorized_email and not user_in_authorized_group:
            return dict(message="The supplied credentials are invalid"), 403

        user = user_service.get_by_email(profile["email"])

        roles = create_user_roles(profile)
        user = update_user(user, profile, roles)

        if not user.active:
            metrics.send(
                "login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
            )
            return dict(message="The supplied credentials are invalid"), 403

        # Tell Flask-Principal the identity changed
        identity_changed.send(
            current_app._get_current_object(), identity=Identity(user.id)
        )

        metrics.send(
            "login", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
        )

        return dict(token=create_token(user))


class ISAToken(Resource):
    """
    Authenticates using ISA tokens validated against HashiCorp Vault.

    This endpoint accepts an ISA token, validates it against the approved token list
    stored in Vault, and returns a JWT token for API access if valid.

    The ISA tokens and their associated user information must be pre-configured in Vault
    at the path specified by ISA_VAULT_TOKEN_PATH configuration.
    """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(ISAToken, self).__init__()

    def post(self):
        """
        .. http:post:: /auth/isa

           Authenticate with ISA token

           **Example request**:

           .. sourcecode:: http

              POST /auth/isa HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "isa_token": "your-isa-token-here"
              }

           **Example response**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
              }

           :arg isa_token: ISA authentication token
           :statuscode 401: invalid or expired token
           :statuscode 403: token not authorized or user inactive
           :statuscode 500: Vault communication error
           :statuscode 200: authentication successful
        """
        self.reqparse.add_argument(
            "isa_token", type=str, required=True, location="json"
        )

        args = self.reqparse.parse_args()
        isa_token = args["isa_token"]

        try:
            # Initialize Vault validator
            validator = ISAVaultValidator()

            # Validate token against Vault
            token_data = validator.validate_token(isa_token)

            if not token_data:
                metrics.send(
                    "isa_login",
                    "counter",
                    1,
                    metric_tags={"status": FAILURE_METRIC_STATUS},
                )
                return dict(message="Invalid or unauthorized ISA token"), 401

            # Get user by email or ID
            user = None
            if token_data.get("user_email"):
                user = user_service.get_by_email(token_data["user_email"])
            elif token_data.get("user_id"):
                user = user_service.get_by_id(token_data["user_id"])

            if not user:
                current_app.logger.error(
                    f"ISA token valid but user not found: {token_data.get('user_email')}"
                )
                metrics.send(
                    "isa_login",
                    "counter",
                    1,
                    metric_tags={"status": FAILURE_METRIC_STATUS},
                )
                return dict(message="User not found"), 403

            if not user.active:
                current_app.logger.warning(
                    f"ISA token valid but user inactive: {user.email}"
                )
                metrics.send(
                    "isa_login",
                    "counter",
                    1,
                    metric_tags={"status": FAILURE_METRIC_STATUS},
                )
                return dict(message="User account is inactive"), 403

            # Log successful authentication
            log_service.audit_log(
                "isa_token_login", user.username, f"Successful ISA token authentication"
            )

            # Tell Flask-Principal the identity changed
            identity_changed.send(
                current_app._get_current_object(), identity=Identity(user.id)
            )

            metrics.send(
                "isa_login", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
            )

            return dict(token=create_token(user))

        except ValueError as e:
            current_app.logger.error(f"ISA token validation configuration error: {e}")
            metrics.send(
                "isa_login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
            )
            return dict(message="Authentication service misconfigured"), 500

        except Exception as e:
            current_app.logger.error(f"ISA token validation error: {e}")
            metrics.send(
                "isa_login", "counter", 1, metric_tags={"status": FAILURE_METRIC_STATUS}
            )
            return dict(message="Authentication service error"), 500


class ProxyAuth(Resource):
    """
    Proxy authorization endpoint for service-to-service operations acting on behalf of users.

    This endpoint validates an API token and checks if the specified user exists and is active
    in the Lemur database. It's designed for services that need to perform operations on
    behalf of users.
    """

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(ProxyAuth, self).__init__()

    def post(self):
        """
        .. http:post:: /auth/proxy-auth

           Authorize a service token to act on behalf of a user

           **Example request**:

           .. sourcecode:: http

              POST /auth/proxy-auth HTTP/1.1
              Host: example.com
              Accept: application/json, text/javascript
              Content-Type: application/json;charset=UTF-8

              {
                "api_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "behalf_of": "user@example.com"
              }

           **Example response (success)**:

           .. sourcecode:: http

              HTTP/1.1 200 OK
              Vary: Accept
              Content-Type: text/javascript

              {
                "authorized": true,
                "user": {
                  "id": 1,
                  "email": "user@example.com",
                  "username": "user",
                  "active": true
                }
              }

           **Example response (failure)**:

           .. sourcecode:: http

              HTTP/1.1 403 Forbidden
              Vary: Accept
              Content-Type: text/javascript

              {
                "authorized": false,
                "message": "User not found or inactive"
              }

           :arg api_token: JWT token for the service
           :arg behalf_of: User email or username to act on behalf of
           :statuscode 200: authorization check completed
           :statuscode 400: missing required fields
           :statuscode 401: invalid or expired token
           :statuscode 403: user not found or inactive
        """
        self.reqparse.add_argument(
            "api_token", type=str, required=True, location="json"
        )
        self.reqparse.add_argument(
            "behalf_of", type=str, required=True, location="json"
        )

        args = self.reqparse.parse_args()
        api_token = args["api_token"]
        behalf_of = args["behalf_of"]

        # Step 1: Validate the API token
        try:
            payload = jwt.decode(
                api_token,
                current_app.config["LEMUR_TOKEN_SECRET"],
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            current_app.logger.warning(
                f"Proxy-auth attempt with expired token for behalf_of: {behalf_of}"
            )
            metrics.send(
                "proxy_auth",
                "counter",
                1,
                metric_tags={
                    "status": FAILURE_METRIC_STATUS,
                    "reason": "expired_token",
                },
            )
            return dict(authorized=False, message="Token has expired"), 401
        except jwt.InvalidTokenError as e:
            current_app.logger.warning(
                f"Proxy-auth attempt with invalid token for behalf_of: {behalf_of}"
            )
            metrics.send(
                "proxy_auth",
                "counter",
                1,
                metric_tags={
                    "status": FAILURE_METRIC_STATUS,
                    "reason": "invalid_token",
                },
            )
            return dict(authorized=False, message="Token is invalid"), 401

        # Step 2: Get the service account/user who owns this API token
        service_account_id = payload.get("sub")
        if not service_account_id:
            current_app.logger.warning(f"Proxy-auth attempt with token missing user ID")
            metrics.send(
                "proxy_auth",
                "counter",
                1,
                metric_tags={
                    "status": FAILURE_METRIC_STATUS,
                    "reason": "invalid_token_format",
                },
            )
            return dict(authorized=False, message="Token is invalid"), 401

        service_account = user_service.get(service_account_id)
        if not service_account:
            current_app.logger.warning(
                f"Proxy-auth attempt with token for non-existent user ID: {service_account_id}"
            )
            metrics.send(
                "proxy_auth",
                "counter",
                1,
                metric_tags={
                    "status": FAILURE_METRIC_STATUS,
                    "reason": "service_account_not_found",
                },
            )
            return dict(authorized=False, message="Service account not found"), 401

        # Step 3: CRITICAL - Verify the service account (token owner) has the proxy role
        # This ensures only authorized service accounts can act on behalf of users
        has_proxy_role = any(role.name == "proxy" for role in service_account.roles)
        if not has_proxy_role:
            current_app.logger.warning(
                f"Proxy-auth DENIED: service account '{service_account.email}' lacks proxy role (attempted behalf_of: {behalf_of})"
            )
            metrics.send(
                "proxy_auth",
                "counter",
                1,
                metric_tags={
                    "status": FAILURE_METRIC_STATUS,
                    "reason": "missing_proxy_role",
                },
            )
            return (
                dict(
                    authorized=False,
                    message="Service account does not have proxy role",
                    service_account=service_account.email,
                ),
                403,
            )

        # Step 4: Look up the target user (behalf_of) - this is who we're acting ON BEHALF OF
        # NOTE: We do NOT check if this user has proxy role - only verify they exist and are active
        target_user = None
        if "@" in behalf_of:
            # Treat as email
            target_user = user_service.get_by_email(behalf_of)
        else:
            # Treat as username
            target_user = user_service.get_by_username(behalf_of)

        if not target_user:
            current_app.logger.warning(
                f"Proxy-auth failed: target user '{behalf_of}' not found (requested by: {service_account.email})"
            )
            metrics.send(
                "proxy_auth",
                "counter",
                1,
                metric_tags={
                    "status": FAILURE_METRIC_STATUS,
                    "reason": "target_user_not_found",
                },
            )
            return dict(authorized=False, message="Target user not found"), 403

        if not target_user.active:
            current_app.logger.warning(
                f"Proxy-auth failed: target user '{behalf_of}' inactive (requested by: {service_account.email})"
            )
            metrics.send(
                "proxy_auth",
                "counter",
                1,
                metric_tags={
                    "status": FAILURE_METRIC_STATUS,
                    "reason": "target_user_inactive",
                },
            )
            return dict(authorized=False, message="Target user is inactive"), 403

        # Authorization successful - service account can act on behalf of target user
        current_app.logger.info(
            f"Proxy-auth SUCCESS: '{service_account.email}' authorized to act on behalf of '{target_user.email}'"
        )
        metrics.send(
            "proxy_auth", "counter", 1, metric_tags={"status": SUCCESS_METRIC_STATUS}
        )

        return (
            dict(
                authorized=True,
                service_account={
                    "id": service_account.id,
                    "email": service_account.email,
                    "username": service_account.username,
                },
                target_user={
                    "id": target_user.id,
                    "email": target_user.email,
                    "username": target_user.username,
                    "active": target_user.active,
                },
            ),
            200,
        )


class Providers(Resource):
    def get(self):
        active_providers = []

        for provider in current_app.config.get("ACTIVE_PROVIDERS", []):
            provider = provider.lower()

            if provider == "google":
                active_providers.append(
                    {
                        "name": "google",
                        "clientId": current_app.config.get("GOOGLE_CLIENT_ID"),
                        "url": api.url_for(Google),
                    }
                )

            elif provider == "ping":
                active_providers.append(
                    {
                        "name": current_app.config.get("PING_NAME"),
                        "url": current_app.config.get(
                            "PING_URL", current_app.config.get("PING_REDIRECT_URI")
                        ),
                        "redirectUri": current_app.config.get("PING_REDIRECT_URI"),
                        "clientId": current_app.config.get("PING_CLIENT_ID"),
                        "responseType": "code",
                        "scope": ["openid", "email", "profile", "address"],
                        "scopeDelimiter": " ",
                        "authorizationEndpoint": current_app.config.get(
                            "PING_AUTH_ENDPOINT"
                        ),
                        "requiredUrlParams": ["scope"],
                        "type": "2.0",
                    }
                )

            elif provider == "oauth2":
                active_providers.append(
                    {
                        "name": current_app.config.get("OAUTH2_NAME"),
                        "url": current_app.config.get(
                            "OAUTH2_URL", current_app.config.get("OAUTH2_REDIRECT_URI")
                        ),
                        "redirectUri": current_app.config.get("OAUTH2_REDIRECT_URI"),
                        "clientId": current_app.config.get("OAUTH2_CLIENT_ID"),
                        "responseType": "code",
                        "scope": ["openid", "email", "profile", "groups"],
                        "scopeDelimiter": " ",
                        "authorizationEndpoint": current_app.config.get(
                            "OAUTH2_AUTH_ENDPOINT"
                        ),
                        "requiredUrlParams": ["scope", "state", "nonce"],
                        "state": generate_state_token(),
                        "nonce": get_psuedo_random_string(),
                        "type": "2.0",
                    }
                )

            elif provider == "vault":
                active_providers.append(
                    {
                        "name": current_app.config.get("VAULT_NAME"),
                        "url": current_app.config.get("VAULT_REDIRECT_URI"),
                        "redirectUri": current_app.config.get("VAULT_REDIRECT_URI"),
                        "clientId": current_app.config.get("VAULT_CLIENT_ID"),
                        "responseType": "id_token",
                        "responseParams": {
                            "code": "code",
                            "clientId": "clientId",
                            "redirectUri": "redirectUri",
                            "id_token": "id_token",
                        },
                        "scope": ["openid"],
                        "scopeDelimiter": " ",
                        "authorizationEndpoint": current_app.config.get(
                            "VAULT_AUTH_ENDPOINT"
                        ),
                        "requiredUrlParams": ["scope", "nonce"],
                        "oauthType": "2.0",
                        "nonce": get_psuedo_random_string(),
                    }
                )

        return active_providers


api.add_resource(Login, "/auth/login", endpoint="login")
api.add_resource(Ping, "/auth/ping", endpoint="ping")
api.add_resource(Google, "/auth/google", endpoint="google")
api.add_resource(OAuth2, "/auth/oauth2", endpoint="oauth2")
api.add_resource(Vault, "/auth/vault", endpoint="vault")
api.add_resource(ISAToken, "/auth/isa", endpoint="isa")
api.add_resource(ProxyAuth, "/auth/proxy-auth", endpoint="proxyauth")
api.add_resource(Providers, "/auth/providers", endpoint="providers")
