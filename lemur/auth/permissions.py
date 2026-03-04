"""
.. module: lemur.auth.permissions
    :platform: Unix
    :synopsis: This module defines all the permission used within Lemur
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>
"""

from functools import partial, wraps
from collections import namedtuple

from flask import current_app, g, request, jsonify
from flask_principal import Permission, RoleNeed, Identity, identity_changed

# Permissions
operator_permission = Permission(RoleNeed("operator"))
admin_permission = Permission(RoleNeed("admin"))

CertificateOwner = namedtuple("certificate", ["method", "value"])
CertificateOwnerNeed = partial(CertificateOwner, "role")


class SensitiveDomainPermission(Permission):
    def __init__(self):
        needs = [RoleNeed("admin")]
        sensitive_domain_roles = current_app.config.get("SENSITIVE_DOMAIN_ROLES", [])

        if sensitive_domain_roles:
            for role in sensitive_domain_roles:
                needs.append(RoleNeed(role))

        super(SensitiveDomainPermission, self).__init__(*needs)


class CertificatePermission(Permission):
    def __init__(self, owner, roles):
        needs = [RoleNeed("admin"), RoleNeed(owner), RoleNeed("creator")]
        for r in roles:
            needs.append(CertificateOwnerNeed(str(r)))
            # Backwards compatibility with mixed-case role names
            if str(r) != str(r).lower():
                needs.append(CertificateOwnerNeed(str(r).lower()))

        super(CertificatePermission, self).__init__(*needs)


class ApiKeyCreatorPermission(Permission):
    def __init__(self):
        super(ApiKeyCreatorPermission, self).__init__(RoleNeed("admin"))


RoleMember = namedtuple("role", ["method", "value"])
RoleMemberNeed = partial(RoleMember, "member")


class RoleMemberPermission(Permission):
    def __init__(self, role_id):
        needs = [RoleNeed("admin"), RoleMemberNeed(role_id)]
        super(RoleMemberPermission, self).__init__(*needs)


AuthorityCreator = namedtuple("authority", ["method", "value"])
AuthorityCreatorNeed = partial(AuthorityCreator, "authorityUse")

AuthorityOwner = namedtuple("authority", ["method", "value"])
AuthorityOwnerNeed = partial(AuthorityOwner, "role")


class AuthorityPermission(Permission):
    def __init__(self, authority_id, roles):
        needs = [RoleNeed("admin"), AuthorityCreatorNeed(str(authority_id))]
        for r in roles:
            needs.append(AuthorityOwnerNeed(str(r)))

        super(AuthorityPermission, self).__init__(*needs)


def allow_proxy_authentication(f):
    """
    Decorator that enables proxy authentication.

    This allows service accounts with the 'proxy' role to act on behalf of other users
    by temporarily assuming their identity and permissions. The target user's full
    permission set is used for authorization checks.

    How it works:
    1. If 'behalf_of' parameter is present in request data
    2. Current user must have 'proxy' role
    3. Target user (behalf_of) must exist and be active
    4. Identity is swapped to target user for the duration of the request
    5. All permission checks use target user's permissions

    Original service account is stored in g.service_account for audit logging.
    Target user becomes g.current_user and g.user (standard Flask-Principal pattern).

    Usage:
        @allow_proxy_authentication
        def post(self, data=None):
            # g.current_user is now the target user (if proxy auth used)
            # g.service_account contains the original nom user (if proxy auth used)
            # All permission checks work normally with target user's permissions
            ...
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        request_data = request.get_json(silent=True) or {}
        behalf_of = request_data.get("behalf_of")

        current_app.logger.info(f"[PROXY] Decorator called, behalf_of={behalf_of}")

        # No proxy authentication requested - proceed normally
        if not behalf_of:
            current_app.logger.info("[PROXY] No behalf_of, proceeding normally")
            return f(*args, **kwargs)

        # Proxy authentication requested
        current_user = g.get("current_user")
        if not current_user:
            response = jsonify({"message": "Authentication required"})
            response.status_code = 401
            return response

        # Verify current user has proxy role
        has_proxy_role = any(role.name == "proxy" for role in current_user.roles)
        if not has_proxy_role:
            response = jsonify(
                {
                    "message": "Proxy authentication requires 'proxy' role",
                    "service_account": current_user.email,
                }
            )
            response.status_code = 403
            return response

        # Look up target user
        from lemur.users import service as user_service

        target_user = None
        if "@" in behalf_of:
            target_user = user_service.get_by_email(behalf_of)
        else:
            target_user = user_service.get_by_username(behalf_of)

        if not target_user:
            current_app.logger.warning(
                f"Proxy auth failed: Target user '{behalf_of}' not found"
            )
            response = jsonify(
                {
                    "message": f"Target user '{behalf_of}' not found for proxy authentication",
                    "behalf_of": behalf_of,
                }
            )
            response.status_code = 403
            return response

        if not target_user.active:
            current_app.logger.warning(
                f"Proxy auth failed: Target user '{behalf_of}' is not active"
            )
            response = jsonify(
                {
                    "message": f"Target user '{behalf_of}' is not active",
                    "behalf_of": behalf_of,
                }
            )
            response.status_code = 403
            return response

        # Store original service account for audit trail
        g.service_account = current_user
        g.behalf_of_user = target_user

        # PROXY: Swap identity to target user
        # This makes all permission checks work as if target user is making the request
        g.current_user = target_user
        g.user = target_user

        # Update Flask-Principal identity to target user
        # This ensures Permission.can() checks use target user's roles
        identity_changed.send(
            current_app._get_current_object(), identity=Identity(target_user.id)
        )

        current_app.logger.info(
            f"Proxy-auth: '{current_user.email}' (proxy) acting as '{target_user.email}'"
        )

        return f(*args, **kwargs)

    return decorated_function
