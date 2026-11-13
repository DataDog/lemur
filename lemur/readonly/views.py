"""Opt-in certificate metadata API for short-lived, externally signed identities."""

import math
import time

import arrow
from flask import Blueprint, abort, current_app, g, jsonify, request
from sqlalchemy import text
from sqlalchemy.orm import Session

from lemur.auth.vault_jwt_auth import JWTAuthenticator
from lemur.certificates.models import Certificate
from lemur.extensions import db
from lemur.users.models import User

mod = Blueprint("readonly", __name__)


def reference(certificate):
    return {"id": certificate.id, "name": certificate.name, "cn": certificate.cn}


def metadata(certificate):
    result = reference(certificate)
    for output, attribute in (
        ("issuer", "issuer"),
        ("owner", "owner"),
        ("status", "status"),
        ("active", "notify"),
        ("rotation", "rotation"),
        ("serial", "serial"),
        ("keyType", "key_type"),
        ("bits", "bits"),
    ):
        value = getattr(certificate, attribute)
        result[output] = str(value) if output == "serial" else value
    result["notBefore"] = certificate.not_before.isoformat()
    result["notAfter"] = certificate.not_after.isoformat()
    result["san"] = ", ".join(domain.name for domain in certificate.domains)
    result["destinations"] = [
        {"id": destination.id, "label": destination.label}
        for destination in certificate.destinations
    ]
    result["endpoints"] = [
        {
            "id": endpoint.id,
            "name": endpoint.name,
            "dnsname": endpoint.dnsname,
            "port": endpoint.port,
            "active": endpoint.active,
            "sourceLabel": endpoint.source.label if endpoint.source else None,
        }
        for endpoint in certificate.endpoints
    ]
    result["replaces"] = [reference(item) for item in certificate.replaces]
    result["replacedBy"] = [reference(item) for item in certificate.replaced]
    return result


@mod.before_request
def authorize():
    if not current_app.config.get("READ_ONLY_API_ENABLED", False):
        abort(404)
    # Reject methods before authentication, including for administrators.
    if request.method != "GET":
        abort(405)
    audience = current_app.config.get("READ_ONLY_API_AUDIENCE")
    issuers = current_app.config.get("READ_ONLY_API_ISSUERS")
    environment = current_app.config.get("READ_ONLY_API_ENVIRONMENT")
    if not audience or not issuers or not environment:
        abort(503)
    authorization = request.headers.get("Authorization", "").split()
    if len(authorization) != 2 or authorization[0].lower() != "bearer":
        abort(401)
    try:
        authenticator = JWTAuthenticator.instance(
            name="readonly:" + audience + ":" + ",".join(issuers),
            audience=audience,
            issuers=issuers,
            timeout=1,
        )
        claims = authenticator.authenticate(authorization[1])
        expiry = claims.get("exp")
        if (
            claims.get("iss") not in issuers
            or claims.get("environment") != environment
            or not claims.get("sub")
            or not isinstance(claims.get("email"), str)
            or not claims["email"]
            or isinstance(expiry, bool)
            or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry)
            or expiry <= time.time()
        ):
            abort(401)
    except Exception:
        # Never include a token or authentication-library error in the response.
        abort(401)

    # Use a separate transaction so no shared service helper can accidentally
    # flush writes. PostgreSQL enforces read-only access even for an admin user.
    if db.engine.dialect.name != "postgresql":
        abort(503)
    g.readonly_connection = db.engine.connect()
    g.readonly_transaction = g.readonly_connection.begin()
    g.readonly_connection.execute(text("SET TRANSACTION READ ONLY"))
    g.readonly_session = Session(bind=g.readonly_connection, autoflush=False)
    user = g.readonly_session.query(User).filter(User.email == claims["email"]).one_or_none()
    if user is None or not user.active:
        abort(403)
    # Reuse the existing active account without creating users, changing roles,
    # issuing management tokens or calling the normal login endpoint.
    g.current_user = user


@mod.teardown_request
def close_transaction(_error):
    session = g.pop("readonly_session", None)
    if session is not None:
        session.close()
    transaction = g.pop("readonly_transaction", None)
    if transaction is not None and transaction.is_active:
        transaction.rollback()
    connection = g.pop("readonly_connection", None)
    if connection is not None:
        connection.close()


@mod.after_request
def prevent_caching(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@mod.route("/readonly/session")
def session():
    if request.args:
        abort(400)
    return jsonify(email=g.current_user.email, readOnly=True)


@mod.route("/readonly/certificates")
def certificates():
    if set(request.args) - {"page", "count", "query"}:
        abort(400)
    if any(len(request.args.getlist(key)) != 1 for key in request.args):
        abort(400)
    try:
        page = int(request.args.get("page", "1"))
        count = int(request.args.get("count", "25"))
    except ValueError:
        abort(400)
    search = request.args.get("query", "").strip()
    if not 1 <= page <= 10000 or not 1 <= count <= 100 or len(search) > 253:
        abort(400)
    cutoff = arrow.utcnow().shift(
        months=current_app.config.get("HIDE_EXPIRED_CERTS_AFTER_MONTHS", -1)
    )
    query = g.readonly_session.query(Certificate).filter(Certificate.not_after > cutoff)
    if search:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(Certificate.cn.ilike("%" + escaped + "%", escape="\\"))
    total = query.count()
    items = query.order_by(Certificate.id.desc()).offset((page - 1) * count).limit(count)
    return jsonify(total=total, items=[metadata(item) for item in items])


@mod.route("/readonly/certificates/<int:certificate_id>")
def certificate(certificate_id):
    if request.args:
        abort(400)
    item = g.readonly_session.query(Certificate).filter(Certificate.id == certificate_id).first()
    if item is None:
        abort(404)
    return jsonify(metadata(item))


@mod.route("/readonly/<path:unused>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def unsupported(unused):
    abort(404)
