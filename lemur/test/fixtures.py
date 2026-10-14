"""Real external fixtures used by the Lemur sandbox task suite."""

import copy
import time
from types import SimpleNamespace

import arrow
import botocore
from flask import current_app, g
from flask_principal import Identity, identity_changed

from lemur import database
from lemur.certificates import service as certificate_service
from lemur.certificates.models import Certificate
from lemur.certificates.schemas import CertificateInputSchema
from lemur.destinations import service as destination_service
from lemur.endpoints import service as endpoint_service
from lemur.endpoints.models import Endpoint
from lemur.plugins.base import plugins
from lemur.plugins.lemur_aws import acm, elb, iam
from lemur.plugins.utils import get_plugin_option, set_plugin_option
from lemur.sources import service as source_service
from lemur.users import service as user_service
from lemur.authorities import service as authority_service

TEST_CERTIFICATE_PREFIX = "lemur-test-run-"
AWS_CERTIFICATE_PROPAGATION_ATTEMPTS = 12
AWS_CERTIFICATE_PROPAGATION_DELAY_SECONDS = 5
TEST_CERTIFICATE_ROLES = ("primary", "sni")


def _options(plugin_name, configured):
    plugin = plugins.get(plugin_name)
    if not plugin:
        raise RuntimeError("Required plugin is not installed: {}".format(plugin_name))
    options = copy.deepcopy(plugin.options)
    for name, value in configured.items():
        if not any(option["name"] == name for option in options):
            raise RuntimeError(
                "Unknown option {!r} for plugin {!r}".format(name, plugin_name)
            )
        set_plugin_option(name, value, options)
    missing = [
        option["name"]
        for option in options
        if option.get("required") and get_plugin_option(option["name"], options) is None
    ]
    if missing:
        raise RuntimeError(
            "Missing required options for {}: {}".format(
                plugin_name, ", ".join(sorted(missing))
            )
        )
    return options


def _create_destinations():
    configured = current_app.config.get("LEMUR_TEST_DESTINATIONS", [])
    if not configured:
        raise RuntimeError("LEMUR_TEST_DESTINATIONS must not be empty")
    destinations = []
    for item in configured:
        destinations.append(
            destination_service.create(
                label=item["label"],
                plugin_name=item["plugin_name"],
                options=_options(item["plugin_name"], item.get("options", {})),
                description=item.get("description", "Lemur sandbox test fixture"),
            )
        )
    return destinations


def _create_sources():
    configured = current_app.config.get("LEMUR_TEST_SOURCES", [])
    if not configured:
        raise RuntimeError("LEMUR_TEST_SOURCES must not be empty")
    sources = []
    for item in configured:
        existing = source_service.get_by_label(item["label"])
        if existing:
            existing.plugin_name = item["plugin_name"]
            existing.options = _options(item["plugin_name"], item.get("options", {}))
            sources.append(database.update(existing))
            continue
        sources.append(
            source_service.create(
                label=item["label"],
                plugin_name=item["plugin_name"],
                options=_options(item["plugin_name"], item.get("options", {})),
                description=item.get("description", "Lemur sandbox test fixture"),
            )
        )
    return sources


def _issue_test_certificate(run_id, destinations, role="primary"):
    authority = authority_service.get_by_name("TestCA")
    user = user_service.get_by_username("lemur-test")
    g.current_user = user
    identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
    base_common_name = current_app.config.get(
        "LEMUR_TEST_COMMON_NAME", "lemur-test.sandbox.staging.dog"
    )
    common_name = (
        base_common_name
        if role == "primary"
        else "{}.{}".format(role, base_common_name)
    )
    data, errors = CertificateInputSchema().load(
        {
            "name": "{}{}-{}".format(TEST_CERTIFICATE_PREFIX, run_id[:12], role),
            "commonName": common_name,
            "owner": user.email,
            "authority": {"id": authority.id},
            "description": "Certificate created by the Lemur sandbox task suite",
            "validityStart": arrow.utcnow().shift(minutes=-5).isoformat(),
            "validityEnd": arrow.utcnow().shift(days=1).isoformat(),
            "keyType": "RSA2048",
            "rotation": True,
            "notify": True,
            "destinations": [{"id": destination.id} for destination in destinations],
            "extensions": {
                "subAltNames": {
                    "names": [{"nameType": "DNSName", "value": common_name}]
                }
            },
        }
    )
    if errors:
        raise RuntimeError("Unable to create test certificate: {}".format(errors))
    data["creator"] = user
    return certificate_service.create(**data)


def _iam_certificate_arn(certificate):
    destination = next(
        (
            destination
            for destination in certificate.destinations
            if destination.plugin_name == "aws-destination"
        ),
        None,
    )
    if not destination:
        raise RuntimeError("Test certificate requires an aws-destination")
    account = get_plugin_option("accountNumber", destination.options)
    path = (get_plugin_option("path", destination.options) or "").strip("/")
    return iam.create_arn_from_cert(
        account,
        current_app.config.get("LEMUR_AWS_PARTITION", "aws"),
        certificate.name,
        path,
    )


def _set_endpoint_certificate_once(fixture, certificate_arn):
    account = current_app.config["LEMUR_TEST_AWS_ACCOUNT"]
    region = current_app.config.get("LEMUR_TEST_AWS_REGION", "us-east-1")
    if fixture["type"] == "elb":
        return elb.attach_certificate(
            fixture["name"],
            fixture["port"],
            certificate_arn,
            account_number=account,
            region=region,
        )
    if fixture["type"] in ("alb", "nlb"):
        listener = elb.get_listener_arn_from_endpoint(
            fixture["name"],
            fixture["port"],
            account_number=account,
            region=region,
        )
        return elb.attach_certificate_v2(
            listener,
            fixture["port"],
            [{"CertificateArn": certificate_arn}],
            account_number=account,
            region=region,
        )
    raise RuntimeError("Unknown AWS endpoint fixture type: {}".format(fixture["type"]))


def _set_endpoint_certificate(fixture, certificate_arn):
    for attempt in range(AWS_CERTIFICATE_PROPAGATION_ATTEMPTS):
        try:
            return _set_endpoint_certificate_once(fixture, certificate_arn)
        except botocore.exceptions.ClientError as error:
            is_propagating = error.response["Error"]["Code"] == "CertificateNotFound"
            if (
                not is_propagating
                or attempt == AWS_CERTIFICATE_PROPAGATION_ATTEMPTS - 1
            ):
                raise
            time.sleep(AWS_CERTIFICATE_PROPAGATION_DELAY_SECONDS)


def _add_endpoint_sni_certificate_once(fixture, certificate_arn):
    if fixture["type"] not in ("alb", "nlb"):
        raise RuntimeError(
            "AWS endpoint fixture type {} does not support SNI".format(fixture["type"])
        )
    account = current_app.config["LEMUR_TEST_AWS_ACCOUNT"]
    region = current_app.config.get("LEMUR_TEST_AWS_REGION", "us-east-1")
    listener = elb.get_listener_arn_from_endpoint(
        fixture["name"],
        fixture["port"],
        account_number=account,
        region=region,
    )
    return elb.add_listener_certificates_v2(
        listener,
        [{"CertificateArn": certificate_arn}],
        account_number=account,
        region=region,
    )


def _add_endpoint_sni_certificate(fixture, certificate_arn):
    for attempt in range(AWS_CERTIFICATE_PROPAGATION_ATTEMPTS):
        try:
            return _add_endpoint_sni_certificate_once(fixture, certificate_arn)
        except botocore.exceptions.ClientError as error:
            is_propagating = error.response["Error"]["Code"] == "CertificateNotFound"
            if (
                not is_propagating
                or attempt == AWS_CERTIFICATE_PROPAGATION_ATTEMPTS - 1
            ):
                raise
            time.sleep(AWS_CERTIFICATE_PROPAGATION_DELAY_SECONDS)


def _baseline_certificate_arn(fixture):
    configured_arn = fixture.get("baseline_certificate_arn")
    if configured_arn:
        return configured_arn
    return iam.create_arn_from_cert(
        current_app.config["LEMUR_TEST_AWS_ACCOUNT"],
        current_app.config.get("LEMUR_AWS_PARTITION", "aws"),
        fixture.get("baseline_certificate_name", "lemur-test-baseline"),
        fixture.get("baseline_certificate_path", "/lemur-test/").strip("/"),
    )


def prepare(run_id):
    """Create DB fixtures and attach primary and SNI certs to RDNA fixtures."""
    destinations = _create_destinations()
    sources = _create_sources()
    certificates = {
        role: _issue_test_certificate(run_id, destinations, role=role)
        for role in TEST_CERTIFICATE_ROLES
    }
    certificate_arns = {
        role: _iam_certificate_arn(certificate)
        for role, certificate in certificates.items()
    }
    state = {
        "certificate_ids": {
            role: certificate.id for role, certificate in certificates.items()
        },
        "source_labels": [source.label for source in sources],
        "coa_paths": {},
    }
    database.db.session.remove()
    endpoints = current_app.config.get("LEMUR_TEST_AWS_ENDPOINTS", [])
    if not endpoints:
        raise RuntimeError("LEMUR_TEST_AWS_ENDPOINTS must not be empty")
    for fixture in endpoints:
        _set_endpoint_certificate(fixture, certificate_arns["primary"])
        _add_endpoint_sni_certificate(fixture, certificate_arns["sni"])
    return state


def _replacement_chain(certificate):
    chain = [certificate]
    while chain[-1].replaced:
        if len(chain[-1].replaced) != 1:
            raise RuntimeError(
                "certificate {} has {} direct replacements, expected one".format(
                    chain[-1].id, len(chain[-1].replaced)
                )
            )
        chain.append(chain[-1].replaced[0])
    return chain


def _fingerprint(body):
    return acm.certificate_fingerprint(body).hex()


def _aws_destination(certificate):
    destination = next(
        (
            item
            for item in certificate.destinations
            if item.plugin_name == "aws-destination"
        ),
        None,
    )
    if not destination:
        raise RuntimeError("Test certificate requires an aws-destination")
    return destination


def _certificate_arn(certificate):
    destination = _aws_destination(certificate)
    account = get_plugin_option("accountNumber", destination.options)
    path = (get_plugin_option("path", destination.options) or "").strip("/")
    return iam.create_arn_from_cert(
        account,
        current_app.config.get("LEMUR_AWS_PARTITION", "aws"),
        certificate.name,
        path,
    )


def _listener_certificates(fixture):
    account = current_app.config["LEMUR_TEST_AWS_ACCOUNT"]
    region = current_app.config.get("LEMUR_TEST_AWS_REGION", "us-east-1")
    listener = elb.get_listener_arn_from_endpoint(
        fixture["name"],
        fixture["port"],
        account_number=account,
        region=region,
    )
    response = elb.describe_listener_certificates_v2(
        account_number=account,
        region=region,
        ListenerArn=listener,
    )
    return listener, response.get("Certificates", [])


def _coa_objects(source_label):
    source = source_service.get_by_label(source_label)
    if not source:
        raise RuntimeError("COA source {} does not exist".format(source_label))
    plugin = plugins.get(source.plugin_name)
    if not hasattr(plugin, "fetch_certificates_from_paths"):
        raise RuntimeError("COA source does not expose certificate discovery")
    return plugin.fetch_certificates_from_paths(source.options)


def _verify_remote_state(state, chains, failures):
    account = current_app.config["LEMUR_TEST_AWS_ACCOUNT"]
    region = current_app.config.get("LEMUR_TEST_AWS_REGION", "us-east-1")
    latest = {role: chain[-1] for role, chain in chains.items()}

    for role, certificate in latest.items():
        try:
            remote = iam.get_certificate(certificate.name, account_number=account)
        except botocore.exceptions.ClientError:
            remote = None
        if not remote or _fingerprint(remote["CertificateBody"]) != _fingerprint(
            certificate.body
        ):
            failures.append(
                "latest {} certificate is missing from RDNA IAM".format(role)
            )

    imported = acm.get_imported_certificates(
        account_number=account,
        region=region,
    )
    imported_fingerprints = {_fingerprint(item["body"]) for item in imported}
    for role, certificate in latest.items():
        if _fingerprint(certificate.body) not in imported_fingerprints:
            failures.append(
                "latest {} certificate is missing from RDNA ACM".format(role)
            )

    coa_label = current_app.config.get("LEMUR_TEST_COA_SOURCE", "lemur-test-coa")
    allowed_prefix = current_app.config.get("LEMUR_TEST_ALLOWED_COA_PATH_PREFIX")
    coa_objects = _coa_objects(coa_label)
    remote_by_fingerprint = {
        _fingerprint(item.certificate): item.vault_path for item in coa_objects
    }
    for role, certificate in latest.items():
        fingerprint = _fingerprint(certificate.body)
        path = remote_by_fingerprint.get(fingerprint)
        if not path:
            failures.append(
                "latest {} certificate is missing from staging COA Vault".format(role)
            )
            continue
        if allowed_prefix and not path.startswith(allowed_prefix.rstrip("/") + "/"):
            failures.append(
                "COA path {} is outside the allowed test prefix".format(path)
            )
        previous_path = state["coa_paths"].get(role)
        if previous_path and path != previous_path:
            failures.append(
                "COA path changed across rotations for {}: {} to {}".format(
                    role, previous_path, path
                )
            )
        state["coa_paths"][role] = path

        old_fingerprints = {_fingerprint(old.body) for old in chains[role][:-1]}
        if old_fingerprints.intersection(remote_by_fingerprint):
            failures.append(
                "staging COA Vault still exposes an older {} generation".format(role)
            )


def verify_generation(state, generation):
    """Verify one complete rotation generation in DB, RDNA, and staging COA."""
    failures = []
    for label in state["source_labels"]:
        source = source_service.get_by_label(label)
        if not source or not source.last_run:
            failures.append("source {} was not synced".format(label))

    chains = {}
    for role, certificate_id in state["certificate_ids"].items():
        certificate = certificate_service.get(certificate_id)
        try:
            chain = _replacement_chain(certificate)
        except RuntimeError as error:
            failures.append(str(error))
            continue
        chains[role] = chain
        if len(chain) != generation + 1:
            failures.append(
                "{} certificate has {} replacements, expected {}".format(
                    role, len(chain) - 1, generation
                )
            )

    expected_endpoints = current_app.config.get("LEMUR_TEST_EXPECTED_ENDPOINTS", [])
    for expected in expected_endpoints:
        endpoint = endpoint_service.get_by_name_and_source(
            expected["name"], expected["source"]
        )
        if not endpoint:
            failures.append(
                "endpoint {} was not discovered from {}".format(
                    expected["name"], expected["source"]
                )
            )
        elif expected.get("rotated") and len(chains) == len(TEST_CERTIFICATE_ROLES):
            expected_primary = chains["primary"][-1]
            expected_sni = chains["sni"][-1]
            if (
                not endpoint.primary_certificate
                or endpoint.primary_certificate.id != expected_primary.id
            ):
                failures.append(
                    "endpoint {} was not rotated to primary generation {}".format(
                        expected["name"], generation
                    )
                )
            sni_ids = {item.id for item in endpoint.sni_certificates}
            if expected_sni.id not in sni_ids:
                failures.append(
                    "endpoint {} was not rotated to SNI generation {}".format(
                        expected["name"], generation
                    )
                )
            old_ids = {
                item.id for role in TEST_CERTIFICATE_ROLES for item in chains[role][:-1]
            }
            if old_ids.intersection({item.id for item in endpoint.certificates}):
                failures.append(
                    "endpoint {} still references an older generation".format(
                        expected["name"]
                    )
                )

            _, listener_certificates = _listener_certificates(expected)
            remote_primary = {
                item["CertificateArn"]
                for item in listener_certificates
                if item.get("IsDefault", True)
            }
            remote_sni = {
                item["CertificateArn"]
                for item in listener_certificates
                if not item.get("IsDefault", True)
            }
            if _certificate_arn(expected_primary) not in remote_primary:
                failures.append(
                    "RDNA listener does not use primary generation {}".format(
                        generation
                    )
                )
            if _certificate_arn(expected_sni) not in remote_sni:
                failures.append(
                    "RDNA listener does not use SNI generation {}".format(generation)
                )
            previous_arns = {
                _certificate_arn(item)
                for role in TEST_CERTIFICATE_ROLES
                for item in chains[role][:-1]
            }
            if previous_arns.intersection(remote_primary | remote_sni):
                failures.append(
                    "RDNA listener still uses an older certificate generation"
                )

    minimum_endpoints = current_app.config.get("LEMUR_TEST_MIN_ENDPOINTS_BY_SOURCE", {})
    for source_label, minimum in minimum_endpoints.items():
        discovered = Endpoint.query.filter(
            Endpoint.source.has(label=source_label)
        ).count()
        if discovered < minimum:
            failures.append(
                "source {} discovered {} endpoints, expected at least {}".format(
                    source_label, discovered, minimum
                )
            )

    if len(chains) == len(TEST_CERTIFICATE_ROLES):
        coa_label = current_app.config.get("LEMUR_TEST_COA_SOURCE", "lemur-test-coa")
        coa_endpoints = Endpoint.query.filter(
            Endpoint.source.has(label=coa_label)
        ).all()
        coa_certificate_ids = {
            endpoint.primary_certificate.id
            for endpoint in coa_endpoints
            if endpoint.primary_certificate
        }
        for role, chain in chains.items():
            if chain[-1].id not in coa_certificate_ids:
                failures.append(
                    "COA endpoint does not reference {} generation {}".format(
                        role, generation
                    )
                )
        _verify_remote_state(state, chains, failures)

    if failures:
        raise RuntimeError("; ".join(failures))
    return {
        "generation": generation,
        "sources_synced": len(state["source_labels"]),
        "endpoints_verified": len(expected_endpoints) + sum(minimum_endpoints.values()),
        "certificate_ids": {role: chain[-1].id for role, chain in chains.items()},
        "coa_paths": dict(state["coa_paths"]),
    }


def verify(state):
    """Verify the configured final rotation generation."""
    return verify_generation(
        state,
        current_app.config.get("LEMUR_TEST_ROTATION_GENERATIONS", 2),
    )


def _run_certificates(state):
    roots = []
    if state:
        for certificate_id in state.get("certificate_ids", {}).values():
            certificate = certificate_service.get(certificate_id)
            if certificate:
                roots.append(certificate)
    roots.extend(
        Certificate.query.filter(
            Certificate.name.startswith(TEST_CERTIFICATE_PREFIX)
        ).all()
    )

    certificates = []
    pending = list(roots)
    seen = set()
    while pending:
        certificate = pending.pop()
        if certificate.id in seen:
            continue
        seen.add(certificate.id)
        certificates.append(certificate)
        pending.extend(certificate.replaced)
    return certificates


def _detach_run_certificates(fixture, certificates):
    if fixture["type"] not in ("alb", "nlb"):
        return
    account = current_app.config["LEMUR_TEST_AWS_ACCOUNT"]
    region = current_app.config.get("LEMUR_TEST_AWS_REGION", "us-east-1")
    listener, listener_certificates = _listener_certificates(fixture)
    run_arns = {_certificate_arn(certificate) for certificate in certificates}
    attached_sni = [
        {"CertificateArn": item["CertificateArn"]}
        for item in listener_certificates
        if not item.get("IsDefault", True) and item["CertificateArn"] in run_arns
    ]
    if attached_sni:
        elb.remove_listener_certificates_v2(
            account_number=account,
            region=region,
            listener_arn=listener,
            certificates=attached_sni,
        )


def _remote_cleanup_failures(certificates):
    failures = []
    account = current_app.config["LEMUR_TEST_AWS_ACCOUNT"]
    region = current_app.config.get("LEMUR_TEST_AWS_REGION", "us-east-1")
    imported = acm.get_imported_certificates(
        account_number=account,
        region=region,
    )
    imported_fingerprints = {_fingerprint(item["body"]) for item in imported}
    for certificate in certificates:
        try:
            remote = iam.get_certificate(certificate.name, account_number=account)
        except botocore.exceptions.ClientError:
            remote = None
        if remote:
            failures.append("{} remains in RDNA IAM".format(certificate.name))
        if _fingerprint(certificate.body) in imported_fingerprints:
            failures.append("{} remains in RDNA ACM".format(certificate.name))
    return failures


def cleanup(state=None):
    """Restore persistent endpoints and remove certificates created by the suite."""
    cleanup_errors = []

    run_certificates = _run_certificates(state)
    for fixture in current_app.config.get("LEMUR_TEST_AWS_ENDPOINTS", []):
        try:
            _set_endpoint_certificate(fixture, _baseline_certificate_arn(fixture))
            _detach_run_certificates(fixture, run_certificates)
        except Exception as error:
            cleanup_errors.append("restore {}: {!r}".format(fixture["name"], error))

    cleanup_targets = []
    for certificate in run_certificates:
        cleanable_certificate = SimpleNamespace(
            name=certificate.name,
            body=certificate.body,
        )
        for destination in list(certificate.destinations):
            plugin = plugins.get(destination.plugin_name)
            if not hasattr(plugin, "clean"):
                continue
            cleanup_targets.append(
                (
                    cleanable_certificate,
                    plugin,
                    copy.deepcopy(destination.options),
                    destination.label,
                )
            )

    database.db.session.remove()
    for certificate, plugin, options, destination_label in cleanup_targets:
        try:
            for attempt in range(AWS_CERTIFICATE_PROPAGATION_ATTEMPTS):
                try:
                    plugin.clean(certificate=certificate, options=options)
                    break
                except botocore.exceptions.ClientError as error:
                    is_propagating = error.response["Error"]["Code"] == "DeleteConflict"
                    if (
                        not is_propagating
                        or attempt == AWS_CERTIFICATE_PROPAGATION_ATTEMPTS - 1
                    ):
                        raise
                    time.sleep(AWS_CERTIFICATE_PROPAGATION_DELAY_SECONDS)
        except Exception as error:
            cleanup_errors.append(
                "clean {} from {}: {!r}".format(
                    certificate.name, destination_label, error
                )
            )
    for attempt in range(AWS_CERTIFICATE_PROPAGATION_ATTEMPTS):
        remote_failures = _remote_cleanup_failures(run_certificates)
        if not remote_failures:
            break
        if attempt == AWS_CERTIFICATE_PROPAGATION_ATTEMPTS - 1:
            cleanup_errors.extend(remote_failures)
            break
        time.sleep(AWS_CERTIFICATE_PROPAGATION_DELAY_SECONDS)
    if cleanup_errors:
        raise RuntimeError("; ".join(cleanup_errors))
