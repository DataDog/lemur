"""Real external fixtures used by the Lemur sandbox task suite."""

import copy

import arrow
from flask import current_app

from lemur import database
from lemur.certificates import service as certificate_service
from lemur.certificates.models import Certificate
from lemur.certificates.schemas import CertificateInputSchema
from lemur.destinations import service as destination_service
from lemur.endpoints import service as endpoint_service
from lemur.endpoints.models import Endpoint
from lemur.plugins.base import plugins
from lemur.plugins.lemur_aws import elb, iam
from lemur.plugins.utils import get_plugin_option, set_plugin_option
from lemur.sources import service as source_service
from lemur.users import service as user_service
from lemur.authorities import service as authority_service

TEST_CERTIFICATE_PREFIX = "lemur-test-"
SYNC_SOURCE_TASK = "lemur.common.celery.sync_source"


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


def _issue_test_certificate(run_id, destinations):
    authority = authority_service.get_by_name("TestCA")
    user = user_service.get_by_username("lemur-test")
    common_name = current_app.config.get(
        "LEMUR_TEST_COMMON_NAME", "lemur-test.sandbox.staging.dog"
    )
    data, errors = CertificateInputSchema().load(
        {
            "name": "{}{}".format(TEST_CERTIFICATE_PREFIX, run_id[:12]),
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


def _set_endpoint_certificate(fixture, certificate_arn):
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
    """Create DB fixtures and attach the run certificate to persistent AWS fixtures."""
    destinations = _create_destinations()
    sources = _create_sources()
    certificate = _issue_test_certificate(run_id, destinations)
    certificate_arn = _iam_certificate_arn(certificate)
    endpoints = current_app.config.get("LEMUR_TEST_AWS_ENDPOINTS", [])
    if not endpoints:
        raise RuntimeError("LEMUR_TEST_AWS_ENDPOINTS must not be empty")
    for fixture in endpoints:
        _set_endpoint_certificate(fixture, certificate_arn)
    return {
        "certificate_id": certificate.id,
        "source_labels": [source.label for source in sources],
    }


def after_task(task_name, state):
    """Prepare task-specific state after prerequisite tasks have completed."""
    rotation = current_app.config.get("LEMUR_TEST_CLOUDFRONT_ROTATION")
    if task_name != SYNC_SOURCE_TASK or not rotation:
        return

    old_certificate = certificate_service.get_by_name(rotation["old_certificate"])
    new_certificate = certificate_service.get_by_name(rotation["new_certificate"])
    if not old_certificate or not new_certificate:
        raise RuntimeError(
            "CloudFront certificates were not discovered from {}".format(
                rotation["source"]
            )
        )
    if old_certificate not in new_certificate.replaces:
        new_certificate.replaces.append(old_certificate)
        database.commit()
    state["cloudfront_old_certificate_id"] = old_certificate.id
    state["cloudfront_new_certificate_id"] = new_certificate.id


def verify(state):
    """Verify that task execution produced real discovery and rotation state."""
    failures = []
    for label in state["source_labels"]:
        source = source_service.get_by_label(label)
        if not source or not source.last_run:
            failures.append("source {} was not synced".format(label))

    certificate = certificate_service.get(state["certificate_id"])
    if not certificate.replaced:
        failures.append("test certificate was not reissued")

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

    rotation = current_app.config.get("LEMUR_TEST_CLOUDFRONT_ROTATION")
    if rotation:
        rotated = [
            endpoint
            for endpoint in endpoint_service.get_by_source(rotation["source"])
            if endpoint.primary_certificate
            and endpoint.primary_certificate.name == rotation["new_certificate"]
        ]
        if not rotated:
            failures.append("CloudFront fixture was not rotated")

    if failures:
        raise RuntimeError("; ".join(failures))
    return {
        "sources_synced": len(state["source_labels"]),
        "endpoints_verified": len(expected_endpoints) + sum(minimum_endpoints.values()),
        "replacement_ids": [item.id for item in certificate.replaced],
    }


def cleanup():
    """Restore persistent endpoints and remove certificates created by the suite."""
    cleanup_errors = []

    rotation = current_app.config.get("LEMUR_TEST_CLOUDFRONT_ROTATION")
    if rotation:
        source = source_service.get_by_label(rotation["source"])
        old_certificate = certificate_service.get_by_name(rotation["old_certificate"])
        if source and old_certificate:
            plugin = plugins.get(source.plugin_name)
            for endpoint in endpoint_service.get_by_source(source.label):
                if (
                    not endpoint.primary_certificate
                    or endpoint.primary_certificate.name
                    not in {
                        rotation["old_certificate"],
                        rotation["new_certificate"],
                    }
                ):
                    continue
                try:
                    plugin.update_endpoint(endpoint, old_certificate)
                except Exception as error:
                    cleanup_errors.append(
                        "restore CloudFront {}: {!r}".format(endpoint.name, error)
                    )

    for fixture in current_app.config.get("LEMUR_TEST_AWS_ENDPOINTS", []):
        try:
            _set_endpoint_certificate(fixture, _baseline_certificate_arn(fixture))
        except Exception as error:
            cleanup_errors.append("restore {}: {!r}".format(fixture["name"], error))

    certificates = Certificate.query.filter(
        Certificate.name.startswith(TEST_CERTIFICATE_PREFIX)
    ).all()
    for certificate in certificates:
        for destination in certificate.destinations:
            plugin = plugins.get(destination.plugin_name)
            if not hasattr(plugin, "clean"):
                continue
            try:
                plugin.clean(certificate=certificate, options=destination.options)
            except Exception as error:
                cleanup_errors.append(
                    "clean {} from {}: {!r}".format(
                        certificate.name, destination.label, error
                    )
                )
    if cleanup_errors:
        raise RuntimeError("; ".join(cleanup_errors))
