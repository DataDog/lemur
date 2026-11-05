from lemur.tests.factories import CertificateFactory, DestinationFactory
from lemur.logs.models import Log
from flask import g


def test_update_destinations_no_sibling_propagation(session, destination_plugin):
    """Adding a destination to one certificate must not cause other certificates
    that share an existing destination to gain the newly-added destination.
    """
    # Shared existing destination
    shared = DestinationFactory()

    cert_a = CertificateFactory()
    cert_b = CertificateFactory()

    # Attach both certs to the shared destination
    cert_a.destinations.append(shared)
    cert_b.destinations.append(shared)
    session.flush()

    # New destination to be added only to cert_a
    new_dest = DestinationFactory()
    session.flush()

    # Append new_dest to cert_a; the SQLAlchemy 'append' event listener should
    # act only on the target certificate (cert_a) and must not alter cert_b.
    cert_a.destinations.append(new_dest)
    session.flush()

    assert new_dest in cert_a.destinations
    assert new_dest not in cert_b.destinations


def test_update_destinations_creates_log_entry_for_user(session, logged_in_user, destination_plugin):
    """When a user-triggered destination add occurs (within a request context)
    we should create a Log row so the change is visible via /api/1/logs.
    """
    # The logged_in_user fixture sets g.current_user inside a request context.
    assert hasattr(g, "current_user")

    cert = CertificateFactory()
    dest = DestinationFactory()
    session.flush()

    # Append will trigger update_destinations and (when g.current_user is present)
    # create a Log entry via log_service.create
    cert.destinations.append(dest)
    session.flush()

    # Verify a Log row was created for this certificate
    logs = session.query(Log).filter(Log.certificate_id == cert.id).all()
    assert len(logs) >= 1
    # Ensure the log_type is one of the update/create types
    assert any(log.log_type in ("update_cert", "create_cert") for log in logs)
