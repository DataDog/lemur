import re

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import NameOID
from flask import current_app
from marshmallow.exceptions import ValidationError

from lemur.auth.permissions import SensitiveDomainPermission
from lemur.common.utils import check_cert_signature, is_weekend
from lemur.plugins.base import plugins


def common_name(value):
    """If the common name could be a domain name, apply domain validation rules."""
    # Common name could be a domain name, or a human-readable name of the subject (often used in CA names or client
    # certificates). As a simple heuristic, we assume that human-readable names always include a space.
    # However, to avoid confusion for humans, we also don't count spaces at the beginning or end of the string.
    value = value.strip()
    if value and " " not in value:
        return sensitive_domain(value)


def sensitive_domain(domain):
    """
    Checks if user has the admin role, the domain does not match sensitive domains and allowed domain patterns.
    :param domain: domain name (str)
    :return:
    """
    if SensitiveDomainPermission().can():
        # User has permission, no need to check anything
        return

    allowlist = current_app.config.get("LEMUR_ALLOWED_DOMAINS", [])
    if allowlist and not any(re.match(pattern, domain) for pattern in allowlist):
        raise ValidationError(
            "Domain {0} does not match allowed domain patterns. "
            "Contact an administrator to issue the certificate.".format(domain)
        )

    # Avoid circular import.
    from lemur.domains import service as domain_service

    if domain_service.is_domain_sensitive(domain):
        raise ValidationError(
            "Domain {0} has been marked as sensitive. "
            "Contact an administrator to issue the certificate.".format(domain)
        )


def encoding(oid_encoding):
    """
    Determines if the specified oid type is valid.
    :param oid_encoding:
    :return:
    """
    valid_types = ["b64asn1", "string", "ia5string"]
    if oid_encoding.lower() not in [o_type.lower() for o_type in valid_types]:
        raise ValidationError(
            "Invalid Oid Encoding: {0} choose from {1}".format(
                oid_encoding, ",".join(valid_types)
            )
        )


def sub_alt_type(alt_type):
    """
    Determines if the specified subject alternate type is valid.
    :param alt_type:
    :return:
    """
    valid_types = [
        "DNSName",
        "IPAddress",
        "uniFormResourceIdentifier",
        "directoryName",
        "rfc822Name",
        "registrationID",
        "otherName",
        "x400Address",
        "EDIPartyName",
    ]
    if alt_type.lower() not in [a_type.lower() for a_type in valid_types]:
        raise ValidationError(
            "Invalid SubAltName Type: {0} choose from {1}".format(
                type, ",".join(valid_types)
            )
        )


def csr(data):
    """
    Determines if the CSR is valid and allowed.
    :param data:
    :return:
    """
    try:
        request = x509.load_pem_x509_csr(data.encode("utf-8"), default_backend())
    except Exception:
        raise ValidationError("CSR presented is not valid.")

    # Validate common name and SubjectAltNames
    try:
        for name in request.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            common_name(name.value)
    except ValueError as err:
        current_app.logger.info("Error parsing Subject from CSR: %s", err)
        raise ValidationError("Invalid Subject value in supplied CSR")

    try:
        alt_names = request.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )

        for name in alt_names.value.get_values_for_type(x509.DNSName):
            sensitive_domain(name)
    except x509.ExtensionNotFound:
        pass


def dates(data):
    if not data.get("validity_start") and data.get("validity_end"):
        raise ValidationError("If validity start is specified so must validity end.")

    if not data.get("validity_end") and data.get("validity_start"):
        raise ValidationError("If validity end is specified so must validity start.")

    if data.get("validity_start") and data.get("validity_end"):
        if not current_app.config.get("LEMUR_ALLOW_WEEKEND_EXPIRATION", True):
            if is_weekend(data.get("validity_end")):
                raise ValidationError("Validity end must not land on a weekend.")

        if not data["validity_start"] < data["validity_end"]:
            raise ValidationError("Validity start must be before validity end.")

        if data.get("authority"):
            if (
                data.get("validity_start").date()
                < data["authority"].authority_certificate.not_before.date()
            ):
                raise ValidationError(
                    "Validity start must not be before {0}".format(
                        data["authority"].authority_certificate.not_before
                    )
                )

            if (
                data.get("validity_end").date()
                > data["authority"].authority_certificate.not_after.date()
            ):
                raise ValidationError(
                    "Validity end must not be after {0}".format(
                        data["authority"].authority_certificate.not_after
                    )
                )

    return data


def verify_private_key_match(key, cert, error_class=ValidationError):
    """
    Checks that the supplied private key matches the certificate.

    :param cert: Parsed certificate
    :param key: Parsed private key
    :param error_class: Exception class to raise on error
    """
    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise error_class("Private key does not match certificate.")


def verify_cert_chain(certs, error_class=ValidationError):
    """
    Verifies that every certificate in the bundle is reachable from the leaf via
    signature relationships (a connected DAG rooted at certs[0]).

    This supports both linear chains (the common case) and non-linear bundles such
    as dual-chain cross-signed intermediates (e.g. Sectigo R46 signed by both
    USERTrust and AAA). See RFC 8446 section 4.4.2 for background on non-linear
    certificate messages.

    Algorithm:
      1. Start from the leaf (certs[0]).
      2. For each visited cert, find all certs in the bundle whose public key
         successfully verifies the visited cert's signature. Mark those as reached.
      3. Walk transitively until no new certs are reached.
      4. Any cert not reached from the leaf is rejected as orphaned.

    Certs whose issuer is not in the bundle are valid top-of-chain termination
    points (their parent is a root CA not included in the bundle).

    :param certs: List of parsed certificates; certs[0] must be the leaf.
    :param error_class: Exception class to raise on error.
    """
    if len(certs) < 2:
        return

    # Avoid circular import.
    from lemur.common import defaults

    # Build the set of certs reachable from the leaf by walking signature relationships.
    # Use indices to identify certs (avoids equality issues with x509 objects).
    reached = {0}  # leaf is always reached
    frontier = [0]

    while frontier:
        current_idx = frontier.pop()
        current_cert = certs[current_idx]

        for candidate_idx, candidate in enumerate(certs):
            if candidate_idx in reached:
                continue

            try:
                check_cert_signature(current_cert, candidate.public_key())
            except InvalidSignature:
                continue
            except UnsupportedAlgorithm as err:
                # Can't verify this pair — do NOT treat as a valid edge.
                # Falling through would let an unverifiable cert appear connected
                # and pull orphaned subgraphs into the accepted set.
                current_app.logger.warning("Skipping chain validation for pair: %s", err)
                continue

            # candidate's public key verified current_cert's signature,
            # so candidate is a valid issuer of current_cert.
            reached.add(candidate_idx)
            frontier.append(candidate_idx)

    # Every cert in the bundle must be reachable from the leaf.
    unreached = set(range(len(certs))) - reached
    if unreached:
        # Report the first unreachable cert for a clear error message.
        orphan_idx = min(unreached)
        raise error_class(
            "Incorrect chain certificate(s) provided: '%s' is not signed by any certificate in the chain"
            % (defaults.common_name(certs[orphan_idx]) or "Unknown")
        )

    # Enforce leaf-to-root ordering: each cert after the leaf (position i > 0)
    # must be an issuer of at least one cert that appears before it (position
    # j < i). This ensures the chain is presented in the order TLS clients
    # expect, while still allowing non-linear bundles where multiple issuers
    # can appear at different positions.
    for i in range(1, len(certs)):
        candidate = certs[i]
        signs_something_before = False
        for j in range(i):
            try:
                check_cert_signature(certs[j], candidate.public_key())
                signs_something_before = True
                break
            except (InvalidSignature, UnsupportedAlgorithm):
                continue

        if not signs_something_before:
            raise error_class(
                "Incorrect chain certificate(s) provided: "
                "chain is not in leaf-to-root order — '%s' (position %d) "
                "does not sign any preceding certificate"
                % (defaults.common_name(candidate) or "Unknown", i)
            )


def is_valid_owner(email):
    user_membership_provider = None
    if current_app.config.get("USER_MEMBERSHIP_PROVIDER") is not None:
        user_membership_provider = plugins.get(
            current_app.config.get("USER_MEMBERSHIP_PROVIDER")
        )
    if user_membership_provider is None:
        # nothing to check since USER_MEMBERSHIP_PROVIDER is not configured
        return True

    # expecting owner to be an existing team DL
    return user_membership_provider.does_group_exist(email)
