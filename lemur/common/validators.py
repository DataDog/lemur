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


def _is_issuer(issuer, child, issuer_pos, child_pos):
    """
    Return True if ``issuer`` is the issuer of ``child``: the names line up and
    issuer's public key verifies child's signature.

    The subject/issuer name check comes first so a certificate that merely
    reuses a signing key (but names a different subject) is not accepted as a
    valid issuer. That keeps the orphan check meaningful while still allowing
    cross-signed certs, which keep the same subject across their variants.
    """
    if issuer.subject != child.issuer:
        return False
    try:
        check_cert_signature(child, issuer.public_key())
        return True
    except InvalidSignature:
        return False
    except UnsupportedAlgorithm as err:
        # COMPAT: we cannot verify this signature algorithm (e.g. RSASSA-PSS),
        # so trust the presented order for the immediately-adjacent hop only.
        # Drop this once the algorithm is natively supported.
        # See: https://github.com/DataDog/lemur/pull/254#issuecomment-4265512236
        if issuer_pos == child_pos + 1:
            current_app.logger.warning(
                "Skipping chain validation for adjacent pair (unsupported algorithm): %s",
                err,
            )
            return True
        return False


def verify_cert_chain(certs, error_class=ValidationError):
    """
    Verify that a certificate bundle is a well-formed, leaf-first chain.

    Every certificate after the leaf (certs[0]) must be the issuer of at least
    one certificate that appears before it. By induction this guarantees the
    whole bundle chains back to the leaf, so it accepts linear chains and
    non-linear bundles alike (e.g. a dual cross-signed intermediate such as
    Sectigo R46 signed by both USERTrust and AAA, IR-50398), while rejecting
    orphaned certs and out-of-order bundles. See RFC 8446 section 4.4.2 for
    background on non-linear certificate messages.

    A certificate whose issuer is not in the bundle is a valid top-of-chain
    termination point (its parent is a root CA not included in the bundle).

    :param certs: List of parsed certificates, leaf first (see parse_cert_chain()).
    :param error_class: Exception class to raise on error.
    """
    # Avoid circular import.
    from lemur.common import defaults

    for i in range(1, len(certs)):
        candidate = certs[i]
        if not any(_is_issuer(candidate, certs[j], i, j) for j in range(i)):
            raise error_class(
                "Incorrect chain certificate(s) provided: '%s' (position %d) "
                "does not sign any preceding certificate. The chain must be in "
                "leaf-to-root order with every certificate connected to the leaf."
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
