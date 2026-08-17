"""
.. module: lemur.exceptions
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""

from flask import current_app


class LemurException(Exception):
    def __init__(self, *args, **kwargs):
        current_app.logger.exception(self)


class DuplicateError(LemurException):
    def __init__(self, key):
        self.key = key

    def __str__(self):
        return repr("Duplicate found! Could not create: {0}".format(self.key))


class InvalidListener(LemurException):
    def __str__(self):
        return repr(
            "Invalid listener, ensure you select a certificate if you are using a secure protocol"
        )


class InvalidDistribution(LemurException):
    def __init__(self, field):
        self.field = field

    def __str__(self):
        return repr(
            "Invalid distribution {0}, must use IAM certificates".format(self.field)
        )


class AttrNotFound(LemurException):
    def __init__(self, field):
        self.field = field

    def __str__(self):
        return repr("The field '{0}' is not sortable or filterable".format(self.field))


class PendingCertificateTerminalError(Exception):
    """
    Base class for pending-certificate failures that retrying can never resolve.

    Terminal failures are configuration, DNS-delegation, or credential problems
    (e.g. no DNS provider configured for a domain, broken ACME CNAME delegation,
    or invalid ACME account credentials). Re-queueing these only re-runs the ACME
    order/challenge and burns the CA's rate limit (Let's Encrypt: 5 duplicate
    certificates / failed validations per week per domain), so they must fail fast
    and mark the pending certificate resolved instead of retrying.
    """


class ACMEAuthenticationError(PendingCertificateTerminalError):
    """The ACME CA rejected our credentials (upstream HTTP 401/403)."""


class NoDNSProviderError(PendingCertificateTerminalError):
    """No DNS provider is authoritative for the validation domain."""


class DNSChallengeSetupError(PendingCertificateTerminalError):
    """The DNS-01 challenge could not be set up (delegation/config problem)."""


class InvalidConfiguration(PendingCertificateTerminalError):
    pass


class InvalidAuthority(Exception):
    pass


class UnknownProvider(Exception):
    pass
