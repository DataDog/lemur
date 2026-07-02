from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional


@dataclass
class ValidationStatus:
    status: Literal["VALID", "EXPIRING_SOON", "MISSING"]
    expiry: Optional[datetime] = None


@dataclass
class DNSRecord:
    name: str   # e.g. "_dv.ap3.prod.dog"
    value: str  # e.g. "<token>.dcv.digicert.com"


class DCVAPIError(Exception):
    def __init__(self, domain: str, ca: str, reason: str):
        self.domain = domain
        self.ca = ca
        self.reason = reason
        super().__init__(f"DCV API error for {domain} ({ca}): {reason}")


class DCVPropagationTimeout(Exception):
    def __init__(self, domain: str, record_name: str):
        self.domain = domain
        self.record_name = record_name
        super().__init__(f"DNS propagation timeout for {record_name}")


class DCVDomainNotRegistered(Exception):
    def __init__(self, domain: str):
        self.domain = domain
        super().__init__(
            f"Domain {domain} not registered with CA. "
            "Call register_domain() first."
        )


class DCVRegistrationError(Exception):
    def __init__(self, domain: str, reason: str):
        self.domain = domain
        self.reason = reason
        super().__init__(f"DCV registration failed for {domain}: {reason}")


class DCVProvider(ABC):
    @abstractmethod
    def check_validation(self, domain: str, window_days: Optional[int] = None) -> ValidationStatus:
        """Return VALID, EXPIRING_SOON, or MISSING."""

    @abstractmethod
    def register_domain(self, domain: str) -> None:
        """New-DC pre-flight: add domain to CA + run full DCV flow.

        Idempotent — if domain is already VALID and not expiring within 30 days,
        returns immediately with no API calls.
        Raises DCVRegistrationError on registration/token failure.
        Raises DCVAPIError on API communication failure.
        Raises DCVPropagationTimeout if DNS propagation exceeds the configured timeout.
        """

    @abstractmethod
    def initiate_validation(self, domain: str) -> DNSRecord:
        """Get CNAME token for already-registered domain. Raises DCVDomainNotRegistered if not registered."""

    @abstractmethod
    def confirm_validation(self, domain: str) -> bool:
        """Tell the CA to re-check DNS. Returns True when confirmed."""
