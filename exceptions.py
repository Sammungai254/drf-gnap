"""Custom exceptions for drf-gnap."""


class GNAPError(Exception):
    """Base class for all drf-gnap errors."""


class GNAPConfigError(GNAPError):
    """Raised when GNAP settings are missing or invalid."""


class GNAPGrantError(GNAPError):
    """Raised when the Authorization Server returns an error during grant negotiation."""

    def __init__(self, message: str, error_code: str | None = None, status_code: int | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.status_code = status_code


class GNAPTokenError(GNAPError):
    """Raised when an access token is invalid, expired, or cannot be obtained."""


class GNAPSignatureError(GNAPError):
    """Raised when an HTTP Message Signature (RFC 9421) cannot be created or verified."""


class GNAPContinuationError(GNAPError):
    """Raised during GNAP grant continuation flow failures."""


class OpenPaymentsError(GNAPError):
    """Raised for Open Payments-specific errors (Rafiki / Interledger)."""