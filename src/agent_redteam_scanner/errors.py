"""Structured errors."""


class ScannerError(Exception):
    """Base error for the scanner."""


class UnknownAgentError(ScannerError):
    """Raised when a target agent name is not known."""


class InvalidPayloadError(ScannerError):
    """Raised when a payload is malformed."""
