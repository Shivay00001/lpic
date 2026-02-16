"""
Domain-specific exceptions for LPIC.
All exceptions are explicit and carry meaningful context.
"""


class LPICError(Exception):
    """Base exception for all LPIC errors."""
    pass


class IdentityError(LPICError):
    """Base exception for identity-related errors."""
    pass


class KeypairError(IdentityError):
    """Raised when keypair operations fail."""
    pass


class SignatureError(IdentityError):
    """Raised when signature validation fails."""
    pass


class IdentityNotFoundError(IdentityError):
    """Raised when an identity does not exist."""
    pass


class IdentityAlreadyExistsError(IdentityError):
    """Raised when attempting to create a duplicate identity."""
    pass


class PolicyError(LPICError):
    """Base exception for policy-related errors."""
    pass


class InvalidPolicyError(PolicyError):
    """Raised when a policy fails validation."""
    pass


class PolicyEvaluationError(PolicyError):
    """Raised when policy evaluation fails."""
    pass


class ConditionError(PolicyError):
    """Raised when a condition cannot be evaluated."""
    pass


class AuditError(LPICError):
    """Base exception for audit-related errors."""
    pass


class AuditIntegrityError(AuditError):
    """Raised when audit log integrity is compromised."""
    pass


class AuditChainBrokenError(AuditIntegrityError):
    """Raised when the audit hash chain is broken."""
    pass


class DatabaseError(LPICError):
    """Base exception for database-related errors."""
    pass


class SchemaError(DatabaseError):
    """Raised when database schema operations fail."""
    pass


class MigrationError(DatabaseError):
    """Raised when database migrations fail."""
    pass


class InvariantViolationError(LPICError):
    """Raised when a core security invariant is violated."""
    pass


class RequestValidationError(LPICError):
    """Raised when a request fails validation."""
    pass


class UnsignedRequestError(RequestValidationError):
    """Raised when a request lacks a signature."""
    pass


class InvalidRequestError(RequestValidationError):
    """Raised when a request is malformed."""
    pass
