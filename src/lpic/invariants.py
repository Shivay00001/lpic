"""
Runtime security invariant validation.
These checks ensure core security properties are maintained.
"""

from typing import Dict, Any

from .errors import InvariantViolationError
from .config import VALID_DECISIONS, VALID_ACTIONS, IDENTITY_ID_LENGTH
from .identity.signature import SignedRequest
from .audit.log_schema import AuditEntry


def validate_identity_binding(identity_id: str, public_key: bytes):
    """
    Validate that identity is properly bound to public key.
    
    Args:
        identity_id: Identity ID
        public_key: Public key bytes
        
    Raises:
        InvariantViolationError: If binding is invalid
    """
    from .utils.hashing import hash_bytes
    
    # Identity ID must be hash of public key
    expected_id = hash_bytes(public_key)
    if identity_id != expected_id:
        raise InvariantViolationError(
            f"Identity {identity_id} not properly bound to public key. "
            f"Expected {expected_id}"
        )


def validate_request_signature(request: SignedRequest, public_key: bytes):
    """
    Validate that request is properly signed.
    
    Args:
        request: Signed request
        public_key: Public key to verify with
        
    Raises:
        InvariantViolationError: If signature is invalid
    """
    from .identity.signature import verify_signature
    
    try:
        verify_signature(request, public_key)
    except Exception as e:
        raise InvariantViolationError(f"Request signature invalid: {e}")


def validate_decision(decision: str):
    """
    Validate that decision is one of the allowed values.
    
    Args:
        decision: Decision string
        
    Raises:
        InvariantViolationError: If decision is invalid
    """
    if decision not in VALID_DECISIONS:
        raise InvariantViolationError(f"Invalid decision: {decision}")


def validate_action(action: str):
    """
    Validate that action is one of the allowed values.
    
    Args:
        action: Action string
        
    Raises:
        InvariantViolationError: If action is invalid
    """
    if action not in VALID_ACTIONS:
        raise InvariantViolationError(f"Invalid action: {action}")


def validate_audit_entry(entry: AuditEntry, previous_hash: str):
    """
    Validate audit entry integrity.
    
    Args:
        entry: Audit entry
        previous_hash: Expected previous hash
        
    Raises:
        InvariantViolationError: If entry is invalid
    """
    from .utils.canonical_json import canonicalize_bytes
    from .utils.hashing import chain_hashes
    from .audit.log_schema import create_entry_payload
    
    # Validate previous hash
    if entry.previous_hash != previous_hash:
        raise InvariantViolationError(
            f"Audit entry {entry.entry_id} has incorrect previous_hash"
        )
    
    # Validate hash computation
    payload = create_entry_payload(
        request_hash=entry.request_hash,
        identity_id=entry.identity_id,
        resource=entry.resource,
        action=entry.action,
        decision=entry.decision,
        timestamp=entry.timestamp,
        context=entry.context,
    )
    
    payload_bytes = canonicalize_bytes(payload)
    expected_hash = chain_hashes(previous_hash, payload_bytes)
    
    if entry.entry_hash != expected_hash:
        raise InvariantViolationError(
            f"Audit entry {entry.entry_id} has incorrect entry_hash"
        )


def validate_no_implicit_allow(decision: str, matching_policies: list):
    """
    Validate that ALLOW decisions are explicit, not implicit.
    
    Args:
        decision: Decision made
        matching_policies: List of policies that matched
        
    Raises:
        InvariantViolationError: If ALLOW is implicit
    """
    if decision == "ALLOW" and not matching_policies:
        raise InvariantViolationError(
            "ALLOW decision without matching policies (implicit allow)"
        )


def validate_deterministic_evaluation(
    identity_id: str,
    resource: str,
    action: str,
    context: Dict[str, Any],
    decision1: str,
    decision2: str,
):
    """
    Validate that policy evaluation is deterministic.
    
    Args:
        identity_id: Identity ID
        resource: Resource
        action: Action
        context: Context
        decision1: First evaluation result
        decision2: Second evaluation result
        
    Raises:
        InvariantViolationError: If results differ
    """
    if decision1 != decision2:
        raise InvariantViolationError(
            f"Non-deterministic evaluation: same request produced {decision1} and {decision2}"
        )


def validate_policy_purity(conditions: Dict[str, Any]):
    """
    Validate that policy conditions have no side effects.
    This is a static check - actual purity is enforced by implementation.
    
    Args:
        conditions: Policy conditions
        
    Raises:
        InvariantViolationError: If conditions might have side effects
    """
    # Check for disallowed condition types
    disallowed = ['exec', 'eval', 'lambda', 'function']
    
    for key in conditions.keys():
        if key in disallowed:
            raise InvariantViolationError(
                f"Policy condition '{key}' may have side effects"
            )


def validate_identity_id_format(identity_id: str):
    """
    Validate identity ID format.
    
    Args:
        identity_id: Identity ID to validate
        
    Raises:
        InvariantViolationError: If format is invalid
    """
    if not isinstance(identity_id, str):
        raise InvariantViolationError("Identity ID must be a string")
    
    if len(identity_id) != IDENTITY_ID_LENGTH:
        raise InvariantViolationError(
            f"Identity ID must be {IDENTITY_ID_LENGTH} characters, got {len(identity_id)}"
        )
    
    # Must be valid hex
    try:
        int(identity_id, 16)
    except ValueError:
        raise InvariantViolationError("Identity ID must be valid hexadecimal")


def validate_request_hash_format(request_hash: str):
    """
    Validate request hash format.
    
    Args:
        request_hash: Request hash to validate
        
    Raises:
        InvariantViolationError: If format is invalid
    """
    if not isinstance(request_hash, str):
        raise InvariantViolationError("Request hash must be a string")
    
    if len(request_hash) != 64:
        raise InvariantViolationError(
            f"Request hash must be 64 characters, got {len(request_hash)}"
        )
    
    # Must be valid hex
    try:
        int(request_hash, 16)
    except ValueError:
        raise InvariantViolationError("Request hash must be valid hexadecimal")


def check_all_invariants(
    identity_id: str,
    public_key: bytes,
    request: SignedRequest,
    decision: str,
):
    """
    Check all applicable invariants for a request.
    
    Args:
        identity_id: Identity ID
        public_key: Public key
        request: Signed request
        decision: Authorization decision
        
    Raises:
        InvariantViolationError: If any invariant is violated
    """
    validate_identity_id_format(identity_id)
    validate_identity_binding(identity_id, public_key)
    validate_request_signature(request, public_key)
    validate_decision(decision)
    validate_action(request.action)
    validate_request_hash_format(request.get_request_hash())
