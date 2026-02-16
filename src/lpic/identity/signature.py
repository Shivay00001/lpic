"""
Request signing and signature verification.
All requests must be cryptographically signed.
"""

from typing import Dict, Any, Optional
from cryptography.exceptions import InvalidSignature

from ..errors import SignatureError, UnsignedRequestError
from ..utils.canonical_json import canonicalize_bytes
from ..utils.hashing import hash_bytes
from .keypair import Keypair, load_public_key


class SignedRequest:
    """
    Represents a cryptographically signed request.
    """
    
    def __init__(
        self,
        identity_id: str,
        resource: str,
        action: str,
        context: Dict[str, Any],
        signature: bytes,
    ):
        """
        Initialize signed request.
        
        Args:
            identity_id: Identity making the request
            resource: Resource being accessed
            action: Action being performed
            context: Additional context
            signature: Ed25519 signature bytes
        """
        self.identity_id = identity_id
        self.resource = resource
        self.action = action
        self.context = context
        self.signature = signature
    
    def get_payload(self) -> Dict[str, Any]:
        """
        Get the signed payload (everything except signature).
        
        Returns:
            Payload dictionary
        """
        return {
            'identity_id': self.identity_id,
            'resource': self.resource,
            'action': self.action,
            'context': self.context,
        }
    
    def get_payload_bytes(self) -> bytes:
        """
        Get canonical bytes of the payload.
        
        Returns:
            Canonical JSON bytes
        """
        return canonicalize_bytes(self.get_payload())
    
    def get_request_hash(self) -> str:
        """
        Get hash of the entire request (including signature).
        
        Returns:
            Hex-encoded hash
        """
        full_request = {
            **self.get_payload(),
            'signature': self.signature.hex(),
        }
        return hash_bytes(canonicalize_bytes(full_request))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            **self.get_payload(),
            'signature': self.signature.hex(),
        }


def sign_request(
    keypair: Keypair,
    resource: str,
    action: str,
    context: Optional[Dict[str, Any]] = None,
) -> SignedRequest:
    """
    Sign a request using a keypair.
    
    Args:
        keypair: Keypair to sign with
        resource: Resource being accessed
        action: Action being performed
        context: Optional additional context
        
    Returns:
        SignedRequest object
    """
    if context is None:
        context = {}
    
    identity_id = keypair.get_identity_id()
    
    # Create payload
    payload = {
        'identity_id': identity_id,
        'resource': resource,
        'action': action,
        'context': context,
    }
    
    # Sign canonical payload
    payload_bytes = canonicalize_bytes(payload)
    signature = keypair.private_key.sign(payload_bytes)
    
    return SignedRequest(
        identity_id=identity_id,
        resource=resource,
        action=action,
        context=context,
        signature=signature,
    )


def verify_signature(request: SignedRequest, public_key_bytes: bytes) -> bool:
    """
    Verify request signature.
    
    Args:
        request: SignedRequest to verify
        public_key_bytes: Public key bytes
        
    Returns:
        True if signature is valid
        
    Raises:
        SignatureError: If verification fails
    """
    try:
        # Load public key
        public_key = load_public_key(public_key_bytes)
        
        # Get payload bytes
        payload_bytes = request.get_payload_bytes()
        
        # Verify signature
        public_key.verify(request.signature, payload_bytes)
        return True
        
    except InvalidSignature:
        raise SignatureError("Invalid signature")
    except Exception as e:
        raise SignatureError(f"Signature verification failed: {e}")


def parse_signed_request(request_dict: Dict[str, Any]) -> SignedRequest:
    """
    Parse a signed request from a dictionary.
    
    Args:
        request_dict: Dictionary containing request data
        
    Returns:
        SignedRequest object
        
    Raises:
        UnsignedRequestError: If request is not properly signed
    """
    # Validate required fields
    required = ['identity_id', 'resource', 'action', 'signature']
    for field in required:
        if field not in request_dict:
            raise UnsignedRequestError(f"Missing required field: {field}")
    
    # Parse signature
    try:
        signature = bytes.fromhex(request_dict['signature'])
    except ValueError as e:
        raise UnsignedRequestError(f"Invalid signature format: {e}")
    
    # Extract context
    context = request_dict.get('context', {})
    
    return SignedRequest(
        identity_id=request_dict['identity_id'],
        resource=request_dict['resource'],
        action=request_dict['action'],
        context=context,
        signature=signature,
    )
