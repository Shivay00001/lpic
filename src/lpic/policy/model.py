"""
Policy model and schema validation.
Policies are declarative and must be deterministic.
"""

from typing import Dict, Any, Optional
import json
import uuid

from ..config import VALID_DECISIONS, VALID_ACTIONS
from ..errors import InvalidPolicyError
from ..utils.time import now


class Policy:
    """
    Represents an authorization policy.
    """
    
    def __init__(
        self,
        policy_id: str,
        subject: str,
        resource: str,
        action: str,
        decision: str,
        conditions: Optional[Dict[str, Any]] = None,
        created_at: Optional[str] = None,
    ):
        """
        Initialize policy.
        
        Args:
            policy_id: Unique policy identifier
            subject: Identity ID or role
            resource: Resource identifier (supports wildcards)
            action: Action identifier
            decision: ALLOW, DENY, or REQUIRE_REVIEW
            conditions: Optional conditions for policy application
            created_at: Creation timestamp
        """
        # Validate decision
        if decision not in VALID_DECISIONS:
            raise InvalidPolicyError(f"Invalid decision: {decision}")
        
        # Validate action
        if action not in VALID_ACTIONS:
            raise InvalidPolicyError(f"Invalid action: {action}")
        
        self.policy_id = policy_id
        self.subject = subject
        self.resource = resource
        self.action = action
        self.decision = decision
        self.conditions = conditions or {}
        self.created_at = created_at or now()
    
    @classmethod
    def create(
        cls,
        subject: str,
        resource: str,
        action: str,
        decision: str,
        conditions: Optional[Dict[str, Any]] = None,
    ) -> 'Policy':
        """
        Create a new policy with generated ID.
        
        Args:
            subject: Identity ID or role
            resource: Resource identifier
            action: Action identifier
            decision: ALLOW, DENY, or REQUIRE_REVIEW
            conditions: Optional conditions
            
        Returns:
            Policy object
        """
        policy_id = str(uuid.uuid4())
        return cls(
            policy_id=policy_id,
            subject=subject,
            resource=resource,
            action=action,
            decision=decision,
            conditions=conditions,
        )
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Policy':
        """
        Create policy from dictionary.
        
        Args:
            data: Policy data
            
        Returns:
            Policy object
            
        Raises:
            InvalidPolicyError: If data is invalid
        """
        required = ['subject', 'resource', 'action', 'decision']
        for field in required:
            if field not in data:
                raise InvalidPolicyError(f"Missing required field: {field}")
        
        return cls(
            policy_id=data.get('policy_id', str(uuid.uuid4())),
            subject=data['subject'],
            resource=data['resource'],
            action=data['action'],
            decision=data['decision'],
            conditions=data.get('conditions'),
            created_at=data.get('created_at'),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary."""
        return {
            'policy_id': self.policy_id,
            'subject': self.subject,
            'resource': self.resource,
            'action': self.action,
            'decision': self.decision,
            'conditions': self.conditions,
            'created_at': self.created_at,
        }
    
    def matches_request(
        self,
        identity_id: str,
        resource: str,
        action: str,
    ) -> bool:
        """
        Check if policy matches a request (without condition evaluation).
        
        Args:
            identity_id: Identity making request
            resource: Resource being accessed
            action: Action being performed
            
        Returns:
            True if policy matches
        """
        # Match action
        if self.action != action:
            return False
        
        # Match subject (identity or wildcard)
        if self.subject != '*' and self.subject != identity_id:
            return False
        
        # Match resource (exact or wildcard prefix)
        if self.resource == '*':
            return True
        
        # Support wildcard suffix (e.g., "files/*")
        if self.resource.endswith('/*'):
            prefix = self.resource[:-2]
            if resource.startswith(prefix):
                return True
        
        # Exact match
        if self.resource == resource:
            return True
        
        return False


def validate_policy_dict(data: Dict[str, Any]) -> bool:
    """
    Validate a policy dictionary.
    
    Args:
        data: Policy data to validate
        
    Returns:
        True if valid
        
    Raises:
        InvalidPolicyError: If validation fails
    """
    # Check required fields
    required = ['subject', 'resource', 'action', 'decision']
    for field in required:
        if field not in data:
            raise InvalidPolicyError(f"Missing required field: {field}")
        if not isinstance(data[field], str):
            raise InvalidPolicyError(f"Field {field} must be a string")
    
    # Validate decision
    if data['decision'] not in VALID_DECISIONS:
        raise InvalidPolicyError(f"Invalid decision: {data['decision']}")
    
    # Validate action
    if data['action'] not in VALID_ACTIONS:
        raise InvalidPolicyError(f"Invalid action: {data['action']}")
    
    # Validate conditions if present
    if 'conditions' in data:
        if data['conditions'] is not None and not isinstance(data['conditions'], dict):
            raise InvalidPolicyError("Conditions must be a dictionary or null")
    
    return True
