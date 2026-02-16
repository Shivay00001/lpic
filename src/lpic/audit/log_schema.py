"""
Audit log schema and entry structure.
Every decision is recorded immutably with hash chaining.
"""

from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class AuditEntry:
    """
    Represents a single audit log entry.
    """
    entry_id: int
    request_hash: str
    identity_id: str
    resource: str
    action: str
    decision: str
    timestamp: str
    previous_hash: str
    entry_hash: str
    context: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit entry to dictionary."""
        return {
            'entry_id': self.entry_id,
            'request_hash': self.request_hash,
            'identity_id': self.identity_id,
            'resource': self.resource,
            'action': self.action,
            'decision': self.decision,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'entry_hash': self.entry_hash,
            'context': self.context,
        }
    
    @classmethod
    def from_row(cls, row) -> 'AuditEntry':
        """Create audit entry from database row."""
        import json
        
        context = json.loads(row['context']) if row['context'] else {}
        
        return cls(
            entry_id=row['entry_id'],
            request_hash=row['request_hash'],
            identity_id=row['identity_id'],
            resource=row['resource'],
            action=row['action'],
            decision=row['decision'],
            timestamp=row['timestamp'],
            previous_hash=row['previous_hash'],
            entry_hash=row['entry_hash'],
            context=context,
        )


def create_entry_payload(
    request_hash: str,
    identity_id: str,
    resource: str,
    action: str,
    decision: str,
    timestamp: str,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create the payload for an audit entry (before hashing).
    
    Args:
        request_hash: Hash of the original request
        identity_id: Identity that made the request
        resource: Resource accessed
        action: Action performed
        decision: Authorization decision
        timestamp: Timestamp of decision
        context: Additional context
        
    Returns:
        Payload dictionary
    """
    return {
        'request_hash': request_hash,
        'identity_id': identity_id,
        'resource': resource,
        'action': action,
        'decision': decision,
        'timestamp': timestamp,
        'context': context,
    }
