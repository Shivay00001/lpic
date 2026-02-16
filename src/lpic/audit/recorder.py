"""
Audit log recorder for immutable decision logging.
All decisions are recorded with hash chaining for tamper detection.
"""

import json
from typing import Dict, Any, Optional

from ..config import AUDIT_HASH_CHAIN_INITIAL
from ..db.connection import DatabaseConnection
from ..errors import AuditError
from ..utils.canonical_json import canonicalize_bytes
from ..utils.hashing import chain_hashes
from ..utils.time import now
from .log_schema import AuditEntry, create_entry_payload


class AuditRecorder:
    """
    Records authorization decisions in an append-only audit log.
    """
    
    def __init__(self, db: DatabaseConnection):
        """
        Initialize audit recorder.
        
        Args:
            db: Database connection
        """
        self.db = db
    
    def get_last_entry(self) -> Optional[AuditEntry]:
        """
        Get the most recent audit entry.
        
        Returns:
            Last AuditEntry or None if log is empty
        """
        row = self.db.fetch_one(
            "SELECT * FROM audit_log ORDER BY entry_id DESC LIMIT 1"
        )
        
        if not row:
            return None
        
        return AuditEntry.from_row(row)
    
    def get_last_hash(self) -> str:
        """
        Get the hash of the last entry in the chain.
        
        Returns:
            Hash string (initial hash if log is empty)
        """
        last_entry = self.get_last_entry()
        if last_entry is None:
            return AUDIT_HASH_CHAIN_INITIAL
        return last_entry.entry_hash
    
    def record_decision(
        self,
        request_hash: str,
        identity_id: str,
        resource: str,
        action: str,
        decision: str,
        context: Dict[str, Any],
    ) -> AuditEntry:
        """
        Record an authorization decision in the audit log.
        
        Args:
            request_hash: Hash of the request
            identity_id: Identity that made the request
            resource: Resource accessed
            action: Action performed
            decision: Authorization decision
            context: Additional context
            
        Returns:
            Created AuditEntry
            
        Raises:
            AuditError: If recording fails
        """
        try:
            timestamp = now()
            
            # Get previous hash for chaining
            previous_hash = self.get_last_hash()
            
            # Create entry payload
            payload = create_entry_payload(
                request_hash=request_hash,
                identity_id=identity_id,
                resource=resource,
                action=action,
                decision=decision,
                timestamp=timestamp,
                context=context,
            )
            
            # Calculate entry hash
            payload_bytes = canonicalize_bytes(payload)
            entry_hash = chain_hashes(previous_hash, payload_bytes)
            
            # Store in database
            context_json = json.dumps(context) if context else None
            
            with self.db.transaction():
                cursor = self.db.execute(
                    """
                    INSERT INTO audit_log (
                        request_hash, identity_id, resource, action, decision,
                        timestamp, previous_hash, entry_hash, context
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request_hash,
                        identity_id,
                        resource,
                        action,
                        decision,
                        timestamp,
                        previous_hash,
                        entry_hash,
                        context_json,
                    )
                )
                
                entry_id = cursor.lastrowid
            
            return AuditEntry(
                entry_id=entry_id,
                request_hash=request_hash,
                identity_id=identity_id,
                resource=resource,
                action=action,
                decision=decision,
                timestamp=timestamp,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                context=context,
            )
            
        except Exception as e:
            raise AuditError(f"Failed to record decision: {e}")
    
    def get_entry(self, entry_id: int) -> AuditEntry:
        """
        Retrieve an audit entry by ID.
        
        Args:
            entry_id: Entry ID
            
        Returns:
            AuditEntry
            
        Raises:
            AuditError: If entry not found
        """
        row = self.db.fetch_one(
            "SELECT * FROM audit_log WHERE entry_id = ?",
            (entry_id,)
        )
        
        if not row:
            raise AuditError(f"Audit entry {entry_id} not found")
        
        return AuditEntry.from_row(row)
    
    def get_entries_by_identity(self, identity_id: str) -> list[AuditEntry]:
        """
        Get all audit entries for an identity.
        
        Args:
            identity_id: Identity ID
            
        Returns:
            List of AuditEntry objects
        """
        rows = self.db.fetch_all(
            "SELECT * FROM audit_log WHERE identity_id = ? ORDER BY entry_id",
            (identity_id,)
        )
        
        return [AuditEntry.from_row(row) for row in rows]
    
    def get_entries_by_resource(self, resource: str) -> list[AuditEntry]:
        """
        Get all audit entries for a resource.
        
        Args:
            resource: Resource identifier
            
        Returns:
            List of AuditEntry objects
        """
        rows = self.db.fetch_all(
            "SELECT * FROM audit_log WHERE resource = ? ORDER BY entry_id",
            (resource,)
        )
        
        return [AuditEntry.from_row(row) for row in rows]
    
    def get_all_entries(self) -> list[AuditEntry]:
        """
        Get all audit entries in order.
        
        Returns:
            List of AuditEntry objects
        """
        rows = self.db.fetch_all(
            "SELECT * FROM audit_log ORDER BY entry_id"
        )
        
        return [AuditEntry.from_row(row) for row in rows]
    
    def count_entries(self) -> int:
        """
        Count total audit entries.
        
        Returns:
            Number of entries
        """
        row = self.db.fetch_one("SELECT COUNT(*) as count FROM audit_log")
        return row['count'] if row else 0
