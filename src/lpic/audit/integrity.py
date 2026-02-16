"""
Audit log integrity verification.
Detects tampering via hash chain validation.
"""

from typing import List, Optional

from ..config import AUDIT_HASH_CHAIN_INITIAL
from ..errors import AuditChainBrokenError, AuditIntegrityError
from ..utils.canonical_json import canonicalize_bytes
from ..utils.hashing import chain_hashes
from .log_schema import AuditEntry, create_entry_payload
from .recorder import AuditRecorder


class IntegrityVerifier:
    """
    Verifies audit log integrity via hash chain validation.
    """
    
    def __init__(self, recorder: AuditRecorder):
        """
        Initialize integrity verifier.
        
        Args:
            recorder: AuditRecorder instance
        """
        self.recorder = recorder
    
    def verify_entry(self, entry: AuditEntry, previous_hash: str) -> bool:
        """
        Verify a single audit entry's integrity.
        
        Args:
            entry: Audit entry to verify
            previous_hash: Expected previous hash
            
        Returns:
            True if entry is valid
            
        Raises:
            AuditIntegrityError: If verification fails
        """
        # Check previous hash matches
        if entry.previous_hash != previous_hash:
            raise AuditChainBrokenError(
                f"Entry {entry.entry_id}: previous_hash mismatch. "
                f"Expected {previous_hash}, got {entry.previous_hash}"
            )
        
        # Recreate entry hash
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
        
        # Verify hash
        if entry.entry_hash != expected_hash:
            raise AuditIntegrityError(
                f"Entry {entry.entry_id}: entry_hash mismatch. "
                f"Expected {expected_hash}, got {entry.entry_hash}"
            )
        
        return True
    
    def verify_chain(self, entries: Optional[List[AuditEntry]] = None) -> bool:
        """
        Verify the entire audit log chain.
        
        Args:
            entries: Optional list of entries to verify (defaults to all entries)
            
        Returns:
            True if entire chain is valid
            
        Raises:
            AuditChainBrokenError: If chain is broken
            AuditIntegrityError: If any entry is invalid
        """
        if entries is None:
            entries = self.recorder.get_all_entries()
        
        if not entries:
            # Empty chain is valid
            return True
        
        # Start with initial hash
        previous_hash = AUDIT_HASH_CHAIN_INITIAL
        
        # Verify each entry in sequence
        for entry in entries:
            self.verify_entry(entry, previous_hash)
            previous_hash = entry.entry_hash
        
        return True
    
    def verify_from_entry(self, start_entry_id: int) -> bool:
        """
        Verify audit chain from a specific entry onwards.
        
        Args:
            start_entry_id: Entry ID to start verification from
            
        Returns:
            True if chain is valid from this point
        """
        # Get all entries from start_entry_id onwards
        all_entries = self.recorder.get_all_entries()
        entries_to_verify = [e for e in all_entries if e.entry_id >= start_entry_id]
        
        if not entries_to_verify:
            raise AuditIntegrityError(f"No entries found from ID {start_entry_id}")
        
        # Get previous hash
        if start_entry_id == 1:
            previous_hash = AUDIT_HASH_CHAIN_INITIAL
        else:
            prev_entry = self.recorder.get_entry(start_entry_id - 1)
            previous_hash = prev_entry.entry_hash
        
        # Verify from this point
        for entry in entries_to_verify:
            self.verify_entry(entry, previous_hash)
            previous_hash = entry.entry_hash
        
        return True
    
    def detect_tampering(self) -> List[int]:
        """
        Scan for tampered entries.
        
        Returns:
            List of entry IDs that failed verification
        """
        tampered = []
        
        entries = self.recorder.get_all_entries()
        if not entries:
            return tampered
        
        previous_hash = AUDIT_HASH_CHAIN_INITIAL
        
        for entry in entries:
            try:
                self.verify_entry(entry, previous_hash)
                previous_hash = entry.entry_hash
            except (AuditChainBrokenError, AuditIntegrityError):
                tampered.append(entry.entry_id)
        
        return tampered
    
    def get_chain_summary(self) -> dict:
        """
        Get summary of audit chain status.
        
        Returns:
            Dictionary with chain statistics
        """
        entries = self.recorder.get_all_entries()
        
        summary = {
            'total_entries': len(entries),
            'is_valid': False,
            'tampered_entries': [],
            'first_entry_id': None,
            'last_entry_id': None,
            'last_hash': None,
        }
        
        if entries:
            summary['first_entry_id'] = entries[0].entry_id
            summary['last_entry_id'] = entries[-1].entry_id
            summary['last_hash'] = entries[-1].entry_hash
            
            try:
                self.verify_chain(entries)
                summary['is_valid'] = True
            except (AuditChainBrokenError, AuditIntegrityError):
                summary['is_valid'] = False
                summary['tampered_entries'] = self.detect_tampering()
        else:
            summary['is_valid'] = True  # Empty chain is valid
            summary['last_hash'] = AUDIT_HASH_CHAIN_INITIAL
        
        return summary
