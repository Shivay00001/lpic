"""
LPIC Public API - Local-First Identity & Policy Core

This is the main entry point for the LPIC system.
All authorization decisions flow through this engine.
"""

from typing import Dict, Any, Optional
from pathlib import Path

from .db.connection import DatabaseConnection
from .db.migrations import initialize_schema, verify_schema
from .identity_v2 import Keypair, IdentityStore, SignedRequest, sign_request, parse_signed_request, verify_signature
from .policy import Policy, PolicyEvaluator
from .audit import AuditRecorder, IntegrityVerifier
from .errors import *
from .config import DECISION_DENY
from .invariants import check_all_invariants
from .utils.time import now


class LPICEngine:
    """
    Main engine for Local-First Identity & Policy Core.
    
    This is the primary interface for:
    - Registering identities
    - Managing policies
    - Authorizing requests
    - Querying audit logs
    """
    
    def __init__(self, db_path: str):
        """
        Initialize LPIC engine.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db = DatabaseConnection(db_path)
        self.db.connect()
        
        # Initialize schema if needed
        initialize_schema(self.db)
        
        # Initialize subsystems
        self.identity_store = IdentityStore(self.db)
        self.policy_evaluator = PolicyEvaluator(self.db)
        self.audit_recorder = AuditRecorder(self.db)
        self.integrity_verifier = IntegrityVerifier(self.audit_recorder)
    
    def close(self):
        """Close database connection."""
        self.db.close()
    
    # ==================== Identity Management ====================
    
    def register_identity(
        self,
        keypair: Keypair,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Register a new identity.
        
        Args:
            keypair: Ed25519 keypair
            metadata: Optional metadata
            
        Returns:
            Identity ID
            
        Raises:
            IdentityAlreadyExistsError: If identity exists
        """
        identity = self.identity_store.register(keypair, metadata)
        return identity.identity_id
    
    def get_identity(self, identity_id: str) -> Dict[str, Any]:
        """
        Get identity information.
        
        Args:
            identity_id: Identity ID
            
        Returns:
            Identity information dictionary
            
        Raises:
            IdentityNotFoundError: If identity not found
        """
        identity = self.identity_store.get(identity_id)
        return identity.to_dict()
    
    def list_identities(self) -> list[Dict[str, Any]]:
        """
        List all registered identities.
        
        Returns:
            List of identity dictionaries
        """
        identities = self.identity_store.list_all()
        return [i.to_dict() for i in identities]
    
    # ==================== Policy Management ====================
    
    def add_policy(
        self,
        subject: str,
        resource: str,
        action: str,
        decision: str,
        conditions: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Add an authorization policy.
        
        Args:
            subject: Identity ID or '*' for all
            resource: Resource identifier (supports wildcards)
            action: Action (read, write, execute, delete, admin)
            decision: ALLOW, DENY, or REQUIRE_REVIEW
            conditions: Optional conditions
            
        Returns:
            Policy ID
            
        Raises:
            InvalidPolicyError: If policy is invalid
        """
        policy = Policy.create(
            subject=subject,
            resource=resource,
            action=action,
            decision=decision,
            conditions=conditions,
        )
        
        self.policy_evaluator.add_policy(policy)
        return policy.policy_id
    
    def get_policy(self, policy_id: str) -> Dict[str, Any]:
        """
        Get a policy by ID.
        
        Args:
            policy_id: Policy ID
            
        Returns:
            Policy dictionary
        """
        policy = self.policy_evaluator.get_policy(policy_id)
        return policy.to_dict()
    
    def list_policies(self) -> list[Dict[str, Any]]:
        """
        List all policies.
        
        Returns:
            List of policy dictionaries
        """
        policies = self.policy_evaluator.list_policies()
        return [p.to_dict() for p in policies]
    
    def delete_policy(self, policy_id: str):
        """
        Delete a policy.
        
        Args:
            policy_id: Policy ID
        """
        self.policy_evaluator.delete_policy(policy_id)
    
    # ==================== Authorization ====================
    
    def authorize(
        self,
        request: SignedRequest,
        additional_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Authorize a signed request.
        
        This is the core authorization function. It:
        1. Validates the request signature
        2. Verifies identity exists
        3. Evaluates policies
        4. Records decision in audit log
        5. Returns decision
        
        Args:
            request: Signed authorization request
            additional_context: Optional additional context
            
        Returns:
            Decision: ALLOW, DENY, or REQUIRE_REVIEW
            
        Raises:
            IdentityNotFoundError: If identity not found
            SignatureError: If signature invalid
            InvariantViolationError: If security invariant violated
        """
        try:
            # Get identity
            identity = self.identity_store.get(request.identity_id)
            
            # Verify signature
            verify_signature(request, identity.public_key)
            
            # Merge context
            context = {**request.context}
            if additional_context:
                context.update(additional_context)
            
            # Add timestamp if not present
            if 'timestamp' not in context:
                context['timestamp'] = now()
            
            # Evaluate policies
            decision = self.policy_evaluator.evaluate(
                identity_id=request.identity_id,
                resource=request.resource,
                action=request.action,
                context=context,
            )
            
            # Check invariants
            check_all_invariants(
                identity_id=request.identity_id,
                public_key=identity.public_key,
                request=request,
                decision=decision,
            )
            
            # Record decision
            self.audit_recorder.record_decision(
                request_hash=request.get_request_hash(),
                identity_id=request.identity_id,
                resource=request.resource,
                action=request.action,
                decision=decision,
                context=context,
            )
            
            return decision
            
        except (IdentityNotFoundError, SignatureError, InvariantViolationError):
            # Re-raise security errors
            raise
        except Exception as e:
            # Unexpected error = DENY and log
            try:
                self.audit_recorder.record_decision(
                    request_hash=request.get_request_hash(),
                    identity_id=request.identity_id,
                    resource=request.resource,
                    action=request.action,
                    decision=DECISION_DENY,
                    context={'error': str(e)},
                )
            except:
                pass  # Don't fail if audit fails
            
            return DECISION_DENY
    
    def authorize_dict(
        self,
        request_dict: Dict[str, Any],
        additional_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Authorize a request from dictionary format.
        
        Args:
            request_dict: Request dictionary with signature
            additional_context: Optional additional context
            
        Returns:
            Decision: ALLOW, DENY, or REQUIRE_REVIEW
        """
        request = parse_signed_request(request_dict)
        return self.authorize(request, additional_context)
    
    # ==================== Audit Log ====================
    
    def get_audit_entry(self, entry_id: int) -> Dict[str, Any]:
        """
        Get an audit log entry.
        
        Args:
            entry_id: Entry ID
            
        Returns:
            Audit entry dictionary
        """
        entry = self.audit_recorder.get_entry(entry_id)
        return entry.to_dict()
    
    def get_audit_log(
        self,
        identity_id: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> list[Dict[str, Any]]:
        """
        Get audit log entries.
        
        Args:
            identity_id: Optional filter by identity
            resource: Optional filter by resource
            
        Returns:
            List of audit entry dictionaries
        """
        if identity_id:
            entries = self.audit_recorder.get_entries_by_identity(identity_id)
        elif resource:
            entries = self.audit_recorder.get_entries_by_resource(resource)
        else:
            entries = self.audit_recorder.get_all_entries()
        
        return [e.to_dict() for e in entries]
    
    def verify_audit_integrity(self) -> bool:
        """
        Verify audit log integrity.
        
        Returns:
            True if audit log is intact
            
        Raises:
            AuditChainBrokenError: If chain is broken
            AuditIntegrityError: If entries are tampered
        """
        return self.integrity_verifier.verify_chain()
    
    def get_audit_summary(self) -> Dict[str, Any]:
        """
        Get audit log summary.
        
        Returns:
            Summary dictionary with statistics
        """
        return self.integrity_verifier.get_chain_summary()
    
    # ==================== Utilities ====================
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform system health check.
        
        Returns:
            Health status dictionary
        """
        try:
            # Check schema
            schema_valid = verify_schema(self.db)
            
            # Check audit integrity
            audit_summary = self.get_audit_summary()
            
            # Count entities
            identity_count = len(self.list_identities())
            policy_count = len(self.list_policies())
            
            return {
                'status': 'healthy' if schema_valid and audit_summary['is_valid'] else 'unhealthy',
                'schema_valid': schema_valid,
                'audit_valid': audit_summary['is_valid'],
                'audit_entries': audit_summary['total_entries'],
                'identities': identity_count,
                'policies': policy_count,
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
            }
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
