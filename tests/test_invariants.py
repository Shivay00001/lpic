"""
Tests for security invariant validation.
These tests attempt to violate core security invariants.
"""

import pytest
import tempfile
import os

from lpic import LPICEngine, Keypair, sign_request
from lpic.config import DECISION_ALLOW, DECISION_DENY
from lpic.errors import (
    InvariantViolationError,
    SignatureError,
    IdentityNotFoundError,
    InvalidPolicyError,
)
from lpic.invariants import *


class TestIdentityBinding:
    """Test identity-to-keypair binding."""
    
    def test_identity_derived_from_public_key(self):
        """Test that identity ID is derived from public key."""
        keypair = Keypair.generate()
        identity_id = keypair.get_identity_id()
        public_key = keypair.get_public_bytes()
        
        # Should not raise
        validate_identity_binding(identity_id, public_key)
    
    def test_wrong_binding_rejected(self):
        """Test that wrong identity-key binding is rejected."""
        keypair1 = Keypair.generate()
        keypair2 = Keypair.generate()
        
        identity_id1 = keypair1.get_identity_id()
        public_key2 = keypair2.get_public_bytes()
        
        # Should raise
        with pytest.raises(InvariantViolationError):
            validate_identity_binding(identity_id1, public_key2)


class TestSignatureInvariant:
    """Test signature validation invariant."""
    
    def test_unsigned_requests_rejected(self):
        """Test that unsigned requests are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Try to create request without signature
                from lpic.identity.signature import SignedRequest
                
                # Create request with invalid signature
                request = SignedRequest(
                    identity_id=identity_id,
                    resource="file://test.txt",
                    action="read",
                    context={},
                    signature=b'invalid' * 8,  # Wrong length
                )
                
                identity = engine.identity_store.get(identity_id)
                
                # Should fail validation
                with pytest.raises((SignatureError, InvariantViolationError)):
                    validate_request_signature(request, identity.public_key)
    
    def test_mismatched_signature_rejected(self):
        """Test that requests signed by wrong key are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair1 = Keypair.generate()
                keypair2 = Keypair.generate()
                
                identity_id1 = engine.register_identity(keypair1)
                engine.register_identity(keypair2)
                
                # Sign with keypair2, but claim to be identity1
                request = sign_request(
                    keypair=keypair2,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                
                # Modify identity_id to keypair1's identity
                request.identity_id = identity_id1
                
                identity1 = engine.identity_store.get(identity_id1)
                
                # Should fail
                with pytest.raises((SignatureError, InvariantViolationError)):
                    validate_request_signature(request, identity1.public_key)


class TestDefaultDenyInvariant:
    """Test that there is no implicit allow."""
    
    def test_no_policies_denies(self):
        """Test that no policies means DENY."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                engine.register_identity(keypair)
                
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                
                decision = engine.authorize(request)
                assert decision == DECISION_DENY
    
    def test_no_matching_policies_denies(self):
        """Test that no matching policies means DENY."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Policy for different resource
                engine.add_policy(
                    subject=identity_id,
                    resource="file://other.txt",
                    action="read",
                    decision=DECISION_ALLOW,
                )
                
                # Request different resource
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                
                decision = engine.authorize(request)
                assert decision == DECISION_DENY


class TestPolicyPurityInvariant:
    """Test that policies are pure and have no side effects."""
    
    def test_policy_conditions_validated(self):
        """Test that policy conditions are validated for purity."""
        # Valid conditions should pass
        valid_conditions = {
            'time_window': {
                'start': '2025-01-01T00:00:00.000000Z',
                'end': '2025-12-31T23:59:59.999999Z',
            }
        }
        validate_policy_purity(valid_conditions)
    
    def test_dangerous_conditions_rejected(self):
        """Test that potentially impure conditions are rejected."""
        dangerous = {
            'exec': 'dangerous command',
        }
        
        with pytest.raises(InvariantViolationError):
            validate_policy_purity(dangerous)


class TestAuditInvariant:
    """Test audit log invariants."""
    
    def test_every_decision_logged(self):
        """Test that every decision creates an audit entry."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                engine.register_identity(keypair)
                
                # Make 10 requests
                for i in range(10):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                # Should have 10 audit entries
                audit_log = engine.get_audit_log()
                assert len(audit_log) == 10
    
    def test_audit_entry_format_valid(self):
        """Test that audit entries have required fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                engine.register_identity(keypair)
                
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                engine.authorize(request)
                
                audit_log = engine.get_audit_log()
                entry = audit_log[0]
                
                # Check required fields
                required_fields = [
                    'entry_id', 'request_hash', 'identity_id', 'resource',
                    'action', 'decision', 'timestamp', 'previous_hash', 'entry_hash'
                ]
                
                for field in required_fields:
                    assert field in entry


class TestValidationInvariants:
    """Test input validation invariants."""
    
    def test_invalid_decision_rejected(self):
        """Test that invalid decisions are rejected."""
        with pytest.raises(InvariantViolationError):
            validate_decision("INVALID_DECISION")
        
        # Valid decisions should pass
        validate_decision(DECISION_ALLOW)
        validate_decision(DECISION_DENY)
    
    def test_invalid_action_rejected(self):
        """Test that invalid actions are rejected."""
        with pytest.raises(InvariantViolationError):
            validate_action("invalid_action")
        
        # Valid actions should pass
        validate_action("read")
        validate_action("write")
    
    def test_identity_id_format_validated(self):
        """Test that identity ID format is validated."""
        # Valid ID
        valid_id = "a" * 64
        validate_identity_id_format(valid_id)
        
        # Wrong length
        with pytest.raises(InvariantViolationError):
            validate_identity_id_format("a" * 32)
        
        # Not hex
        with pytest.raises(InvariantViolationError):
            validate_identity_id_format("z" * 64)
    
    def test_request_hash_format_validated(self):
        """Test that request hash format is validated."""
        # Valid hash
        valid_hash = "a" * 64
        validate_request_hash_format(valid_hash)
        
        # Wrong length
        with pytest.raises(InvariantViolationError):
            validate_request_hash_format("a" * 32)
        
        # Not hex
        with pytest.raises(InvariantViolationError):
            validate_request_hash_format("z" * 64)


class TestEdgeCaseRejection:
    """Test that edge cases are properly rejected."""
    
    def test_unknown_identity_rejected(self):
        """Test that unknown identities are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                # Create request for unknown identity
                keypair = Keypair.generate()
                
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                
                # Should be rejected
                with pytest.raises(IdentityNotFoundError):
                    engine.authorize(request)
    
    def test_malformed_policy_rejected(self):
        """Test that malformed policies are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                # Invalid decision
                with pytest.raises(InvalidPolicyError):
                    engine.add_policy(
                        subject="*",
                        resource="*",
                        action="read",
                        decision="INVALID",
                    )
                
                # Invalid action
                with pytest.raises(InvalidPolicyError):
                    engine.add_policy(
                        subject="*",
                        resource="*",
                        action="invalid",
                        decision=DECISION_ALLOW,
                    )
    
    def test_empty_resource_handled(self):
        """Test that empty resource is handled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Policy with empty resource should work (treated as literal)
                engine.add_policy(
                    subject=identity_id,
                    resource="",
                    action="read",
                    decision=DECISION_ALLOW,
                )
                
                # Request for empty resource
                request = sign_request(
                    keypair=keypair,
                    resource="",
                    action="read",
                    context={}
                )
                
                decision = engine.authorize(request)
                assert decision == DECISION_ALLOW
