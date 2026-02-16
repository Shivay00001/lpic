"""
Tests for policy evaluation logic.
"""

import pytest
import tempfile
import os

from lpic import LPICEngine, Keypair, sign_request
from lpic.config import DECISION_ALLOW, DECISION_DENY, DECISION_REQUIRE_REVIEW
from lpic.errors import InvalidPolicyError


class TestPolicyDefaultDeny:
    """Test that default decision is DENY."""
    
    def test_no_policies_deny(self):
        """Test that requests are denied when no policies exist."""
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
    
    def test_non_matching_policies_deny(self):
        """Test that requests are denied when no policies match."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Add policy for different resource
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


class TestPolicyMatching:
    """Test policy matching logic."""
    
    def test_exact_match_allows(self):
        """Test exact match policy allows request."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                engine.add_policy(
                    subject=identity_id,
                    resource="file://test.txt",
                    action="read",
                    decision=DECISION_ALLOW,
                )
                
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                
                decision = engine.authorize(request)
                assert decision == DECISION_ALLOW
    
    def test_wildcard_subject(self):
        """Test wildcard subject matches all identities."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                engine.register_identity(keypair)
                
                # Policy for all subjects
                engine.add_policy(
                    subject="*",
                    resource="file://public.txt",
                    action="read",
                    decision=DECISION_ALLOW,
                )
                
                request = sign_request(
                    keypair=keypair,
                    resource="file://public.txt",
                    action="read",
                    context={}
                )
                
                decision = engine.authorize(request)
                assert decision == DECISION_ALLOW
    
    def test_wildcard_resource(self):
        """Test wildcard resource matches all resources."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                engine.add_policy(
                    subject=identity_id,
                    resource="*",
                    action="read",
                    decision=DECISION_ALLOW,
                )
                
                request = sign_request(
                    keypair=keypair,
                    resource="file://anything.txt",
                    action="read",
                    context={}
                )
                
                decision = engine.authorize(request)
                assert decision == DECISION_ALLOW
    
    def test_prefix_wildcard(self):
        """Test prefix wildcard matches resources under path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                engine.add_policy(
                    subject=identity_id,
                    resource="files/*",
                    action="read",
                    decision=DECISION_ALLOW,
                )
                
                # Should match
                request1 = sign_request(
                    keypair=keypair,
                    resource="files/test.txt",
                    action="read",
                    context={}
                )
                assert engine.authorize(request1) == DECISION_ALLOW
                
                # Should not match
                request2 = sign_request(
                    keypair=keypair,
                    resource="other/test.txt",
                    action="read",
                    context={}
                )
                assert engine.authorize(request2) == DECISION_DENY


class TestPolicyPrecedence:
    """Test policy precedence rules."""
    
    def test_deny_overrides_allow(self):
        """Test that DENY takes precedence over ALLOW."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Add ALLOW policy
                engine.add_policy(
                    subject=identity_id,
                    resource="file://test.txt",
                    action="read",
                    decision=DECISION_ALLOW,
                )
                
                # Add DENY policy
                engine.add_policy(
                    subject=identity_id,
                    resource="file://test.txt",
                    action="read",
                    decision=DECISION_DENY,
                )
                
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                
                decision = engine.authorize(request)
                assert decision == DECISION_DENY
    
    def test_require_review_overrides_allow(self):
        """Test that REQUIRE_REVIEW takes precedence over ALLOW."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                engine.add_policy(
                    subject=identity_id,
                    resource="file://test.txt",
                    action="write",
                    decision=DECISION_ALLOW,
                )
                
                engine.add_policy(
                    subject=identity_id,
                    resource="file://test.txt",
                    action="write",
                    decision=DECISION_REQUIRE_REVIEW,
                )
                
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="write",
                    context={}
                )
                
                decision = engine.authorize(request)
                assert decision == DECISION_REQUIRE_REVIEW


class TestPolicyConditions:
    """Test policy condition evaluation."""
    
    def test_time_window_condition(self):
        """Test time window condition."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Policy with time window
                engine.add_policy(
                    subject=identity_id,
                    resource="file://test.txt",
                    action="read",
                    decision=DECISION_ALLOW,
                    conditions={
                        'time_window': {
                            'start': '2020-01-01T00:00:00.000000Z',
                            'end': '2030-01-01T00:00:00.000000Z',
                        }
                    }
                )
                
                # Request with timestamp in window
                from lpic.utils.time import now
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={'timestamp': now()}
                )
                
                decision = engine.authorize(request)
                assert decision == DECISION_ALLOW
    
    def test_device_id_condition(self):
        """Test device ID condition."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Policy with device ID
                engine.add_policy(
                    subject=identity_id,
                    resource="file://test.txt",
                    action="read",
                    decision=DECISION_ALLOW,
                    conditions={'device_id': 'device-123'}
                )
                
                # Request with matching device
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={'device_id': 'device-123'}
                )
                
                decision = engine.authorize(request)
                assert decision == DECISION_ALLOW
                
                # Request with non-matching device
                request2 = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={'device_id': 'device-456'}
                )
                
                decision2 = engine.authorize(request2)
                assert decision2 == DECISION_DENY


class TestPolicyValidation:
    """Test policy validation."""
    
    def test_invalid_decision_rejected(self):
        """Test that invalid decisions are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                with pytest.raises(InvalidPolicyError):
                    engine.add_policy(
                        subject="*",
                        resource="*",
                        action="read",
                        decision="INVALID",
                    )
    
    def test_invalid_action_rejected(self):
        """Test that invalid actions are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                with pytest.raises(InvalidPolicyError):
                    engine.add_policy(
                        subject="*",
                        resource="*",
                        action="invalid_action",
                        decision=DECISION_ALLOW,
                    )
