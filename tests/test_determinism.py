"""
Tests for deterministic policy evaluation.
"""

import pytest
import tempfile
import os

from lpic import LPICEngine, Keypair, sign_request
from lpic.config import DECISION_ALLOW, DECISION_DENY


class TestDeterministicEvaluation:
    """Test that policy evaluation is deterministic."""
    
    def test_same_request_same_result(self):
        """Test that identical requests produce identical results."""
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
                
                # Make same request multiple times
                results = []
                for _ in range(5):
                    request = sign_request(
                        keypair=keypair,
                        resource="file://test.txt",
                        action="read",
                        context={'key': 'value'}
                    )
                    decision = engine.authorize(request)
                    results.append(decision)
                
                # All results should be identical
                assert all(r == results[0] for r in results)
                assert results[0] == DECISION_ALLOW
    
    def test_order_independence(self):
        """Test that evaluation order doesn't affect result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Add policies in one order
                policy_id1 = engine.add_policy(
                    subject=identity_id,
                    resource="file://test.txt",
                    action="read",
                    decision=DECISION_ALLOW,
                )
                
                policy_id2 = engine.add_policy(
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
                
                result1 = engine.authorize(request)
                
                # Remove and re-add in different order
                engine.delete_policy(policy_id1)
                engine.delete_policy(policy_id2)
                
                engine.add_policy(
                    subject=identity_id,
                    resource="file://test.txt",
                    action="read",
                    decision=DECISION_DENY,
                )
                
                engine.add_policy(
                    subject=identity_id,
                    resource="file://test.txt",
                    action="read",
                    decision=DECISION_ALLOW,
                )
                
                request2 = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                
                result2 = engine.authorize(request2)
                
                # Result should be same (DENY wins regardless of order)
                assert result1 == result2
                assert result1 == DECISION_DENY
    
    def test_json_canonicalization(self):
        """Test that JSON canonicalization is deterministic."""
        from lpic.utils.canonical_json import canonicalize
        
        # Same data, different order
        obj1 = {'b': 2, 'a': 1, 'c': 3}
        obj2 = {'a': 1, 'c': 3, 'b': 2}
        obj3 = {'c': 3, 'b': 2, 'a': 1}
        
        json1 = canonicalize(obj1)
        json2 = canonicalize(obj2)
        json3 = canonicalize(obj3)
        
        # All should be identical
        assert json1 == json2 == json3
        
        # Should have sorted keys
        assert json1 == '{"a":1,"b":2,"c":3}'
    
    def test_hash_determinism(self):
        """Test that hashing is deterministic."""
        from lpic.utils.hashing import hash_string
        
        data = "test data"
        
        hash1 = hash_string(data)
        hash2 = hash_string(data)
        hash3 = hash_string(data)
        
        assert hash1 == hash2 == hash3
    
    def test_timestamp_monotonicity(self):
        """Test that timestamps are monotonic."""
        from lpic.utils.time import now
        
        timestamps = []
        for _ in range(10):
            timestamps.append(now())
        
        # Check monotonicity
        for i in range(1, len(timestamps)):
            assert timestamps[i] >= timestamps[i-1]


class TestReplayDeterminism:
    """Test that replaying requests gives same results."""
    
    def test_replay_same_decision(self):
        """Test that replaying a request gives the same decision."""
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
                
                # Create request
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={'timestamp': '2025-01-01T00:00:00.000000Z'}
                )
                
                # First evaluation
                decision1 = engine.authorize(request)
                
                # Replay same request (with same context)
                request_replay = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={'timestamp': '2025-01-01T00:00:00.000000Z'}
                )
                
                decision2 = engine.authorize(request_replay)
                
                # Should be same decision
                assert decision1 == decision2
    
    def test_policy_evaluation_pure(self):
        """Test that policy evaluation has no side effects."""
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
                
                # Get policy count before
                policies_before = len(engine.list_policies())
                
                # Evaluate multiple requests
                for i in range(10):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                # Policy count should be unchanged
                policies_after = len(engine.list_policies())
                assert policies_before == policies_after


class TestConditionDeterminism:
    """Test that condition evaluation is deterministic."""
    
    def test_time_window_deterministic(self):
        """Test that time window evaluation is deterministic."""
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
                    conditions={
                        'time_window': {
                            'start': '2025-01-01T00:00:00.000000Z',
                            'end': '2025-12-31T23:59:59.999999Z',
                        }
                    }
                )
                
                # Same timestamp, multiple evaluations
                timestamp = '2025-06-15T12:00:00.000000Z'
                
                results = []
                for _ in range(5):
                    request = sign_request(
                        keypair=keypair,
                        resource="file://test.txt",
                        action="read",
                        context={'timestamp': timestamp}
                    )
                    decision = engine.authorize(request)
                    results.append(decision)
                
                # All should be same
                assert all(r == results[0] for r in results)
    
    def test_device_condition_deterministic(self):
        """Test that device ID condition is deterministic."""
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
                    conditions={'device_id': 'device-123'}
                )
                
                # Multiple evaluations with same device
                results = []
                for _ in range(5):
                    request = sign_request(
                        keypair=keypair,
                        resource="file://test.txt",
                        action="read",
                        context={'device_id': 'device-123'}
                    )
                    decision = engine.authorize(request)
                    results.append(decision)
                
                # All should be same
                assert all(r == results[0] for r in results)
                assert results[0] == DECISION_ALLOW
