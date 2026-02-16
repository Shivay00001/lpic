"""
Tests for audit log integrity and tamper detection.
"""

import pytest
import tempfile
import os

from lpic import LPICEngine, Keypair, sign_request
from lpic.config import DECISION_ALLOW, DECISION_DENY, AUDIT_HASH_CHAIN_INITIAL
from lpic.errors import AuditChainBrokenError, AuditIntegrityError


class TestAuditLogging:
    """Test audit log recording."""
    
    def test_decision_recorded(self):
        """Test that authorization decisions are recorded."""
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
                    context={'metadata': 'test'}
                )
                
                decision = engine.authorize(request)
                
                # Check audit log
                audit_log = engine.get_audit_log()
                assert len(audit_log) == 1
                
                entry = audit_log[0]
                assert entry['identity_id'] == identity_id
                assert entry['resource'] == "file://test.txt"
                assert entry['action'] == "read"
                assert entry['decision'] == DECISION_ALLOW
    
    def test_all_decisions_logged(self):
        """Test that all decisions are logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Multiple requests
                for i in range(5):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                # Check all logged
                audit_log = engine.get_audit_log()
                assert len(audit_log) == 5


class TestAuditIntegrity:
    """Test audit log integrity verification."""
    
    def test_hash_chain_valid(self):
        """Test that hash chain is valid for legitimate entries."""
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
                
                # Create multiple requests
                for i in range(10):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                # Verify integrity
                assert engine.verify_audit_integrity()
    
    def test_initial_hash_correct(self):
        """Test that first entry uses initial hash."""
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
                
                # Check first entry
                audit_log = engine.get_audit_log()
                first_entry = audit_log[0]
                assert first_entry['previous_hash'] == AUDIT_HASH_CHAIN_INITIAL
    
    def test_hash_chain_links(self):
        """Test that hash chain links entries correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                engine.register_identity(keypair)
                
                # Create multiple entries
                for i in range(3):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                # Check chain linkage
                audit_log = engine.get_audit_log()
                
                for i in range(1, len(audit_log)):
                    prev_entry = audit_log[i-1]
                    curr_entry = audit_log[i]
                    
                    # Current entry's previous_hash should match previous entry's hash
                    assert curr_entry['previous_hash'] == prev_entry['entry_hash']


class TestTamperDetection:
    """Test detection of audit log tampering."""
    
    def test_modified_entry_detected(self):
        """Test that modified entries are detected."""
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
                
                # Create entries
                for i in range(3):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                # Verify initially valid
                assert engine.verify_audit_integrity()
                
                # Tamper with an entry
                engine.db.execute(
                    "UPDATE audit_log SET decision = ? WHERE entry_id = ?",
                    (DECISION_DENY, 2)
                )
                engine.db.commit()
                
                # Verify should fail
                with pytest.raises((AuditChainBrokenError, AuditIntegrityError)):
                    engine.verify_audit_integrity()
    
    def test_broken_chain_detected(self):
        """Test that broken hash chains are detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                engine.register_identity(keypair)
                
                # Create entries
                for i in range(3):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                # Break the chain by modifying previous_hash
                engine.db.execute(
                    "UPDATE audit_log SET previous_hash = ? WHERE entry_id = ?",
                    ("0" * 64, 2)
                )
                engine.db.commit()
                
                # Verify should fail
                with pytest.raises(AuditChainBrokenError):
                    engine.verify_audit_integrity()
    
    def test_deleted_entry_detected(self):
        """Test that deleted entries break the chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                engine.register_identity(keypair)
                
                # Create entries
                for i in range(5):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                # Delete middle entry
                engine.db.execute("DELETE FROM audit_log WHERE entry_id = ?", (3,))
                engine.db.commit()
                
                # Verify should fail
                with pytest.raises(AuditChainBrokenError):
                    engine.verify_audit_integrity()
    
    def test_tamper_summary(self):
        """Test audit summary reports tampering."""
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
                
                # Create entries
                for i in range(3):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                # Tamper
                engine.db.execute(
                    "UPDATE audit_log SET decision = ? WHERE entry_id = ?",
                    (DECISION_DENY, 2)
                )
                engine.db.commit()
                
                # Check summary
                summary = engine.get_audit_summary()
                assert summary['is_valid'] is False
                assert len(summary['tampered_entries']) > 0


class TestAuditAppendOnly:
    """Test that audit log is append-only."""
    
    def test_cannot_modify_past_without_detection(self):
        """Test that past entries cannot be silently modified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                engine.register_identity(keypair)
                
                # Create entries
                for i in range(5):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                # Get original log
                original_log = engine.get_audit_log()
                
                # Try to modify
                engine.db.execute(
                    "UPDATE audit_log SET resource = ? WHERE entry_id = ?",
                    ("file://modified.txt", 3)
                )
                engine.db.commit()
                
                # Modification should be detectable
                with pytest.raises((AuditChainBrokenError, AuditIntegrityError)):
                    engine.verify_audit_integrity()
    
    def test_audit_survives_engine_restart(self):
        """Test that audit log persists across engine restarts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            # First session
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                for i in range(3):
                    request = sign_request(
                        keypair=keypair,
                        resource=f"file://test{i}.txt",
                        action="read",
                        context={}
                    )
                    engine.authorize(request)
                
                first_count = engine.audit_recorder.count_entries()
            
            # Second session
            with LPICEngine(db_path) as engine:
                second_count = engine.audit_recorder.count_entries()
                
                # Verify count preserved
                assert second_count == first_count
                
                # Verify integrity preserved
                assert engine.verify_audit_integrity()
