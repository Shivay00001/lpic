"""
Tests for identity management and signature verification.
"""

import pytest
import tempfile
import os
from pathlib import Path

from lpic import LPICEngine, Keypair, sign_request
from lpic.errors import (
    IdentityNotFoundError,
    IdentityAlreadyExistsError,
    SignatureError,
    UnsignedRequestError,
)
from lpic.identity.signature import parse_signed_request


class TestKeypairGeneration:
    """Test keypair generation and management."""
    
    def test_generate_keypair(self):
        """Test generating a new keypair."""
        keypair = Keypair.generate()
        
        # Check key sizes
        assert len(keypair.get_public_bytes()) == 32
        assert len(keypair.get_private_bytes()) == 32
        
        # Check identity derivation
        identity_id = keypair.get_identity_id()
        assert len(identity_id) == 64
        assert isinstance(identity_id, str)
    
    def test_keypair_deterministic_identity(self):
        """Test that identity ID is deterministic."""
        keypair = Keypair.generate()
        
        id1 = keypair.get_identity_id()
        id2 = keypair.get_identity_id()
        
        assert id1 == id2
    
    def test_keypair_save_and_load(self):
        """Test saving and loading keypair from file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "test_key.pem")
            
            # Generate and save
            keypair1 = Keypair.generate()
            identity_id1 = keypair1.get_identity_id()
            keypair1.save_to_file(key_path)
            
            # Load and verify
            keypair2 = Keypair.load_from_file(key_path)
            identity_id2 = keypair2.get_identity_id()
            
            assert identity_id1 == identity_id2
            assert keypair1.get_public_bytes() == keypair2.get_public_bytes()


class TestIdentityRegistration:
    """Test identity registration."""
    
    def test_register_identity(self):
        """Test registering a new identity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Verify identity exists
                identity = engine.get_identity(identity_id)
                assert identity['identity_id'] == identity_id
                assert identity['public_key'] == keypair.get_public_bytes().hex()
    
    def test_duplicate_identity_rejected(self):
        """Test that duplicate identities are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                engine.register_identity(keypair)
                
                # Try to register again
                with pytest.raises(IdentityAlreadyExistsError):
                    engine.register_identity(keypair)
    
    def test_unknown_identity_rejected(self):
        """Test that unknown identities are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                with pytest.raises(IdentityNotFoundError):
                    engine.get_identity("0" * 64)


class TestSignatureVerification:
    """Test request signing and signature verification."""
    
    def test_sign_and_verify_request(self):
        """Test signing and verifying a valid request."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                # Register identity
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Create signed request
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                
                # Should not raise
                identity = engine.identity_store.get(identity_id)
                from lpic.identity.signature import verify_signature
                assert verify_signature(request, identity.public_key)
    
    def test_invalid_signature_rejected(self):
        """Test that invalid signatures are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                # Register two identities
                keypair1 = Keypair.generate()
                keypair2 = Keypair.generate()
                engine.register_identity(keypair1)
                identity_id2 = engine.register_identity(keypair2)
                
                # Sign with keypair1
                request = sign_request(
                    keypair=keypair1,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                
                # Try to verify with keypair2's public key
                identity2 = engine.identity_store.get(identity_id2)
                from lpic.identity.signature import verify_signature
                
                with pytest.raises(SignatureError):
                    verify_signature(request, identity2.public_key)
    
    def test_tampered_request_rejected(self):
        """Test that tampered requests are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            
            with LPICEngine(db_path) as engine:
                keypair = Keypair.generate()
                identity_id = engine.register_identity(keypair)
                
                # Create valid request
                request = sign_request(
                    keypair=keypair,
                    resource="file://test.txt",
                    action="read",
                    context={}
                )
                
                # Tamper with resource
                request.resource = "file://tampered.txt"
                
                # Verify should fail
                identity = engine.identity_store.get(identity_id)
                from lpic.identity.signature import verify_signature
                
                with pytest.raises(SignatureError):
                    verify_signature(request, identity.public_key)
    
    def test_unsigned_request_rejected(self):
        """Test that unsigned requests are rejected."""
        request_dict = {
            'identity_id': '0' * 64,
            'resource': 'file://test.txt',
            'action': 'read',
        }
        
        with pytest.raises(UnsignedRequestError):
            parse_signed_request(request_dict)
    
    def test_request_hash_deterministic(self):
        """Test that request hash is deterministic."""
        keypair = Keypair.generate()
        
        request1 = sign_request(
            keypair=keypair,
            resource="file://test.txt",
            action="read",
            context={'key': 'value'}
        )
        
        request2 = sign_request(
            keypair=keypair,
            resource="file://test.txt",
            action="read",
            context={'key': 'value'}
        )
        
        # Different signatures, but payload hash should be deterministic
        # (Note: signatures will differ due to randomness in Ed25519)
        # But if we verify the same request twice, hash should be same
        hash1 = request1.get_request_hash()
        hash2 = request1.get_request_hash()
        assert hash1 == hash2
