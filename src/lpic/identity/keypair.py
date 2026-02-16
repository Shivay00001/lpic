"""
Ed25519 keypair generation and management.
Private keys are never stored in the database.
"""

from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from ..config import PUBLIC_KEY_LENGTH
from ..errors import KeypairError
from ..utils.hashing import hash_bytes


class Keypair:
    """
    Ed25519 keypair with identity derivation.
    """
    
    def __init__(self, private_key: Ed25519PrivateKey):
        """
        Initialize keypair from private key.
        
        Args:
            private_key: Ed25519 private key object
        """
        if not isinstance(private_key, Ed25519PrivateKey):
            raise KeypairError("Invalid private key type")
        
        self._private_key = private_key
        self._public_key = private_key.public_key()
    
    @classmethod
    def generate(cls) -> 'Keypair':
        """
        Generate a new Ed25519 keypair.
        
        Returns:
            New Keypair instance
        """
        private_key = Ed25519PrivateKey.generate()
        return cls(private_key)
    
    @classmethod
    def from_private_bytes(cls, private_bytes: bytes) -> 'Keypair':
        """
        Load keypair from private key bytes.
        
        Args:
            private_bytes: 32-byte Ed25519 private key
            
        Returns:
            Keypair instance
            
        Raises:
            KeypairError: If bytes are invalid
        """
        if len(private_bytes) != 32:
            raise KeypairError(f"Private key must be 32 bytes, got {len(private_bytes)}")
        
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
            return cls(private_key)
        except Exception as e:
            raise KeypairError(f"Invalid private key bytes: {e}")
    
    @classmethod
    def from_private_pem(cls, pem_data: bytes) -> 'Keypair':
        """
        Load keypair from PEM-encoded private key.
        
        Args:
            pem_data: PEM-encoded private key
            
        Returns:
            Keypair instance
            
        Raises:
            KeypairError: If PEM is invalid
        """
        try:
            private_key = serialization.load_pem_private_key(
                pem_data,
                password=None,
            )
            if not isinstance(private_key, Ed25519PrivateKey):
                raise KeypairError("PEM does not contain Ed25519 key")
            return cls(private_key)
        except Exception as e:
            raise KeypairError(f"Invalid PEM data: {e}")
    
    @classmethod
    def load_from_file(cls, path: str) -> 'Keypair':
        """
        Load keypair from PEM file.
        
        Args:
            path: Path to PEM file
            
        Returns:
            Keypair instance
            
        Raises:
            KeypairError: If file cannot be read
        """
        try:
            pem_data = Path(path).read_bytes()
            return cls.from_private_pem(pem_data)
        except IOError as e:
            raise KeypairError(f"Cannot read key file: {e}")
    
    def get_private_bytes(self) -> bytes:
        """
        Export private key as raw bytes.
        WARNING: Handle with extreme care.
        
        Returns:
            32-byte private key
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    
    def get_private_pem(self) -> bytes:
        """
        Export private key as PEM.
        WARNING: Handle with extreme care.
        
        Returns:
            PEM-encoded private key
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    
    def get_public_bytes(self) -> bytes:
        """
        Export public key as raw bytes.
        
        Returns:
            32-byte public key
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    
    def get_public_pem(self) -> bytes:
        """
        Export public key as PEM.
        
        Returns:
            PEM-encoded public key
        """
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    
    def get_identity_id(self) -> str:
        """
        Derive identity ID from public key.
        Identity ID = SHA-256(public_key_bytes)
        
        Returns:
            64-character hex string
        """
        public_bytes = self.get_public_bytes()
        return hash_bytes(public_bytes)
    
    def save_to_file(self, path: str):
        """
        Save private key to PEM file.
        WARNING: File permissions should be restricted.
        
        Args:
            path: Path to save file
            
        Raises:
            KeypairError: If file cannot be written
        """
        try:
            pem_data = self.get_private_pem()
            key_path = Path(path)
            key_path.write_bytes(pem_data)
            # Set restrictive permissions (owner read/write only)
            key_path.chmod(0o600)
        except IOError as e:
            raise KeypairError(f"Cannot write key file: {e}")
    
    @property
    def private_key(self) -> Ed25519PrivateKey:
        """Get private key object (for signing)."""
        return self._private_key
    
    @property
    def public_key(self) -> Ed25519PublicKey:
        """Get public key object (for verification)."""
        return self._public_key


def load_public_key(public_bytes: bytes) -> Ed25519PublicKey:
    """
    Load Ed25519 public key from raw bytes.
    
    Args:
        public_bytes: 32-byte public key
        
    Returns:
        Ed25519PublicKey object
        
    Raises:
        KeypairError: If bytes are invalid
    """
    if len(public_bytes) != PUBLIC_KEY_LENGTH:
        raise KeypairError(f"Public key must be {PUBLIC_KEY_LENGTH} bytes, got {len(public_bytes)}")
    
    try:
        return Ed25519PublicKey.from_public_bytes(public_bytes)
    except Exception as e:
        raise KeypairError(f"Invalid public key bytes: {e}")
