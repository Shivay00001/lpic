"""
Identity storage and retrieval.
Stores public keys and identity metadata in SQLite.
"""

from typing import Optional, Dict, Any
import json

from ..db.connection import DatabaseConnection
from ..errors import (
    IdentityNotFoundError,
    IdentityAlreadyExistsError,
    IdentityError,
)
from ..utils.time import now
from ..utils.hashing import hash_bytes
from .keypair import Keypair, load_public_key


class Identity:
    """
    Represents a registered identity.
    """
    
    def __init__(
        self,
        identity_id: str,
        public_key: bytes,
        created_at: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.identity_id = identity_id
        self.public_key = public_key
        self.created_at = created_at
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert identity to dictionary."""
        return {
            'identity_id': self.identity_id,
            'public_key': self.public_key.hex(),
            'created_at': self.created_at,
            'metadata': self.metadata,
        }


class IdentityStore:
    """
    Manages identity storage in database.
    """
    
    def __init__(self, db: DatabaseConnection):
        """
        Initialize identity store.
        
        Args:
            db: Database connection
        """
        self.db = db
    
    def register(
        self,
        keypair: Keypair,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Identity:
        """
        Register a new identity.
        
        Args:
            keypair: Keypair for the identity
            metadata: Optional metadata
            
        Returns:
            Registered Identity object
            
        Raises:
            IdentityAlreadyExistsError: If identity already exists
        """
        identity_id = keypair.get_identity_id()
        public_key = keypair.get_public_bytes()
        
        # Check if identity already exists
        if self.exists(identity_id):
            raise IdentityAlreadyExistsError(f"Identity {identity_id} already exists")
        
        # Store identity
        try:
            metadata_json = json.dumps(metadata) if metadata else None
            created_at = now()
            
            with self.db.transaction():
                self.db.execute(
                    """
                    INSERT INTO identities (identity_id, public_key, created_at, metadata)
                    VALUES (?, ?, ?, ?)
                    """,
                    (identity_id, public_key, created_at, metadata_json)
                )
            
            return Identity(identity_id, public_key, created_at, metadata)
            
        except Exception as e:
            raise IdentityError(f"Failed to register identity: {e}")
    
    def get(self, identity_id: str) -> Identity:
        """
        Retrieve an identity by ID.
        
        Args:
            identity_id: Identity ID to retrieve
            
        Returns:
            Identity object
            
        Raises:
            IdentityNotFoundError: If identity does not exist
        """
        row = self.db.fetch_one(
            "SELECT * FROM identities WHERE identity_id = ?",
            (identity_id,)
        )
        
        if not row:
            raise IdentityNotFoundError(f"Identity {identity_id} not found")
        
        metadata = json.loads(row['metadata']) if row['metadata'] else {}
        
        return Identity(
            identity_id=row['identity_id'],
            public_key=row['public_key'],
            created_at=row['created_at'],
            metadata=metadata,
        )
    
    def get_by_public_key(self, public_key: bytes) -> Identity:
        """
        Retrieve an identity by public key.
        
        Args:
            public_key: Public key bytes
            
        Returns:
            Identity object
            
        Raises:
            IdentityNotFoundError: If identity does not exist
        """
        row = self.db.fetch_one(
            "SELECT * FROM identities WHERE public_key = ?",
            (public_key,)
        )
        
        if not row:
            raise IdentityNotFoundError("Identity with given public key not found")
        
        metadata = json.loads(row['metadata']) if row['metadata'] else {}
        
        return Identity(
            identity_id=row['identity_id'],
            public_key=row['public_key'],
            created_at=row['created_at'],
            metadata=metadata,
        )
    
    def exists(self, identity_id: str) -> bool:
        """
        Check if an identity exists.
        
        Args:
            identity_id: Identity ID to check
            
        Returns:
            True if identity exists
        """
        row = self.db.fetch_one(
            "SELECT 1 FROM identities WHERE identity_id = ? LIMIT 1",
            (identity_id,)
        )
        return row is not None
    
    def list_all(self) -> list[Identity]:
        """
        List all registered identities.
        
        Returns:
            List of Identity objects
        """
        rows = self.db.fetch_all("SELECT * FROM identities ORDER BY created_at")
        
        identities = []
        for row in rows:
            metadata = json.loads(row['metadata']) if row['metadata'] else {}
            identities.append(Identity(
                identity_id=row['identity_id'],
                public_key=row['public_key'],
                created_at=row['created_at'],
                metadata=metadata,
            ))
        
        return identities
    
    def update_metadata(self, identity_id: str, metadata: Dict[str, Any]):
        """
        Update identity metadata.
        
        Args:
            identity_id: Identity ID
            metadata: New metadata
            
        Raises:
            IdentityNotFoundError: If identity does not exist
        """
        if not self.exists(identity_id):
            raise IdentityNotFoundError(f"Identity {identity_id} not found")
        
        try:
            metadata_json = json.dumps(metadata)
            with self.db.transaction():
                self.db.execute(
                    "UPDATE identities SET metadata = ? WHERE identity_id = ?",
                    (metadata_json, identity_id)
                )
        except Exception as e:
            raise IdentityError(f"Failed to update metadata: {e}")
    
    def delete(self, identity_id: str):
        """
        Delete an identity.
        WARNING: This does not delete audit records.
        
        Args:
            identity_id: Identity ID to delete
            
        Raises:
            IdentityNotFoundError: If identity does not exist
        """
        if not self.exists(identity_id):
            raise IdentityNotFoundError(f"Identity {identity_id} not found")
        
        try:
            with self.db.transaction():
                self.db.execute(
                    "DELETE FROM identities WHERE identity_id = ?",
                    (identity_id,)
                )
        except Exception as e:
            raise IdentityError(f"Failed to delete identity: {e}")
