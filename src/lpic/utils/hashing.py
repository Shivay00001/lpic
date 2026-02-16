"""
Cryptographic hashing utilities.
All hashing is deterministic and uses SHA-256.
"""

import hashlib
from typing import Union

from ..config import HASH_ALGORITHM


def hash_bytes(data: bytes) -> str:
    """
    Hash bytes using SHA-256.
    
    Args:
        data: Raw bytes to hash
        
    Returns:
        Hex-encoded hash string (64 characters)
    """
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data)}")
    
    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update(data)
    return hasher.hexdigest()


def hash_string(data: str) -> str:
    """
    Hash a string using SHA-256.
    
    Args:
        data: String to hash (will be UTF-8 encoded)
        
    Returns:
        Hex-encoded hash string (64 characters)
    """
    if not isinstance(data, str):
        raise TypeError(f"Expected str, got {type(data)}")
    
    return hash_bytes(data.encode('utf-8'))


def verify_hash(data: bytes, expected_hash: str) -> bool:
    """
    Verify that data matches the expected hash.
    
    Args:
        data: Data to hash
        expected_hash: Expected hex-encoded hash
        
    Returns:
        True if hashes match, False otherwise
    """
    if not isinstance(expected_hash, str):
        raise TypeError(f"Expected str for hash, got {type(expected_hash)}")
    
    if len(expected_hash) != 64:
        raise ValueError(f"Invalid hash length: {len(expected_hash)}, expected 64")
    
    actual_hash = hash_bytes(data)
    return actual_hash == expected_hash


def chain_hashes(previous_hash: str, current_data: bytes) -> str:
    """
    Create a chained hash by combining previous hash with current data.
    This is used for audit log integrity.
    
    Args:
        previous_hash: Previous entry's hash (hex string)
        current_data: Current entry's data
        
    Returns:
        Hex-encoded hash of (previous_hash || current_data)
    """
    if not isinstance(previous_hash, str):
        raise TypeError(f"Expected str for previous_hash, got {type(previous_hash)}")
    
    if len(previous_hash) != 64:
        raise ValueError(f"Invalid previous_hash length: {len(previous_hash)}")
    
    if not isinstance(current_data, bytes):
        raise TypeError(f"Expected bytes for current_data, got {type(current_data)}")
    
    # Combine previous hash (as bytes) with current data
    combined = previous_hash.encode('utf-8') + current_data
    return hash_bytes(combined)
