"""
Canonical JSON serialization for deterministic hashing.
Ensures identical objects always produce identical JSON strings.
"""

import json
from typing import Any

from ..config import JSON_SEPARATORS, JSON_SORT_KEYS, JSON_ENSURE_ASCII


def canonicalize(obj: Any) -> str:
    """
    Serialize an object to canonical JSON.
    
    Canonical properties:
    - Keys are sorted
    - No whitespace
    - Consistent encoding
    - Deterministic ordering
    
    Args:
        obj: Python object to serialize
        
    Returns:
        Canonical JSON string
        
    Raises:
        TypeError: If object is not JSON-serializable
    """
    try:
        return json.dumps(
            obj,
            separators=JSON_SEPARATORS,
            sort_keys=JSON_SORT_KEYS,
            ensure_ascii=JSON_ENSURE_ASCII,
            allow_nan=False,  # Reject NaN/Infinity for determinism
        )
    except (TypeError, ValueError) as e:
        raise TypeError(f"Object not JSON-serializable: {e}")


def canonicalize_bytes(obj: Any) -> bytes:
    """
    Serialize an object to canonical JSON bytes.
    
    Args:
        obj: Python object to serialize
        
    Returns:
        Canonical JSON as UTF-8 bytes
    """
    canonical_str = canonicalize(obj)
    return canonical_str.encode('utf-8')


def parse(json_str: str) -> Any:
    """
    Parse JSON string into Python object.
    
    Args:
        json_str: JSON string to parse
        
    Returns:
        Parsed Python object
        
    Raises:
        ValueError: If JSON is invalid
    """
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")
