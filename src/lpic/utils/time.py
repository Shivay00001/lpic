"""
Time utilities for deterministic and monotonic timestamps.
Timestamps are ISO 8601 formatted and monotonic within a session.
"""

import time
from datetime import datetime, timezone
from typing import Optional

from ..config import TIMESTAMP_FORMAT


class MonotonicClock:
    """
    Monotonic clock that ensures timestamps never go backwards.
    This prevents replay attacks and ensures audit log ordering.
    """
    
    def __init__(self):
        self._last_timestamp: Optional[str] = None
        self._last_monotonic: float = 0.0
    
    def now(self) -> str:
        """
        Get current timestamp, guaranteed to be >= previous timestamp.
        
        Returns:
            ISO 8601 formatted timestamp string
        """
        # Get current time
        current_dt = datetime.now(timezone.utc)
        current_str = current_dt.strftime(TIMESTAMP_FORMAT)
        current_monotonic = time.monotonic()
        
        # Ensure monotonicity
        if self._last_timestamp is not None:
            # If clock went backwards or same time, increment microseconds
            if current_str <= self._last_timestamp:
                # Parse last timestamp and add 1 microsecond
                last_dt = datetime.strptime(self._last_timestamp, TIMESTAMP_FORMAT)
                # Add minimal increment
                last_dt = last_dt.replace(microsecond=last_dt.microsecond + 1)
                current_str = last_dt.strftime(TIMESTAMP_FORMAT)
        
        self._last_timestamp = current_str
        self._last_monotonic = current_monotonic
        return current_str
    
    def reset(self):
        """Reset monotonic state (for testing only)."""
        self._last_timestamp = None
        self._last_monotonic = 0.0


# Global monotonic clock instance
_clock = MonotonicClock()


def now() -> str:
    """
    Get current monotonic timestamp.
    
    Returns:
        ISO 8601 formatted timestamp string
    """
    return _clock.now()


def parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parse an ISO 8601 timestamp string.
    
    Args:
        timestamp_str: ISO 8601 formatted timestamp
        
    Returns:
        datetime object in UTC
        
    Raises:
        ValueError: If timestamp format is invalid
    """
    try:
        return datetime.strptime(timestamp_str, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise ValueError(f"Invalid timestamp format: {e}")


def is_valid_timestamp(timestamp_str: str) -> bool:
    """
    Check if a string is a valid timestamp.
    
    Args:
        timestamp_str: String to validate
        
    Returns:
        True if valid timestamp, False otherwise
    """
    try:
        parse_timestamp(timestamp_str)
        return True
    except ValueError:
        return False


def compare_timestamps(ts1: str, ts2: str) -> int:
    """
    Compare two timestamps.
    
    Args:
        ts1: First timestamp
        ts2: Second timestamp
        
    Returns:
        -1 if ts1 < ts2, 0 if equal, 1 if ts1 > ts2
    """
    dt1 = parse_timestamp(ts1)
    dt2 = parse_timestamp(ts2)
    
    if dt1 < dt2:
        return -1
    elif dt1 > dt2:
        return 1
    else:
        return 0
