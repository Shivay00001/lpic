"""
Policy condition evaluation.
Conditions are pure functions with no side effects.
"""

from typing import Dict, Any
from datetime import datetime

from ..errors import ConditionError
from ..utils.time import parse_timestamp


def evaluate_conditions(
    conditions: Dict[str, Any],
    context: Dict[str, Any],
) -> bool:
    """
    Evaluate policy conditions against request context.
    
    Supported conditions:
    - time_window: {start: ISO8601, end: ISO8601}
    - device_id: string or list of strings
    - require_metadata: {key: value}
    
    Args:
        conditions: Policy conditions
        context: Request context
        
    Returns:
        True if all conditions are satisfied
        
    Raises:
        ConditionError: If condition evaluation fails
    """
    if not conditions:
        return True
    
    try:
        # Evaluate each condition type
        for condition_type, condition_value in conditions.items():
            if condition_type == 'time_window':
                if not evaluate_time_window(condition_value, context):
                    return False
            
            elif condition_type == 'device_id':
                if not evaluate_device_id(condition_value, context):
                    return False
            
            elif condition_type == 'require_metadata':
                if not evaluate_require_metadata(condition_value, context):
                    return False
            
            else:
                raise ConditionError(f"Unknown condition type: {condition_type}")
        
        return True
        
    except ConditionError:
        raise
    except Exception as e:
        raise ConditionError(f"Condition evaluation failed: {e}")


def evaluate_time_window(
    time_window: Dict[str, str],
    context: Dict[str, Any],
) -> bool:
    """
    Evaluate time window condition.
    
    Args:
        time_window: {start: ISO8601, end: ISO8601}
        context: Request context with 'timestamp' field
        
    Returns:
        True if current time is within window
    """
    if 'start' not in time_window or 'end' not in time_window:
        raise ConditionError("time_window requires 'start' and 'end'")
    
    # Get request timestamp
    if 'timestamp' not in context:
        raise ConditionError("Context missing 'timestamp' for time_window evaluation")
    
    try:
        request_time = parse_timestamp(context['timestamp'])
        start_time = parse_timestamp(time_window['start'])
        end_time = parse_timestamp(time_window['end'])
    except ValueError as e:
        raise ConditionError(f"Invalid timestamp format: {e}")
    
    return start_time <= request_time <= end_time


def evaluate_device_id(
    device_id: Any,
    context: Dict[str, Any],
) -> bool:
    """
    Evaluate device ID condition.
    
    Args:
        device_id: String or list of allowed device IDs
        context: Request context with 'device_id' field
        
    Returns:
        True if device ID matches
    """
    if 'device_id' not in context:
        raise ConditionError("Context missing 'device_id' for device_id evaluation")
    
    request_device = context['device_id']
    
    # Single device ID
    if isinstance(device_id, str):
        return request_device == device_id
    
    # List of device IDs
    if isinstance(device_id, list):
        return request_device in device_id
    
    raise ConditionError(f"Invalid device_id condition type: {type(device_id)}")


def evaluate_require_metadata(
    required: Dict[str, Any],
    context: Dict[str, Any],
) -> bool:
    """
    Evaluate required metadata condition.
    
    Args:
        required: Dictionary of required metadata key-value pairs
        context: Request context with 'metadata' field
        
    Returns:
        True if all required metadata is present and matches
    """
    if 'metadata' not in context:
        raise ConditionError("Context missing 'metadata' for require_metadata evaluation")
    
    metadata = context['metadata']
    if not isinstance(metadata, dict):
        raise ConditionError("Context 'metadata' must be a dictionary")
    
    # Check each required key-value pair
    for key, expected_value in required.items():
        if key not in metadata:
            return False
        if metadata[key] != expected_value:
            return False
    
    return True


def validate_conditions(conditions: Dict[str, Any]) -> bool:
    """
    Validate that conditions are well-formed.
    
    Args:
        conditions: Conditions dictionary
        
    Returns:
        True if valid
        
    Raises:
        ConditionError: If validation fails
    """
    if not isinstance(conditions, dict):
        raise ConditionError("Conditions must be a dictionary")
    
    for condition_type, condition_value in conditions.items():
        if condition_type == 'time_window':
            if not isinstance(condition_value, dict):
                raise ConditionError("time_window must be a dictionary")
            if 'start' not in condition_value or 'end' not in condition_value:
                raise ConditionError("time_window requires 'start' and 'end'")
        
        elif condition_type == 'device_id':
            if not isinstance(condition_value, (str, list)):
                raise ConditionError("device_id must be string or list")
        
        elif condition_type == 'require_metadata':
            if not isinstance(condition_value, dict):
                raise ConditionError("require_metadata must be a dictionary")
        
        else:
            raise ConditionError(f"Unknown condition type: {condition_type}")
    
    return True
