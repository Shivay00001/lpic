"""
Database migration management for LPIC.
Ensures schema is correctly initialized and versioned.
"""

from typing import Optional

from .connection import DatabaseConnection
from .schema import get_schema_statements, get_initial_version_insert, DB_SCHEMA_VERSION
from ..errors import MigrationError, SchemaError


def get_current_version(db: DatabaseConnection) -> Optional[int]:
    """
    Get current schema version from database.
    
    Args:
        db: Database connection
        
    Returns:
        Current version number or None if not initialized
    """
    try:
        row = db.fetch_one("SELECT MAX(version) as version FROM schema_version")
        if row and row['version'] is not None:
            return row['version']
        return None
    except Exception:
        # Table doesn't exist yet
        return None


def initialize_schema(db: DatabaseConnection):
    """
    Initialize database schema.
    
    Args:
        db: Database connection
        
    Raises:
        SchemaError: If initialization fails
    """
    current_version = get_current_version(db)
    
    if current_version is not None:
        if current_version == DB_SCHEMA_VERSION:
            # Already at correct version
            return
        elif current_version > DB_SCHEMA_VERSION:
            raise SchemaError(
                f"Database schema version {current_version} is newer than "
                f"expected version {DB_SCHEMA_VERSION}. Cannot downgrade."
            )
        else:
            # Need migration (not implemented yet)
            raise SchemaError(
                f"Database schema version {current_version} is older than "
                f"expected version {DB_SCHEMA_VERSION}. Migration needed."
            )
    
    # Initialize fresh schema
    try:
        with db.transaction():
            # Create all tables and indexes
            for statement in get_schema_statements():
                db.execute(statement)
            
            # Record schema version
            sql, params = get_initial_version_insert()
            db.execute(sql, params)
            
    except Exception as e:
        raise SchemaError(f"Failed to initialize schema: {e}")


def verify_schema(db: DatabaseConnection) -> bool:
    """
    Verify that schema is correct and complete.
    
    Args:
        db: Database connection
        
    Returns:
        True if schema is valid
    """
    try:
        # Check version
        version = get_current_version(db)
        if version != DB_SCHEMA_VERSION:
            return False
        
        # Check required tables exist
        required_tables = ['identities', 'policies', 'audit_log', 'schema_version']
        
        for table_name in required_tables:
            row = db.fetch_one(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            )
            if not row:
                return False
        
        return True
        
    except Exception:
        return False


def reset_schema(db: DatabaseConnection):
    """
    Drop all tables and reinitialize schema.
    WARNING: This destroys all data. Use only for testing.
    
    Args:
        db: Database connection
        
    Raises:
        SchemaError: If reset fails
    """
    try:
        with db.transaction():
            # Drop all tables
            tables = ['audit_log', 'policies', 'identities', 'schema_version']
            for table in tables:
                db.execute(f"DROP TABLE IF EXISTS {table}")
        
        # Reinitialize
        initialize_schema(db)
        
    except Exception as e:
        raise SchemaError(f"Failed to reset schema: {e}")
