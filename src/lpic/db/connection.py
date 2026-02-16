"""
Database connection management for LPIC.
All database operations use parameterized queries to prevent injection.
"""

import sqlite3
from pathlib import Path
from typing import Any, Optional
from contextlib import contextmanager

from ..errors import DatabaseError


class DatabaseConnection:
    """
    Manages SQLite database connections with security controls.
    """
    
    def __init__(self, db_path: str):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self._connection: Optional[sqlite3.Connection] = None
    
    def connect(self) -> sqlite3.Connection:
        """
        Establish database connection with security settings.
        
        Returns:
            SQLite connection object
            
        Raises:
            DatabaseError: If connection fails
        """
        if self._connection is not None:
            return self._connection
        
        try:
            # Create parent directory if needed
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Connect with security settings
            conn = sqlite3.connect(
                str(self.db_path),
                isolation_level='DEFERRED',
                check_same_thread=False,  # Allow multi-threaded access with caution
            )
            
            # Enable foreign keys
            conn.execute("PRAGMA foreign_keys = ON")
            
            # Set secure defaults
            conn.execute("PRAGMA trusted_schema = OFF")
            
            # Use WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode = WAL")
            
            # Row factory for dict-like access
            conn.row_factory = sqlite3.Row
            
            self._connection = conn
            return conn
            
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to connect to database: {e}")
    
    def close(self):
        """Close database connection."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None
    
    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """
        Execute a SQL statement with parameters.
        
        Args:
            sql: SQL statement (use ? for parameters)
            params: Parameter values
            
        Returns:
            Cursor object
            
        Raises:
            DatabaseError: If execution fails
        """
        conn = self.connect()
        try:
            return conn.execute(sql, params)
        except sqlite3.Error as e:
            raise DatabaseError(f"SQL execution failed: {e}")
    
    def execute_many(self, sql: str, params_list: list[tuple]) -> sqlite3.Cursor:
        """
        Execute a SQL statement multiple times with different parameters.
        
        Args:
            sql: SQL statement
            params_list: List of parameter tuples
            
        Returns:
            Cursor object
            
        Raises:
            DatabaseError: If execution fails
        """
        conn = self.connect()
        try:
            return conn.executemany(sql, params_list)
        except sqlite3.Error as e:
            raise DatabaseError(f"SQL batch execution failed: {e}")
    
    def fetch_one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        """
        Execute query and fetch one row.
        
        Args:
            sql: SQL query
            params: Parameter values
            
        Returns:
            Row object or None
        """
        cursor = self.execute(sql, params)
        return cursor.fetchone()
    
    def fetch_all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        """
        Execute query and fetch all rows.
        
        Args:
            sql: SQL query
            params: Parameter values
            
        Returns:
            List of row objects
        """
        cursor = self.execute(sql, params)
        return cursor.fetchall()
    
    def commit(self):
        """Commit current transaction."""
        if self._connection is not None:
            try:
                self._connection.commit()
            except sqlite3.Error as e:
                raise DatabaseError(f"Commit failed: {e}")
    
    def rollback(self):
        """Rollback current transaction."""
        if self._connection is not None:
            try:
                self._connection.rollback()
            except sqlite3.Error as e:
                raise DatabaseError(f"Rollback failed: {e}")
    
    @contextmanager
    def transaction(self):
        """
        Context manager for transactions.
        
        Usage:
            with db.transaction():
                db.execute(...)
        """
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if exc_type is not None:
            self.rollback()
        self.close()
