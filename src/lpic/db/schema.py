"""
Database schema definitions for LPIC.
All schema changes must be versioned and migrated.
"""

from ..config import DB_SCHEMA_VERSION, AUDIT_HASH_CHAIN_INITIAL


# Schema version tracking
SCHEMA_VERSION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
)
"""

# Identity storage
IDENTITIES_TABLE = """
CREATE TABLE IF NOT EXISTS identities (
    identity_id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    metadata TEXT,
    CHECK(length(identity_id) = 64),
    CHECK(length(public_key) = 32)
)
"""

IDENTITIES_INDEX = """
CREATE INDEX IF NOT EXISTS idx_identities_created 
ON identities(created_at)
"""

# Policy storage
POLICIES_TABLE = """
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    conditions TEXT,
    created_at TEXT NOT NULL,
    CHECK(decision IN ('ALLOW', 'DENY', 'REQUIRE_REVIEW')),
    CHECK(action IN ('read', 'write', 'execute', 'delete', 'admin'))
)
"""

POLICIES_INDEX_SUBJECT = """
CREATE INDEX IF NOT EXISTS idx_policies_subject 
ON policies(subject, resource, action)
"""

POLICIES_INDEX_RESOURCE = """
CREATE INDEX IF NOT EXISTS idx_policies_resource 
ON policies(resource, action)
"""

# Audit log storage
AUDIT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_hash TEXT NOT NULL,
    identity_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE,
    context TEXT,
    CHECK(decision IN ('ALLOW', 'DENY', 'REQUIRE_REVIEW')),
    CHECK(length(request_hash) = 64),
    CHECK(length(previous_hash) = 64),
    CHECK(length(entry_hash) = 64)
)
"""

AUDIT_LOG_INDEX_IDENTITY = """
CREATE INDEX IF NOT EXISTS idx_audit_identity 
ON audit_log(identity_id, timestamp)
"""

AUDIT_LOG_INDEX_RESOURCE = """
CREATE INDEX IF NOT EXISTS idx_audit_resource 
ON audit_log(resource, timestamp)
"""

AUDIT_LOG_INDEX_TIMESTAMP = """
CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
ON audit_log(timestamp)
"""

AUDIT_LOG_INDEX_CHAIN = """
CREATE INDEX IF NOT EXISTS idx_audit_chain 
ON audit_log(entry_id, previous_hash, entry_hash)
"""


def get_schema_statements() -> list[str]:
    """
    Get all schema creation statements in order.
    
    Returns:
        List of SQL statements to create schema
    """
    return [
        SCHEMA_VERSION_TABLE,
        IDENTITIES_TABLE,
        IDENTITIES_INDEX,
        POLICIES_TABLE,
        POLICIES_INDEX_SUBJECT,
        POLICIES_INDEX_RESOURCE,
        AUDIT_LOG_TABLE,
        AUDIT_LOG_INDEX_IDENTITY,
        AUDIT_LOG_INDEX_RESOURCE,
        AUDIT_LOG_INDEX_TIMESTAMP,
        AUDIT_LOG_INDEX_CHAIN,
    ]


def get_initial_version_insert() -> tuple[str, tuple]:
    """
    Get the initial schema version insert statement.
    
    Returns:
        Tuple of (SQL statement, parameters)
    """
    from ..utils.time import now
    
    sql = """
    INSERT INTO schema_version (version, applied_at, description)
    VALUES (?, ?, ?)
    """
    params = (DB_SCHEMA_VERSION, now(), "Initial schema")
    return sql, params
