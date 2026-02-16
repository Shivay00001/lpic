"""
Configuration constants for LPIC.
These are immutable system constants, not runtime configuration.
"""

# Cryptographic constants
HASH_ALGORITHM = "sha256"
SIGNATURE_ALGORITHM = "ed25519"
KEY_SIZE_BYTES = 32

# Policy evaluation outcomes
DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_REQUIRE_REVIEW = "REQUIRE_REVIEW"
VALID_DECISIONS = frozenset([DECISION_ALLOW, DECISION_DENY, DECISION_REQUIRE_REVIEW])

# Policy actions
VALID_ACTIONS = frozenset(["read", "write", "execute", "delete", "admin"])

# Database constants
DB_SCHEMA_VERSION = 1
AUDIT_HASH_CHAIN_INITIAL = "0" * 64  # Initial hash for first entry

# Canonical JSON settings
JSON_SEPARATORS = (',', ':')  # No whitespace
JSON_SORT_KEYS = True
JSON_ENSURE_ASCII = False

# Time constants
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

# Identity constants
IDENTITY_ID_LENGTH = 64  # Hex-encoded SHA-256
PUBLIC_KEY_LENGTH = 32  # Ed25519 public key bytes
