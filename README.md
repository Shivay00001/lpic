# LPIC - Local-First Identity & Policy Core

A zero-cloud, SQLite-backed identity + policy + audit engine that runs entirely locally.

## What is LPIC?

LPIC is a **dependency-grade authorization primitive** designed for offline, air-gapped, and edge environments. It provides cryptographically sound identity management, policy-based authorization, and tamper-evident audit logging without any cloud dependencies.

### Core Questions LPIC Answers

- **Who** is making a request?
- **What** resource is being accessed?
- **What** action is requested?
- **Under what conditions** should this be allowed?
- **Should it be** ALLOW / DENY / REQUIRE_REVIEW?
- **Log every decision** immutably.

## What LPIC Is NOT

- ❌ OAuth / SSO / Web auth
- ❌ Token server
- ❌ Cloud IAM
- ❌ Network service

LPIC is a **local authorization library** that embeds into your application.

## Features

### 1️⃣ Cryptographic Identity

- **Ed25519 keypairs**: Industry-standard elliptic curve cryptography
- **Identity derivation**: Identity ID = SHA-256(public_key)
- **Signature verification**: All requests must be cryptographically signed
- **Local key storage**: Private keys never leave the device

### 2️⃣ Policy-Based Authorization

Policies support:

- **Subject**: Identity ID or role (supports wildcards)
- **Resource**: Resource identifier (supports wildcards like `files/*`)
- **Action**: read, write, execute, delete, admin
- **Decision**: ALLOW, DENY, REQUIRE_REVIEW
- **Conditions**:
  - Time windows
  - Device restrictions
  - Metadata requirements

### 3️⃣ Deterministic Evaluation

- **Pure functions**: No side effects in policy evaluation
- **Canonical JSON**: Deterministic serialization
- **Stable ordering**: Same request → same decision
- **Precedence rules**: DENY > REQUIRE_REVIEW > ALLOW
- **Default DENY**: No implicit allows

### 4️⃣ Tamper-Evident Audit Log

- **Hash chaining**: Each entry links to previous entry
- **Append-only**: Cannot modify past entries without detection
- **Integrity verification**: Cryptographic proof of tampering
- **Complete history**: Every decision is logged

## Installation

```bash
pip install -e . --break-system-packages
```

## Quick Start

```python
from lpic import LPICEngine, Keypair, sign_request

# Initialize engine
engine = LPICEngine("authorization.db")

# Generate and register identity
keypair = Keypair.generate()
identity_id = engine.register_identity(keypair)

# Add authorization policy
engine.add_policy(
    subject=identity_id,
    resource="file://data.txt",
    action="read",
    decision="ALLOW",
)

# Create and authorize request
request = sign_request(
    keypair=keypair,
    resource="file://data.txt",
    action="read",
    context={},
)

decision = engine.authorize(request)
print(f"Decision: {decision}")  # ALLOW

# Verify audit integrity
engine.verify_audit_integrity()
print("Audit log is intact")

engine.close()
```

## Architecture

```
lpic/
├── engine.py              # Public API
├── invariants.py          # Runtime validation
├── errors.py              # Domain exceptions
├── config.py              # Constants
│
├── identity/
│   ├── keypair.py         # Ed25519 key management
│   ├── identity_store.py  # Identity storage
│   └── signature.py       # Request signing
│
├── policy/
│   ├── model.py           # Policy schema
│   ├── evaluator.py       # Deterministic evaluation
│   └── conditions.py      # Context constraints
│
├── audit/
│   ├── log_schema.py      # Audit entry structure
│   ├── recorder.py        # Decision recording
│   └── integrity.py       # Hash-chain verification
│
├── db/
│   ├── connection.py      # SQLite management
│   ├── schema.py          # Database schema
│   └── migrations.py      # Schema versioning
│
└── utils/
    ├── hashing.py         # SHA-256 operations
    ├── canonical_json.py  # Deterministic JSON
    └── time.py            # Monotonic timestamps
```

## Usage Examples

### Identity Management

```python
from lpic import LPICEngine, Keypair

engine = LPICEngine("auth.db")

# Generate new identity
keypair = Keypair.generate()
identity_id = engine.register_identity(
    keypair,
    metadata={"name": "Alice", "role": "admin"}
)

# Save private key (secure storage)
keypair.save_to_file("alice.pem")

# Load existing keypair
keypair = Keypair.load_from_file("alice.pem")
```

### Policy Management

```python
# Allow specific identity to read specific file
engine.add_policy(
    subject="abc123...",
    resource="file://secret.txt",
    action="read",
    decision="ALLOW",
)

# Allow all identities to read public files
engine.add_policy(
    subject="*",
    resource="public/*",
    action="read",
    decision="ALLOW",
)

# Require review for admin actions
engine.add_policy(
    subject="*",
    resource="*",
    action="admin",
    decision="REQUIRE_REVIEW",
)

# Time-based access
engine.add_policy(
    subject="abc123...",
    resource="file://temp.txt",
    action="write",
    decision="ALLOW",
    conditions={
        "time_window": {
            "start": "2025-01-01T00:00:00.000000Z",
            "end": "2025-12-31T23:59:59.999999Z",
        }
    }
)

# Device-restricted access
engine.add_policy(
    subject="abc123...",
    resource="file://secure.txt",
    action="read",
    decision="ALLOW",
    conditions={
        "device_id": ["device-001", "device-002"]
    }
)
```

### Authorization

```python
from lpic import sign_request

# Create signed request
request = sign_request(
    keypair=keypair,
    resource="file://data.txt",
    action="read",
    context={
        "device_id": "device-001",
        "metadata": {"reason": "data analysis"}
    }
)

# Authorize
decision = engine.authorize(request)

if decision == "ALLOW":
    print("Access granted")
elif decision == "DENY":
    print("Access denied")
elif decision == "REQUIRE_REVIEW":
    print("Manual review required")
```

### Audit Log

```python
# Get all audit entries
audit_log = engine.get_audit_log()

# Filter by identity
user_log = engine.get_audit_log(identity_id="abc123...")

# Filter by resource
resource_log = engine.get_audit_log(resource="file://secret.txt")

# Verify integrity
try:
    engine.verify_audit_integrity()
    print("Audit log is intact")
except AuditChainBrokenError:
    print("WARNING: Audit log has been tampered with!")

# Get summary
summary = engine.get_audit_summary()
print(f"Total entries: {summary['total_entries']}")
print(f"Valid: {summary['is_valid']}")
```

## Security Model

### Core Security Invariants

1. **Identity is cryptographically bound to keypair**
   - Identity ID = SHA-256(public_key)
   - Cannot forge identity without private key

2. **Private keys never leave local device**
   - Keys stored in local files or secure containers
   - No network transmission

3. **Policies are deterministic and pure**
   - Same input → same output
   - No side effects
   - Reproducible evaluation

4. **Every authorization decision is auditable**
   - Complete audit trail
   - Tamper detection via hash chains
   - Append-only log

5. **No implicit allow**
   - Default decision is DENY
   - Explicit policies required

6. **Signatures cannot be forged**
   - Ed25519 cryptographic signatures
   - Request integrity verified

## Testing

Run the comprehensive test suite:

```bash
cd lpic
pytest tests/ -v
```

Tests verify:

- ✅ Signature validation correctness
- ✅ Policy denies by default
- ✅ Deterministic decisions
- ✅ Audit chain integrity
- ✅ Tamper detection
- ✅ Replay determinism
- ✅ Edge case rejection
- ✅ Invariant violation detection

## API Reference

### LPICEngine

Main engine class for authorization.

```python
engine = LPICEngine(db_path: str)
```

**Identity Management:**

- `register_identity(keypair, metadata=None) -> str`
- `get_identity(identity_id) -> dict`
- `list_identities() -> list[dict]`

**Policy Management:**

- `add_policy(subject, resource, action, decision, conditions=None) -> str`
- `get_policy(policy_id) -> dict`
- `list_policies() -> list[dict]`
- `delete_policy(policy_id)`

**Authorization:**

- `authorize(request: SignedRequest) -> str`
- `authorize_dict(request_dict) -> str`

**Audit Log:**

- `get_audit_entry(entry_id) -> dict`
- `get_audit_log(identity_id=None, resource=None) -> list[dict]`
- `verify_audit_integrity() -> bool`
- `get_audit_summary() -> dict`

**Utilities:**

- `health_check() -> dict`
- `close()`

### Keypair

Ed25519 keypair management.

```python
keypair = Keypair.generate()
keypair = Keypair.load_from_file(path)
```

**Methods:**

- `get_identity_id() -> str`
- `get_public_bytes() -> bytes`
- `get_private_bytes() -> bytes`
- `save_to_file(path)`

### SignedRequest

Cryptographically signed authorization request.

```python
request = sign_request(keypair, resource, action, context)
```

**Attributes:**

- `identity_id: str`
- `resource: str`
- `action: str`
- `context: dict`
- `signature: bytes`

## Configuration

Constants are defined in `lpic/config.py`:

- **Hash Algorithm**: SHA-256
- **Signature Algorithm**: Ed25519
- **Valid Decisions**: ALLOW, DENY, REQUIRE_REVIEW
- **Valid Actions**: read, write, execute, delete, admin

## Performance Considerations

LPIC prioritizes **correctness over speed**:

- Policy evaluation is O(n) where n = number of policies
- Audit log writes are sequential for integrity
- Hash chain verification is O(n) where n = number of entries
- SQLite provides excellent performance for local operations

For high-performance scenarios, cache policies and batch operations.

## Limitations

- **No distributed consensus**: Single-node only
- **No automatic sync**: Must implement sync layer if needed
- **SQLite limitations**: ~1M writes/sec, 140 TB max database
- **No automatic key rotation**: Must implement key management

## Why LPIC is Secure by Construction

LPIC's security is achieved through multiple layers of defense:

### Immutability

1. **Audit log is append-only**: Past entries cannot be modified without breaking the hash chain
2. **Hash chaining**: Each entry cryptographically links to all previous entries
3. **Canonical serialization**: Ensures identical data always produces identical hashes
4. **Monotonic timestamps**: Time cannot go backwards, preventing temporal attacks

### Deterministic Evaluation

1. **Pure functions**: Policy evaluation has zero side effects
2. **Stable ordering**: Policy precedence rules are explicit and consistent
3. **Canonical JSON**: Eliminates serialization non-determinism
4. **No hidden state**: All evaluation inputs are explicit

### Cryptographic Guarantees

1. **Ed25519 signatures**: Industry-standard elliptic curve cryptography
2. **Identity binding**: Identity ID derived directly from public key (cannot be forged)
3. **SHA-256 hashing**: Collision-resistant hashing for integrity
4. **Request signing**: Every request must be cryptographically signed

### Explicit Denial Model

1. **Default DENY**: No policies = access denied
2. **No implicit allows**: Every ALLOW must be explicitly granted
3. **Precedence rules**: DENY always wins in conflicts
4. **Signature required**: Unsigned requests are rejected

### Runtime Invariant Validation

1. **Identity binding verification**: Identity must match public key
2. **Signature validation**: Every request signature is verified
3. **Decision validation**: Only valid decisions accepted
4. **Format validation**: Hashes, IDs, and timestamps are validated
5. **Chain integrity**: Audit log integrity checked on demand

### Design Principles

- **Fail securely**: Errors default to DENY
- **Explicit over implicit**: All security decisions are explicit
- **Verifiable**: All security properties can be verified
- **Auditable**: Complete decision history
- **Offline-first**: No network dependencies

These properties make LPIC suitable for:

- Air-gapped environments
- Safety-critical systems
- Compliance-sensitive applications
- Edge computing
- Embedded systems
- Security research

## License & Enterprise Usage

This project is open-source for **personal, educational, and non-commercial use** under the MIT License.

### Enterprise & Commercial Use

For enterprise or commercial deployments, a **nominal licensing fee** applies. This ensures sustainable development and priority support.

Please contact **Shivay** (or create a GitHub issue) for enterprise licensing details. We offer:

- Commercial-friendly license
- Priority bug fixes
- Custom feature development
- Integration support

### Contributing

This is a standalone reference implementation. For production use, conduct thorough security review and testing for your specific use case.
