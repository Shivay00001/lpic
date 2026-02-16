from lpic import LPICEngine, Keypair, sign_request, DECISION_ALLOW
import os

# Clean up previous demo db if exists
if os.path.exists("demo.db"):
    os.remove("demo.db")

print("--- LPIC Live Demo ---")

# 1. Initialize Engine
engine = LPICEngine("demo.db")
print("[+] Engine initialized with demo.db")

# 2. Create Identity
keypair = Keypair.generate()
identity_id = engine.register_identity(keypair, metadata={"name": "Alice"})
print(f"[+] Registered Identity: {identity_id[:8]}... (Alice)")

# 3. Add Policy
policy_id = engine.add_policy(
    subject=identity_id,
    resource="file://secret.txt",
    action="read",
    decision=DECISION_ALLOW
)
print(f"[+] Added Policy: {policy_id[:8]}... ALLOW read file://secret.txt")

# 4. Create Signed Request
print("[*] creating signed request...")
request = sign_request(
    keypair=keypair,
    resource="file://secret.txt",
    action="read",
    context={"ip": "127.0.0.1"}
)

# 5. Authorize
decision = engine.authorize(request)
print(f"[+] Authorization Result: {decision}")

# 6. Verify Audit Log
log = engine.get_audit_log()
print(f"[+] Audit Log Entries: {len(log)}")
print(f"    - Action: {log[0]['action']}")
print(f"    - Decision: {log[0]['decision']}")

engine.close()
if os.path.exists("demo.db"):
    os.remove("demo.db")
print("--- Demo Complete ---")
