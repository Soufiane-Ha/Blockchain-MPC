
from transaction import create_transaction
from signature_manager import (
    sign_transaction,
    verify_transaction
)


print("\n========== CERTIFICATE-BASED TRANSACTION TEST ==========")

# Alice creates transaction
tx = create_transaction(
    sender="alice",
    receiver="bob",
    amount=100,
    nonce=1
)

print("[1] Transaction created by ALICE")

# Alice signs transaction
tx["signature"] = sign_transaction(tx)

print("[2] Transaction signed by ALICE")

# Bob verifies Alice certificate and transaction signature
if verify_transaction(tx):
    print("[3] Alice certificate verified by CA")
    print("[4] ECDSA signature verified")
    print("[SUCCESS] Transaction accepted")
else:
    print("[REJECTED] Transaction rejected")


# Attack: modify amount
tampered_tx = tx.copy()
tampered_tx["amount"] = 5000

print("\n========== TAMPERING ATTACK ==========")

if not verify_transaction(tampered_tx):
    print("[ATTACK BLOCKED] Tampered amount rejected")
else:
    print("[SECURITY FAILURE] Tampered transaction accepted")
