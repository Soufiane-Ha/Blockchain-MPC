"""
Part B Unified Demonstration: Self-Sovereign Identity (SSI) Flow.
Demonstrates:
1. DID generation for Issuer, Holder, and Verifier.
2. Verifiable Credential issuance with Salted Commitments.
3. Selective Disclosure (Holder reveals only required attributes).
4. Offline verification by Smart Lock.
5. Tampering attack detection.
6. Revocation mechanism enforcement.
7. Comparison with OAuth 2.0.
"""

import json
import os
import sys

# Ensure ssi package is discoverable
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from ssi.issuer import Issuer
from ssi.holder import Holder
from ssi.verifier import Verifier


def main():
    print("\n" + "#" * 80)
    print("      TP3 - PART B: SELF-SOVEREIGN IDENTITY (SSI) & SELECTIVE DISCLOSURE")
    print("#" * 80)

    # 1. Initialize Roles
    print("\n--- 1. INITIALIZING SSI ROLES & DECENTRALIZED IDENTIFIERS (DIDs) ---")
    issuer = Issuer(name="ParisMunicipality")
    alice = Holder(name="Alice")
    smart_lock = Verifier(name="SmartLock_BuildingA")

    print(f"[+] Issuer DID:     {issuer.did}")
    print(f"[+] Holder DID:     {alice.did}")
    print(f"[+] Verifier DID:   {smart_lock.did}")

    # 2. Issuer signs a Verifiable Credential with multiple attributes
    print("\n--- 2. ISSUER ISSUES VERIFIABLE CREDENTIAL (WITH SALTED COMMITMENTS) ---")
    alice_claims = {
        "over_18": True,
        "city_resident": "Paris",
        "clearance_level": "Level_3",
        "national_id": "FR-987654321",
        "medical_status": "NoChronicCondition"
    }
    print("[*] Raw Claims to be certified:")
    for k, v in alice_claims.items():
        print(f"    - {k}: {v}")

    bundle = issuer.issue_credential(holder_did=alice.did, claims=alice_claims)
    cred_id = bundle["credential"]["id"]
    print(f"\n[+] Issued Credential ID: {cred_id}")
    print("[+] Issuer generated cryptographic salt for each claim:")
    for k, salt in bundle["salts"].items():
        print(f"    - Salt for '{k}': {salt[:16]}... -> Commitment: {bundle['credential']['credentialSubject']['commitments'][k][:20]}...")
    print(f"[+] Issuer ECDSA Signature: {bundle['credential']['proof']['signatureHex'][:40]}...")

    # Alice stores credential in her IoT wallet
    alice.store_credential(bundle)
    print("[+] Alice successfully received and stored credential in her local IoT wallet.")

    # 3. Verifier issues a challenge and requests specific attributes
    print("\n--- 3. SELECTIVE DISCLOSURE VERIFIABLE PRESENTATION ---")
    nonce = smart_lock.generate_challenge()
    print(f"[*] Smart Lock generated challenge nonce: {nonce}")
    print("[*] Smart Lock requires: ONLY 'over_18' and 'clearance_level'.")
    print("[*] Smart Lock MUST NOT learn: 'national_id', 'city_resident', or 'medical_status'!")

    # Alice creates a presentation with selective disclosure
    vp = alice.create_presentation(
        credential_id=cred_id,
        disclosed_claims=["over_18", "clearance_level"],
        verifier_nonce=nonce
    )

    print("\n[+] Alice generated Verifiable Presentation (VP):")
    revealed_keys = list(vp["presentation"]["verifiableCredential"]["revealed_claims"].keys())
    concealed_keys = vp["presentation"]["verifiableCredential"]["concealed_claim_names"]
    print(f"    - Disclosed to Smart Lock: {revealed_keys}")
    print(f"    - Concealed (Zero-Knowledge / Blinded): {concealed_keys}")

    # 4. Smart Lock Offline Verification
    print("\n--- 4. SMART LOCK OFFLINE VERIFICATION ---")
    trusted_issuers = {issuer.did: issuer.key}
    valid, message, claims = smart_lock.verify_presentation(
        presentation_dict=vp,
        expected_nonce=nonce,
        trusted_issuers=trusted_issuers,
        revocation_registry=issuer.revocation_registry
    )

    print(f"[*] Result: {'SUCCESS' if valid else 'FAILED'}")
    print(f"[*] Message: {message}")
    print(f"[+] Verified Claims learned by Smart Lock: {claims}")
    if valid and claims.get("over_18") is True and claims.get("clearance_level") == "Level_3":
        print("\n>>> [ACCESS GRANTED] Smart Lock OPENED for Alice! <<<")
    else:
        print("\n>>> [ACCESS DENIED] Smart Lock remained locked! <<<")

    # 5. Tampering Attack Demonstration
    print("\n--- 5. SECURITY ATTACK SIMULATION: CLAIM TAMPERING ---")
    tampered_vp = json.loads(json.dumps(vp))  # deep copy
    # Attacker tries to elevate clearance level to Level_5
    tampered_vp["presentation"]["verifiableCredential"]["revealed_claims"]["clearance_level"]["value"] = "Level_5"
    print("[!] Attacker modified 'clearance_level' from 'Level_3' to 'Level_5'.")

    t_valid, t_msg, _ = smart_lock.verify_presentation(
        presentation_dict=tampered_vp,
        expected_nonce=nonce,
        trusted_issuers=trusted_issuers,
        revocation_registry=issuer.revocation_registry
    )
    print(f"[*] Verifier Decision: {'ACCEPTED' if t_valid else 'BLOCKED'}")
    print(f"[*] Verifier Message:  {t_msg}")

    # 6. Revocation Demonstration
    print("\n--- 6. REVOCATION MECHANISM DEMONSTRATION ---")
    print(f"[*] Issuer revoking credential ID: {cred_id} (e.g. key compromised / revoked clearance)...")
    issuer.revoke_credential(cred_id)
    rev_list = issuer.get_signed_revocation_list()
    print(f"[+] Published Revocation Status List (Version {rev_list['payload']['version']}):")
    print(f"    - Revoked IDs: {rev_list['payload']['revoked_credentials']}")

    print("\n[*] Alice attempts to access the Smart Lock again using the revoked credential...")
    new_nonce = smart_lock.generate_challenge()
    vp_revoked = alice.create_presentation(
        credential_id=cred_id,
        disclosed_claims=["over_18", "clearance_level"],
        verifier_nonce=new_nonce
    )

    r_valid, r_msg, _ = smart_lock.verify_presentation(
        presentation_dict=vp_revoked,
        expected_nonce=new_nonce,
        trusted_issuers=trusted_issuers,
        revocation_registry=issuer.revocation_registry
    )
    print(f"[*] Verifier Decision: {'ACCEPTED' if r_valid else 'BLOCKED'}")
    print(f"[*] Verifier Message:  {r_msg}")

    # 7. Comparison with Centralized OAuth 2.0
    print("\n" + "=" * 80)
    print("      ARCHITECTURAL COMPARISON: SSI vs CENTRALIZED OAUTH 2.0")
    print("=" * 80)
    comparison_table = [
        ("Criterion", "Centralized OAuth 2.0 (Google/FB)", "Self-Sovereign Identity (SSI)"),
        ("-" * 25, "-" * 32, "-" * 32),
        ("IdP Tracking / Surveillance", "IdP logs every login, time, & service", "IdP has ZERO knowledge of presentations"),
        ("Single Point of Failure", "Yes (IdP outage blocks all services)", "No (Credentials verified offline)"),
        ("Selective Disclosure", "All or nothing (Scopes coarse-grained)", "Cryptographic attribute-level disclosure"),
        ("Trust Anchor", "Centralized Identity Provider", "Decentralized / Asymmetric Cryptography"),
        ("IoT Constrained Suitability", "Requires continuous cloud connection", "Fully offline verification supported")
    ]
    for row in comparison_table:
        print(f"{row[0]:<28} | {row[1]:<38} | {row[2]}")
    print("=" * 80)


if __name__ == "__main__":
    main()

