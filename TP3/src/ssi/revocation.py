"""
Cryptographic Revocation Registry for Verifiable Credentials.
Allows an Issuer to publish a tamper-proof, signed Revocation List.
Verifiers verify the Issuer's signature on the Revocation List and check
whether a credential ID is active or revoked.
"""

import json
import time
from typing import Set, Dict, Any


class RevocationRegistry:
    """Maintains a signed list of revoked credential identifiers."""

    def __init__(self, issuer_did):
        self.issuer_did = issuer_did
        self.revoked_ids: Set[str] = set()
        self.version: int = 1
        self.last_updated: float = time.time()

    def revoke(self, credential_id: str):
        """Marks a credential ID as revoked."""
        self.revoked_ids.add(credential_id)
        self.version += 1
        self.last_updated = time.time()

    def unrevoke(self, credential_id: str):
        """Un-revokes a credential (if allowed)."""
        if credential_id in self.revoked_ids:
            self.revoked_ids.remove(credential_id)
            self.version += 1
            self.last_updated = time.time()

    def is_revoked(self, credential_id: str) -> bool:
        """Checks if a credential ID is currently revoked."""
        return credential_id in self.revoked_ids

    def export_signed_revocation_list(self) -> Dict[str, Any]:
        """
        Creates and signs a cryptographic Revocation Status List.
        """
        payload = {
            "type": "RevocationStatusList2026",
            "issuer": self.issuer_did.did,
            "version": self.version,
            "last_updated": self.last_updated,
            "revoked_credentials": sorted(list(self.revoked_ids))
        }

        canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        signature = self.issuer_did.sign(canonical_bytes)

        return {
            "payload": payload,
            "proof": {
                "type": "EcdsaSecp256r1Signature2026",
                "verificationMethod": self.issuer_did.key_id,
                "signatureHex": signature.hex()
            }
        }

    @staticmethod
    def verify_signed_revocation_list(signed_list: Dict[str, Any], issuer_did) -> bool:
        """Verifies that the revocation list is authentically signed by the issuer."""
        try:
            payload = signed_list["payload"]
            canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
            sig_bytes = bytes.fromhex(signed_list["proof"]["signatureHex"])
            return issuer_did.verify(sig_bytes, canonical_bytes)
        except Exception:
            return False

