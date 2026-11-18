"""
Verifiable Credentials (VC) and Verifiable Presentations (VP)
with Selective Disclosure via Salted Commitments (SD-JWT mechanism).
"""

import hashlib
import json
import os
import secrets
import time
from typing import Dict, Any, List, Optional


def compute_commitment(salt: str, claim_name: str, claim_value: Any) -> str:
    """Computes SHA-256 salted commitment: H(salt || claim_name || json(claim_value))."""
    val_str = json.dumps(claim_value, sort_keys=True)
    preimage = f"{salt}:{claim_name}:{val_str}".encode("utf-8")
    return hashlib.sha256(preimage).hexdigest()


class VerifiableCredential:
    """W3C-compliant Verifiable Credential with Salted Commitments for Selective Disclosure."""

    def __init__(
        self,
        credential_id: str,
        issuer_did: str,
        holder_did: str,
        claims: Dict[str, Any],
        issuance_date: Optional[str] = None
    ):
        self.credential_id = credential_id
        self.issuer_did = issuer_did
        self.holder_did = holder_did
        self.claims = claims
        self.issuance_date = issuance_date or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Generate unique cryptographic salt for each claim
        self.salts: Dict[str, str] = {}
        self.commitments: Dict[str, str] = {}

        for k, v in self.claims.items():
            salt = secrets.token_hex(16)  # 128-bit random salt
            self.salts[k] = salt
            self.commitments[k] = compute_commitment(salt, k, v)

        self.signature_hex: Optional[str] = None

    def get_canonical_payload(self) -> bytes:
        """Returns deterministic serialized bytes for cryptographic signing."""
        payload = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": self.credential_id,
            "type": ["VerifiableCredential", "IoTSmartCityCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": self.issuance_date,
            "credentialSubject": {
                "id": self.holder_did,
                "commitments": self.commitments  # Commitments are signed, not plaintext claims!
            }
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def sign(self, issuer_key):
        """Issuer signs the canonical payload containing salted commitments."""
        canonical_bytes = self.get_canonical_payload()
        sig = issuer_key.sign(canonical_bytes)
        self.signature_hex = sig.hex()

    def to_dict(self) -> dict:
        """Serializes the full signed credential."""
        return {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": self.credential_id,
            "type": ["VerifiableCredential", "IoTSmartCityCredential"],
            "issuer": self.issuer_did,
            "issuanceDate": self.issuance_date,
            "credentialSubject": {
                "id": self.holder_did,
                "commitments": self.commitments
            },
            "proof": {
                "type": "EcdsaSecp256r1Signature2026",
                "created": self.issuance_date,
                "verificationMethod": f"{self.issuer_did}#keys-1",
                "proofPurpose": "assertionMethod",
                "signatureHex": self.signature_hex
            }
        }

    def get_holder_bundle(self) -> dict:
        """Bundle provided to the holder containing plain claims and salts."""
        return {
            "credential": self.to_dict(),
            "claims": self.claims,
            "salts": self.salts
        }


class VerifiablePresentation:
    """Verifiable Presentation created by Holder with Selective Disclosure."""

    @staticmethod
    def create_presentation(
        holder_key,
        holder_bundle: dict,
        disclosed_claims: List[str],
        verifier_nonce: str
    ) -> dict:
        """
        Holder reveals ONLY attributes in `disclosed_claims`.
        All other attributes remain concealed (only commitments are provided).
        """
        cred_dict = holder_bundle["credential"]
        all_claims = holder_bundle["claims"]
        all_salts = holder_bundle["salts"]
        commitments = cred_dict["credentialSubject"]["commitments"]

        revealed = {}
        for claim_name in disclosed_claims:
            if claim_name in all_claims:
                revealed[claim_name] = {
                    "value": all_claims[claim_name],
                    "salt": all_salts[claim_name]
                }

        presentation_id = f"urn:uuid:{secrets.token_hex(8)}"
        created_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        vp_payload = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": presentation_id,
            "type": ["VerifiablePresentation"],
            "holder": holder_key.did,
            "verifier_nonce": verifier_nonce,
            "created": created_time,
            "verifiableCredential": {
                "id": cred_dict["id"],
                "issuer": cred_dict["issuer"],
                "issuanceDate": cred_dict["issuanceDate"],
                "all_commitments": commitments,  # Full commitment tree
                "revealed_claims": revealed,     # Disclosed claims + salts
                "concealed_claim_names": [k for k in commitments.keys() if k not in disclosed_claims],
                "issuer_proof": cred_dict["proof"]
            }
        }

        # Holder signs the presentation payload to prove key ownership & bind to verifier nonce
        canonical_vp = json.dumps(vp_payload, sort_keys=True).encode("utf-8")
        holder_sig = holder_key.sign(canonical_vp)

        return {
            "presentation": vp_payload,
            "holder_proof": {
                "type": "EcdsaSecp256r1Signature2026",
                "verificationMethod": holder_key.key_id,
                "proofPurpose": "authentication",
                "signatureHex": holder_sig.hex()
            }
        }

