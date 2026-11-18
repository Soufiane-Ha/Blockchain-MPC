"""
Holder entity (e.g., Alice with an IoT wallet device or smartphone).
Stores Verifiable Credentials and produces Verifiable Presentations
with Selective Disclosure of claims.
"""

from typing import List, Dict, Any, Optional
from .did import DIDKey
from .credentials import VerifiablePresentation


class Holder:
    """Represents a credential Holder with an IoT digital wallet."""

    def __init__(self, name: str = "Alice"):
        self.name = name
        self.key = DIDKey.generate(name=name)
        self.did = self.key.did
        self.wallet: Dict[str, dict] = {}  # Stores holder bundles indexed by cred_id

    def store_credential(self, bundle: dict):
        """Stores a received credential bundle into the local wallet."""
        cred_id = bundle["credential"]["id"]
        self.wallet[cred_id] = bundle

    def create_presentation(
        self,
        credential_id: str,
        disclosed_claims: List[str],
        verifier_nonce: str
    ) -> dict:
        """
        Generates a Verifiable Presentation disclosing only the specified attributes.
        """
        if credential_id not in self.wallet:
            raise ValueError(f"Credential '{credential_id}' not found in holder wallet.")

        bundle = self.wallet[credential_id]
        vp = VerifiablePresentation.create_presentation(
            holder_key=self.key,
            holder_bundle=bundle,
            disclosed_claims=disclosed_claims,
            verifier_nonce=verifier_nonce
        )
        return vp

