"""
Issuer entity (e.g., Municipality, Energy Authority, or University).
Issues digitally signed Verifiable Credentials to holders and manages revocation.
"""

import uuid
from typing import Dict, Any
from .did import DIDKey
from .credentials import VerifiableCredential
from .revocation import RevocationRegistry


class Issuer:
    """Represents a trusted Issuer in the Self-Sovereign Identity framework."""

    def __init__(self, name: str = "CityMunicipality"):
        self.name = name
        self.key = DIDKey.generate(name=name)
        self.did = self.key.did
        self.revocation_registry = RevocationRegistry(self.key)
        self.issued_credentials: Dict[str, dict] = {}

    def issue_credential(self, holder_did: str, claims: Dict[str, Any]) -> dict:
        """
        Issues a new Verifiable Credential with salted commitments to the holder.
        """
        cred_id = f"urn:uuid:{uuid.uuid4()}"
        vc = VerifiableCredential(
            credential_id=cred_id,
            issuer_did=self.did,
            holder_did=holder_did,
            claims=claims
        )
        vc.sign(self.key)

        bundle = vc.get_holder_bundle()
        self.issued_credentials[cred_id] = bundle
        return bundle

    def revoke_credential(self, credential_id: str):
        """Revokes an issued credential in the registry."""
        self.revocation_registry.revoke(credential_id)

    def get_signed_revocation_list(self) -> dict:
        """Exports the current signed revocation list."""
        return self.revocation_registry.export_signed_revocation_list()

