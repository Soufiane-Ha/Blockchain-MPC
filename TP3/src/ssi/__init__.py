"""
Self-Sovereign Identity (SSI) package for TP3.
Implements:
- Decentralized Identifiers (did:key)
- Verifiable Credentials with Selective Disclosure (Salted Commitments / SD-JWT)
- Offline Verification
- Cryptographic Revocation
"""

from .did import DIDKey
from .revocation import RevocationRegistry
from .credentials import VerifiableCredential, VerifiablePresentation
from .issuer import Issuer
from .holder import Holder
from .verifier import Verifier

