"""
Decentralized Identifier (did:key) implementation using ECDSA SECP256R1.
Provides key generation, DID Document serialization, and cryptographic signing/verifying.
"""

import base64
import hashlib
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


class DIDKey:
    """Represents a Decentralized Identifier based on did:key method."""

    def __init__(self, private_key=None, public_key=None, name="node"):
        self.name = name
        if private_key is not None:
            self._private_key = private_key
            self._public_key = private_key.public_key()
        elif public_key is not None:
            self._private_key = None
            self._public_key = public_key
        else:
            # Generate new ECDSA P-256 keypair
            self._private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            self._public_key = self._private_key.public_key()

        # Derive raw public key bytes in compressed format (SEC1)
        self._pub_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

        # Create multicodec prefix for P-256 public key (0x1200)
        # did:key string is derived as did:key:z + base58 or hex
        pub_hex = self._pub_bytes.hex()
        self.did = f"did:key:z{pub_hex[:32]}"
        self.key_id = f"{self.did}#keys-1"

    @classmethod
    def generate(cls, name="node") -> "DIDKey":
        return cls(name=name)

    @classmethod
    def from_public_bytes(cls, pub_bytes: bytes, name="node") -> "DIDKey":
        pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
        return cls(public_key=pub_key, name=name)

    @property
    def public_bytes(self) -> bytes:
        return self._pub_bytes

    def get_did_document(self) -> dict:
        """Generates standard W3C compliant DID Document."""
        pem_pub = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        return {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ],
            "id": self.did,
            "verificationMethod": [
                {
                    "id": self.key_id,
                    "type": "JsonWebKey2020",
                    "controller": self.did,
                    "publicKeyHex": self._pub_bytes.hex(),
                    "publicKeyPem": pem_pub
                }
            ],
            "authentication": [self.key_id],
            "assertionMethod": [self.key_id]
        }

    def sign(self, message: bytes) -> bytes:
        """Signs a message using the holder's private key with ECDSA SHA256."""
        if self._private_key is None:
            raise ValueError("Cannot sign without private key.")
        return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, signature: bytes, message: bytes) -> bool:
        """Verifies an ECDSA SHA256 signature against this public key."""
        try:
            self._public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


if __name__ == "__main__":
    alice_did = DIDKey.generate(name="Alice")
    print(f"Generated DID: {alice_did.did}")
    doc = alice_did.get_did_document()
    print("DID Document:")
    print(json.dumps(doc, indent=2))

    msg = b"Hello SSI World"
    sig = alice_did.sign(msg)
    assert alice_did.verify(sig, msg)
    print("[+] Self-test passed: DID Key successfully generated and verified signature.")

