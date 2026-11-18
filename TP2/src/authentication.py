
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from certificate_manager import CertificateManager


BASE = Path(__file__).resolve().parent.parent
KEY_DIR = BASE / "keys"
NODES = ["alice", "bob", "carol", "dave"]

class NodeAuthentication:

    def __init__(self, node_name):

        self.node = node_name.lower()

        if self.node not in ["alice", "bob", "carol", "dave"]:
            raise ValueError("Unknown node")

        self.manager = CertificateManager()

        # Load RSA identity certificate
        cert_path = BASE / "certificates" / f"{self.node}_certificate.pem"

        self.identity_certificate = x509.load_pem_x509_certificate(
            cert_path.read_bytes()
        )

        # Load RSA privatekey
        key_path = KEY_DIR / self.node / f"{self.node}_private_key.pem"
        self.private_key = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=None
        )

        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("RSA identity private key required")

        # Verify certificate public key matches private key
        public_bytes = self.identity_certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        private_public_bytes = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if public_bytes != private_public_bytes:
            raise ValueError("Identity key mismatch")

        # Verify our own certificate
        self.manager.verify_ca_signature(self.identity_certificate)
        self.manager.verify_validity(self.identity_certificate)

    def create_challenge(self):
        return secrets.token_bytes(32)

    def sign_challenge(self, challenge):

        return self.private_key.sign(
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    @staticmethod
    def verify_challenge(peer_certificate, challenge, signature):

        public_key = peer_certificate.public_key()

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Expected RSA identity certificate")

        public_key.verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True


def get_common_name(certificate):

    names = certificate.subject.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME
    )

    if not names:
        raise ValueError("Certificate has no Common Name")

    return names[0].value.lower()


def mutual_authentication(node_a, node_b):

    print(f"\n========== {node_a.upper()} <-> {node_b.upper()} ==========")

    alice = NodeAuthentication(node_a)
    bob = NodeAuthentication(node_b)

    alice_cert = alice.identity_certificate
    bob_cert = bob.identity_certificate

    # Verify expected peer identities
    if get_common_name(bob_cert) != node_b.lower():
        raise ValueError("Peer identity mismatch")

    if get_common_name(alice_cert) != node_a.lower():
        raise ValueError("Peer identity mismatch")

    print("[1] Both certificates verified")

    # Alice challenges Bob
    challenge_a = alice.create_challenge()
    response_b = bob.sign_challenge(challenge_a)

    alice.verify_challenge(
        bob_cert,
        challenge_a,
        response_b
    )

    print(f"[2] {node_b.upper()} proved identity to {node_a.upper()}")

    # Bob challenges Alice
    challenge_b = bob.create_challenge()
    response_a = alice.sign_challenge(challenge_b)

    bob.verify_challenge(
        alice_cert,
        challenge_b,
        response_a
    )

    print(f"[3] {node_a.upper()} proved identity to {node_b.upper()}")

    print("[SUCCESS] Mutual authentication completed")


if __name__ == "__main__":

    mutual_authentication("alice", "bob")
    mutual_authentication("alice", "carol")
    mutual_authentication("alice", "dave")
