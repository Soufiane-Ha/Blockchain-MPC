
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa, ec, ed25519, ed448, padding
)

BASE = Path(__file__).resolve().parent.parent
CERT_DIR = BASE / "certificates"
KEY_DIR = BASE / "keys"

def verify_ca_signature(cert, ca_cert):
    public_key = ca_cert.public_key()
    algorithm = cert.signature_hash_algorithm

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            algorithm
        )

    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(algorithm)
        )

    elif isinstance(public_key, (ed25519.Ed25519PublicKey,
                                 ed448.Ed448PublicKey)):
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes
        )

    else:
        raise ValueError("Unsupported CA public key")

def key_type(key):
    if isinstance(key, rsa.RSAPrivateKey):
        return "RSA"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return f"ECDSA ({key.curve.name})"
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "Ed25519"
    return type(key).__name__

def main():
    ca_path = CERT_DIR / "ca_certificate.pem"
    ca = x509.load_pem_x509_certificate(ca_path.read_bytes())

    print("\n========== CA ==========")
    print("Subject:", ca.subject.rfc4514_string())
    print("Public key:", key_type(ca.public_key()))

    nodes = ["alice", "bob", "carol", "dave"]

    for name in nodes:
        print(f"\n========== {name.upper()} ==========")

        cert_path = CERT_DIR / f"{name}_certificate.pem"
        key_path = KEY_DIR / f"{name}_private_key.pem"

        cert = x509.load_pem_x509_certificate(
            cert_path.read_bytes()
        )

        private_key = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=None
        )

        print("Subject:", cert.subject.rfc4514_string())
        print("Issuer:", cert.issuer.rfc4514_string())
        print("Certificate public key:", key_type(cert.public_key()))
        print("Private key:", key_type(private_key))

        try:
            verify_ca_signature(cert, ca)
            print("CA Signature: VALID")
        except Exception as error:
            print("CA Signature: INVALID", repr(error))

        try:
            cert_public = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            private_public = private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )

            print(
                "Private/Public Key Match:",
                "YES" if cert_public == private_public else "NO"
            )
        except Exception as error:
            print("Key comparison error:", error)

if __name__ == "__main__":
    main()
