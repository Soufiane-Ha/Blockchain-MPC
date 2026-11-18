
from pathlib import Path
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    rsa, ec, ed25519, ed448, padding
)

BASE = Path(__file__).resolve().parent.parent
CERT_DIR = BASE / "certificates"

NODES = ["alice", "bob", "carol", "dave"]


class CertificateManager:

    def __init__(self):
        ca_path = CERT_DIR / "ca_certificate.pem"

        self.ca = x509.load_pem_x509_certificate(
            ca_path.read_bytes()
        )

        if not isinstance(self.ca.public_key(), rsa.RSAPublicKey):
            raise ValueError("Expected RSA CA certificate")

    def verify_ca_signature(self, cert):
        public_key = self.ca.public_key()

        if cert.issuer != self.ca.subject:
            raise ValueError("Unknown certificate issuer")

        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )

    def verify_validity(self, cert):
        now = datetime.now(timezone.utc)

        if now < cert.not_valid_before_utc:
            raise ValueError("Certificate not yet valid")

        if now > cert.not_valid_after_utc:
            raise ValueError("Certificate expired")

    def verify_identity(self, cert, expected_node):
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value

            identity = san.get_values_for_type(
                x509.UniformResourceIdentifier
            )

        except x509.ExtensionNotFound:
            raise ValueError("Missing node identity")

        expected = f"urn:blockchain-mpc:node:{expected_node}"

        if expected not in identity:
            raise ValueError("Node identity mismatch")

    def verify_key_type(self, cert):
        public_key = cert.public_key()

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Expected ECDSA public key")

        if not isinstance(public_key.curve, ec.SECP256K1):
            raise ValueError("Expected secp256k1 curve")

    def verify_key_usage(self, cert):
        try:
            usage = cert.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value

            if not usage.digital_signature:
                raise ValueError("Digital signature not permitted")

        except x509.ExtensionNotFound:
            raise ValueError("Missing KeyUsage extension")

    def verify_crl(self, cert):
        crl_path = CERT_DIR / "crl.pem"

        if not crl_path.exists():
            raise ValueError("CRL missing - certificate cannot be trusted")

        crl = x509.load_pem_x509_crl(crl_path.read_bytes())

        if crl.issuer != self.ca.subject:
            raise ValueError("CRL issuer mismatch")

        self.ca.public_key().verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding.PKCS1v15(),
            crl.signature_hash_algorithm
        )

        now = datetime.now(timezone.utc)

        if now < crl.last_update_utc:
            raise ValueError("CRL not yet valid")

        if crl.next_update_utc is None or now > crl.next_update_utc:
            raise ValueError("CRL expired")

        if crl.get_revoked_certificate_by_serial_number(
            cert.serial_number
        ):
            raise ValueError("Certificate revoked")

    def verify_node(self, node):
        node = node.lower()

        if node not in NODES:
            raise ValueError("Unknown node")

        cert_path = CERT_DIR / f"{node}_tx_certificate.pem"

        cert = x509.load_pem_x509_certificate(
            cert_path.read_bytes()
        )

        self.verify_ca_signature(cert)
        self.verify_validity(cert)
        self.verify_identity(cert, node)
        self.verify_key_type(cert)
        self.verify_key_usage(cert)
        self.verify_crl(cert)

        return cert


if __name__ == "__main__":

    manager = CertificateManager()

    for node in NODES:
        print(f"\nChecking {node.upper()}...")

        try:
            manager.verify_node(node)
            print(f"[ACCEPTED] {node.upper()} certificate valid")

        except Exception as error:
            print(f"[REJECTED] {node.upper()}: {error}")
