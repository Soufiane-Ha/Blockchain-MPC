from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parent.parent
CERT_FILE = ROOT / "certificates" / "ca_certificate.pem"

cert = x509.load_pem_x509_certificate(CERT_FILE.read_bytes())

# Verify the self-signature using the certificate's own public key.
public_key = cert.public_key()
public_key.verify(
    cert.signature,
    cert.tbs_certificate_bytes,
    padding.PKCS1v15(),
    cert.signature_hash_algorithm,
)

constraints = cert.extensions.get_extension_for_class(
    x509.BasicConstraints
).value

assert cert.subject == cert.issuer
assert constraints.ca is True

print("Self-signature: VALID")
print("Subject equals issuer: YES")
print("CA certificate: YES")
print("Signature hash:", cert.signature_hash_algorithm.name)
