
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"
CERTS = ROOT / "certificates"

KEYS.mkdir(parents=True, exist_ok=True)
CERTS.mkdir(parents=True, exist_ok=True)

key_path = KEYS / "ca_private_key.pem"
cert_path = CERTS / "ca_certificate.pem"

# Avoid accidentally replacing an existing CA identity.
if key_path.exists() or cert_path.exists():
    raise SystemExit(
        "CA files already exist. Back them up and inspect them first."
    )

# 1. Generate the CA private key.
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072,
)

# 2. Define the CA identity.
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "DZ"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Blockchain MPC Lab"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Blockchain MPC Root CA"),
])

# 3. Create a self-signed root certificate.
now = datetime.now(timezone.utc)

certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + timedelta(days=3650))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=1),
        critical=True,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=None,
            decipher_only=None,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(
            private_key.public_key()
        ),
        critical=False,
    )
    .sign(private_key, hashes.SHA256())
)

# 4. Save the private key and root certificate.
key_path.write_bytes(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

cert_path.write_bytes(
    certificate.public_bytes(serialization.Encoding.PEM)
)

print("CA created successfully.")
print(f"Private key: {key_path}")
print(f"Root certificate: {cert_path}")
print(f"Subject: {certificate.subject.rfc4514_string()}")
print(f"Serial number: {certificate.serial_number}")
print(f"Valid until: {certificate.not_valid_after_utc}")
print(f"Certificate CA flag: {certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca}")