from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
KEYS = ROOT / "keys"
CERTS = ROOT / "certificates"

CA_KEY_FILE = KEYS / "ca_private_key.pem"
CA_CERT_FILE = CERTS / "ca_certificate.pem"

NODES = ["Alice", "Bob", "Carol", "Dave"]

if not CA_KEY_FILE.exists() or not CA_CERT_FILE.exists():
    raise SystemExit("CA files not found. Create the CA first.")

ca_key = serialization.load_pem_private_key(
    CA_KEY_FILE.read_bytes(),
    password=None,
)
ca_cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())

# Ensure the CA private key matches the root certificate.
if (
    ca_key.public_key().public_numbers()
    != ca_cert.public_key().public_numbers()
):
    raise SystemExit("CA private key does not match the root certificate.")

now = datetime.now(timezone.utc)

for node in NODES:
    key_file = KEYS / f"{node.lower()}_private_key.pem"
    csr_file = CERTS / f"{node.lower()}.csr.pem"
    cert_file = CERTS / f"{node.lower()}_certificate.pem"

    # Never silently replace an existing node identity.
    if any(path.exists() for path in (key_file, csr_file, cert_file)):
        raise SystemExit(
            f"Files already exist for {node}. Inspect them before retrying."
        )

    # Generate the node's private key.
    node_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DZ"),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME, "Blockchain MPC Lab"
        ),
        x509.NameAttribute(NameOID.COMMON_NAME, node),
    ])

    # The node signs its CSR using its own private key.
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(node_key, hashes.SHA256())
    )

    if not csr.is_signature_valid:
        raise SystemExit(f"Invalid CSR signature for {node}")

    # The CA issues a certificate for this node.
    certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    key_file.write_bytes(
        node_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    csr_file.write_bytes(
        csr.public_bytes(serialization.Encoding.PEM)
    )

    cert_file.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )

    print(f"{node}: CSR created and certificate issued.")

print("All node certificates issued successfully.")
