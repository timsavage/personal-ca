from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_FILE = "ca.key.pem"
CERT_FILE = "ca.crt.pem"


class CertificateAuthority:
    @classmethod
    def initialise(
            cls,
            path: Path,
            country: str,
            organisation: str,
            common_name: str = None,
            email: str = None,
            state: str = None,
            *,
            valid_from: datetime = None,
            valid_to: datetime = None,
            key_length: int = 2048
    ) -> "CertificateAuthority":
        """
        Initialise a new CA

        :param path: Path to store CA files
        :param country: 2 digit country code
        :param organisation: Name of the organisation
        :param common_name: Common name of CA (defaults to ``organisation CA``)
        :param email: Optional email address of CA
        :param state: Optional state of the CA
        :param valid_from: Date at which becomes valid; default is datetime.utcnow()
        :param valid_to: Date at which becomes valid; default is value_from + 5 years
        :param key_length: Length of key file

        """
        valid_from = valid_from or datetime.utcnow()
        valid_to = valid_to or (valid_from + timedelta(days=365 * 5))

        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        backend = default_backend()

        # Generate private key
        pkey = rsa.generate_private_key(public_exponent=65537, key_size=key_length, backend=backend)
        buf = pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        (path / KEY_FILE).write_bytes(buf)

        # Build your subject/issuer names
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organisation),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name or f"{organisation} CA"),
        ])
        ski = x509.SubjectKeyIdentifier.from_public_key(pkey.public_key())

        # Generate certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(pkey.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
            .add_extension(x509.BasicConstraints(True, None), critical=True)
            .add_extension(ski, critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
            .sign(pkey, hashes.SHA256(), backend)
        )

        # Save
        buf = cert.public_bytes(serialization.Encoding.PEM)
        (path / CERT_FILE).write_bytes(buf)

        return cls(cert)

    @classmethod
    def load(cls, path: Path) -> "CertificateAuthority":
        """
        Load certificate files from disk
        """
        buf = (path / CERT_FILE).read_bytes()
        cert = x509.load_pem_x509_certificate(buf, default_backend())
        return cls(cert)

    def __init__(self, cert: x509.Certificate):
        self.cert = cert

    def __str__(self):
        return f"{self.cert}"
