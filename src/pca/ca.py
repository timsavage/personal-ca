from datetime import datetime, timedelta
from pathlib import Path

from OpenSSL import crypto


KEY_FILE = "key.pem"
CERT_FILE = "crt.pem"


def _format_timestamp(dt: datetime) -> bytes:
    value = dt.strftime("%Y%m%d%H%M%SZ")
    return value.encode("charmap")


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
        path.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Generate private key
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, key_length)
        buf = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
        (path / KEY_FILE).write_bytes(buf)

        # Generate certificate
        cert = crypto.X509()

        # Configure subject
        subject = cert.get_subject()
        subject.countryName = country
        subject.organizationName = organisation
        subject.commonName = common_name or f"{organisation} CA"
        if email:
            subject.emailAddress = email
        if state:
            subject.stateOrProvinceName = state

        # Clone subject to issuer
        cert.set_issuer(subject)

        # Set valid window
        valid_from = valid_from or datetime.utcnow()
        cert.set_notBefore(_format_timestamp(valid_from))

        valid_to = valid_to or (valid_from + timedelta(days=365 * 5))
        cert.set_notAfter(_format_timestamp(valid_to))

        # Set extensions
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE")
        ])

        # Sign
        cert.sign(pkey, "sha256")

        # Save
        buf = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        (path / CERT_FILE).write_bytes(buf)

        return cls(cert)

    @classmethod
    def load(cls, path: Path) -> "CertificateAuthority":
        """
        Load certificate files from disk
        """
        buf = (path / CERT_FILE).read_bytes()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf)

        return cls(cert)

    def __init__(self, cert: crypto.X509):
        self.cert = cert

    def __str__(self):
        subject = self.cert.get_subject()
        for component in subject.get_components():
            print(component)
        return f""
