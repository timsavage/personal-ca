from pathlib import Path
from OpenSSL import crypto
from .ca import CertificateAuthority


def init_ca(path: Path, key_length: int = 2048) -> int:
    """
    Initialise CA
    """

    ca = CertificateAuthority.initialise(
        path, "AU", "Savage.Company", email="tim@savage.company", state="New South Wales", key_length=key_length
    )

    print(ca)

    return 0


def ca_info(path: Path):
    pass
