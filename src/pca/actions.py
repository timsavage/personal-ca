from pathlib import Path
from OpenSSL import crypto
from .ca import CertificateAuthority


def init_ca(path: Path, pkey_bits: int = 2048) -> int:
    """
    Initialise CA
    """

    # Check if CA folder is empty
    if path.is_dir() and list(path.iterdir()):
        print("Target not empty.")
        return 1

    ca = CertificateAuthority.initialise(
        path / "ca", "AU", "Savage.Company", email="tim@savage.company", state="New South Wales", key_length=pkey_bits
    )

    print(ca)

    return 0


def ca_info(path: Path):
    pass
