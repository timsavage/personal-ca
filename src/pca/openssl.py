import subprocess

from pathlib import Path
from typing import Any, Union


def _execute_openssl(cmd: str, *params: Union[str, Path]):
    """
    Execute an openssl command
    """
    args = ["openssl", cmd] + list(params)
    result = subprocess.run(args)
    print(result)


def genrsa(out: Path):
    """
    Generate an RSA key
    """
    _execute_openssl("genrsa", "-out", out)


def der_encode_cert(in_file: Path, out_file: Path):
    """
    Re-encode an PEM encoded x509 certificate into DER encoding
    """
    _execute_openssl("x509", "-in", in_file, "-outform", "DER", "-out", out_file)


def der_encode_rsa_key(in_file: Path, out_file: Path):
    """
    Re-encode a PEM encoded RSA Key into DER encoding
    """
