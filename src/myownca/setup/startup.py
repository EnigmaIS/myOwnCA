"""Non-provisioning checks for an installation whose setup is complete."""

from pathlib import Path

from cryptography import x509
from sqlalchemy.engine import make_url

from myownca.ca_hsm.base import public_keys_match
from myownca_core.storage.database import sqlite_file_path


def require_existing_database(target: str | Path) -> None:
    """Reject missing SQLite storage before Database can create it.

    Remote databases are opened normally: connection errors must propagate,
    and Database does not create remote databases.
    """
    if "://" in str(target):
        url = make_url(str(target))
        if url.get_backend_name() != "sqlite":
            return
        args, kwargs = url.get_dialect()().create_connect_args(url)
        path = sqlite_file_path(args[0], uri=bool(kwargs.get("uri")))
    else:
        path = Path(target)
    if path is None or not path.is_file():
        raise ValueError("The configured installation requires its existing database")


def require_existing_issuer(repository, backend, backend_name: str, *, lab_mode: bool = False) -> None:
    """Check persisted software keys without requiring an HSM PIN at boot."""
    active = repository.get_active_sub_ca()
    if active is None:
        raise ValueError("The configured installation has no active issuing CA")
    certificate = x509.load_pem_x509_certificate(active.certificate_pem.encode())
    if backend_name == "software":
        if not public_keys_match(backend.public_key(active.key_ref), certificate.public_key()):
            raise ValueError("The issuing CA key does not match its certificate")
        if lab_mode:
            # The runtime also loads the Lab fallback chain. Check both keys
            # before that path can attempt generation, including an absent root.
            backend.public_key("lab-root")
            backend.public_key("lab-issuer")
