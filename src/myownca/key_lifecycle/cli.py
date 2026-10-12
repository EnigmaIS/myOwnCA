from __future__ import annotations

import argparse
import getpass
import sys
import urllib.parse
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from myownca.ca_hsm import HSMPinVault, create_hsm
from myownca.ca_main.server_keys import RequestKeyVault
from myownca.cloud import CloudKeyOwnership, CloudKeyRepository, CloudKeyStatus
from myownca.config import Settings
from myownca.key_lifecycle.base import KeyCleanupError, KeyOwnership, KeyStatus, RegisteredKey
from myownca.key_lifecycle.repository import KeyLifecycleRepository
from myownca.key_lifecycle.service import (
    DEFAULT_STALE_CLEANUP_AFTER,
    KeyLifecycleService,
)
from myownca.service_certs import KeyBackend, ServiceKeyStore
from myownca.storage.database import Database
from myownca.storage.repositories import PKIRepository


_CLI_PIN_SESSION = "key-cleanup-cli"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="myownca-key-cleanup",
        description=(
            "Preview or execute the idempotent cleanup of explicitly registered, "
            "due private keys."
        ),
    )
    parser.add_argument(
        "--database-path",
        type=Path,
        help="SQLite database path (defaults to MYOWNCA_DATABASE_URL/PATH)",
    )
    parser.add_argument(
        "--limit",
        type=_positive_int,
        default=100,
        help="maximum keys to process in one pass (default: 100)",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="perform provider cleanup; without this flag the command is read-only",
    )
    return parser


def run(
    argv: list[str] | None = None,
    *,
    settings: Settings | None = None,
    pin_reader: Callable[[str], str] | None = None,
    clock: Callable[[], datetime] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run one manual pass; injectable boundaries keep CLI tests secret-free."""

    args = build_parser().parse_args(argv)
    settings = settings or Settings.from_env()
    pin_reader = pin_reader or getpass.getpass
    clock = clock or (lambda: datetime.now(timezone.utc))
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    database_target = (
        args.database_path
        if args.database_path is not None
        else settings.database_url or settings.database_path
    )
    database = Database(database_target)
    database.migrate()
    repository = KeyLifecycleRepository(database)
    now = clock()
    candidates = _cleanup_candidates(repository, now=now, limit=args.limit)
    if not candidates:
        print("No registered keys are due for cleanup.", file=stdout)
        return 0
    if not args.execute:
        print(
            f"{len(candidates)} registered key(s) due for cleanup (read-only preview):",
            file=stdout,
        )
        for key in candidates:
            print(_format_key(key), file=stdout)
        print("Re-run with --execute to perform cleanup.", file=stdout)
        return 0

    pin_vault = HSMPinVault()
    try:
        active_backend = settings.hsm_backend.strip().lower()
        needs_active_backend = any(
            key.ownership is KeyOwnership.MANAGED
            and key.backend == active_backend
            for key in candidates
        )
        if needs_active_backend and active_backend == "pkcs11":
            try:
                user_pin = pin_reader("PKCS#11 User PIN: ")
            except (EOFError, KeyboardInterrupt):
                print("PKCS#11 User PIN entry was canceled; no cleanup was run.", file=stderr)
                return 2
            if not user_pin:
                print("PKCS#11 User PIN is required; no cleanup was run.", file=stderr)
                return 2
            pin_vault.unlock(_CLI_PIN_SESSION, user_pin)

        backend = None
        backend_name = None
        if needs_active_backend:
            try:
                backend, backend_name = create_hsm(
                    settings,
                    pin_vault=pin_vault,
                    key_dir=settings.online_key_dir,
                )
            except Exception:  # noqa: BLE001 - configuration details may contain secrets
                print(
                    f"Could not initialize configured backend {active_backend}; "
                    "no cleanup was run.",
                    file=stderr,
                )
                return 2

        pki_repository = PKIRepository(database)
        request_vault = RequestKeyVault(
            pki_repository,
            settings.auth_encryption_secret,
        )
        cloud_keys = CloudKeyRepository(database)
        service_key_store = ServiceKeyStore(
            settings.service_key_dir,
            passphrase=settings.online_key_passphrase,
            hsm=backend,
            entropy_source=settings.entropy_source,
        )

        def delete_request_key(key: RegisteredKey) -> None:
            # Missing vault material is already in the desired state and makes
            # crash recovery idempotent.
            request_ids = pki_repository.list_request_private_key_ids_for_registry(
                key.id
            )
            if key.key_ref not in request_ids:
                request_ids.append(key.key_ref)
            for request_id in request_ids:
                request_vault.purge(request_id)

        def detach_reference(key: RegisteredKey) -> None:
            cloud_key = cloud_keys.find(provider=key.backend, key_ref=key.key_ref)
            if cloud_key is not None:
                cloud_keys.set_status(cloud_key.id, CloudKeyStatus.DELETED)

        def delete_service_key(key: RegisteredKey) -> None:
            if key.backend == KeyBackend.SOFTWARE.value:
                service_key_store.delete(key.key_ref, KeyBackend.SOFTWARE)
                return
            if key.backend != KeyBackend.PKCS11.value or backend is None:
                raise KeyCleanupError(
                    f"Backend {key.backend} is not active; service-key cleanup will be retried."
                )
            _idempotent_backend_deleter(backend)(key)

        deleters = {"request_vault": delete_request_key}
        if backend is not None and backend_name is not None:
            provider_delete = _idempotent_backend_deleter(backend)

            def delete_provider_key(key: RegisteredKey) -> None:
                if key.backend == KeyBackend.AZURE_KEY_VAULT.value:
                    cloud_key = cloud_keys.find(
                        provider=key.backend,
                        key_ref=key.key_ref,
                    )
                    if (
                        cloud_key is None
                        or cloud_key.ownership is not CloudKeyOwnership.MANAGED
                    ):
                        raise KeyCleanupError(
                            "Azure deletion requires a tracked myOwnCA-managed key."
                        )
                    name_identity = _azure_key_name_identity(key.key_ref)
                    if any(
                        candidate.id != key.id
                        and candidate.status
                        not in {KeyStatus.DELETED, KeyStatus.DETACHED}
                        and _azure_key_name_identity(candidate.key_ref)
                        == name_identity
                        for candidate in repository.list_all(backend=key.backend)
                    ):
                        raise KeyCleanupError(
                            "Another registered Azure key version with the same name "
                            "is still present."
                        )
                    validator = getattr(
                        backend,
                        "validate_managed_key_for_deletion",
                        None,
                    )
                    if not callable(validator):
                        raise KeyCleanupError(
                            "The Azure backend cannot prove managed-key ownership."
                        )
                    validator(key.key_ref)
                provider_delete(key)
                cloud_key = cloud_keys.find(provider=key.backend, key_ref=key.key_ref)
                if cloud_key is not None:
                    cloud_keys.set_status(
                        cloud_key.id,
                        CloudKeyStatus.PENDING_DELETION,
                    )

            deleters[backend_name] = delete_provider_key
        detachers = {
            key.backend: detach_reference
            for key in candidates
            if key.ownership is KeyOwnership.ATTACHED
        }
        service = KeyLifecycleService(
            repository,
            deleters=deleters,
            detachers=detachers,
            purpose_deleters={
                (KeyBackend.SOFTWARE.value, "service_certificate"): delete_service_key,
                (KeyBackend.PKCS11.value, "service_certificate"): delete_service_key,
            },
            clock=clock,
        )
        outcomes = service.cleanup_due(now=now, limit=args.limit)
    finally:
        pin_vault.clear()

    if not outcomes:
        print("No registered keys were claimed for cleanup.", file=stdout)
        return 0
    for outcome in outcomes:
        suffix = f": {outcome.error}" if outcome.error else ""
        print(
            f"  - {outcome.key_id} [{outcome.backend}/{outcome.ownership.value}] "
            f"{outcome.status.value}{suffix}",
            file=stdout,
        )
    failed = sum(not outcome.succeeded for outcome in outcomes)
    print(
        f"Processed {len(outcomes)} key(s): "
        f"{len(outcomes) - failed} succeeded, {failed} failed.",
        file=stdout,
    )
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    return run(argv)


def _cleanup_candidates(
    repository: KeyLifecycleRepository,
    *,
    now: datetime,
    limit: int,
) -> list[RegisteredKey]:
    """Preview due rows plus stale claims without mutating either state."""

    due = repository.list_due(now=now, limit=limit)
    by_id = {key.id: key for key in due}
    stale_before = now - DEFAULT_STALE_CLEANUP_AFTER
    for key in repository.list_all(status=KeyStatus.DELETING):
        if key.cleanup_started_at is None or key.cleanup_started_at <= stale_before:
            by_id.setdefault(key.id, key)
    return sorted(
        by_id.values(),
        key=lambda key: (key.delete_after or key.created_at, key.created_at, key.id),
    )[:limit]


def _idempotent_backend_deleter(backend):
    deleter = getattr(backend, "delete_key", None)
    if deleter is None:
        def unsupported(_key: RegisteredKey) -> None:
            raise KeyCleanupError("The configured backend does not support key deletion.")

        return unsupported

    def delete(key: RegisteredKey) -> None:
        list_keys = getattr(backend, "list_keys", None)
        if callable(list_keys) and not _listed_key_exists(list_keys(), key.key_ref):
            return
        try:
            deleter(key.key_ref)
        except Exception:  # noqa: BLE001 - re-check local/token state after a race
            if callable(list_keys) and not _listed_key_exists(list_keys(), key.key_ref):
                return
            raise

    return delete


def _listed_key_exists(keys, key_ref: str) -> bool:
    return any(
        isinstance(item, dict)
        and (item.get("label") == key_ref or item.get("id") == key_ref)
        for item in keys
    )


def _format_key(key: RegisteredKey) -> str:
    action = "delete" if key.ownership is KeyOwnership.MANAGED else "detach"
    return f"  - {key.id} [{key.backend}/{key.ownership.value}] {action}"


def _azure_key_name_identity(key_ref: str) -> str:
    parsed = urllib.parse.urlsplit(key_ref)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2 or parts[0].casefold() != "keys":
        return key_ref.casefold()
    return (
        f"{parsed.scheme.casefold()}://{parsed.netloc.casefold()}"
        f"/keys/{parts[1].casefold()}"
    )


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
