from __future__ import annotations

import ast
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src" / "myownca"
OPENSC_SERVICE_FILES = {
    SOURCE / "ca_hsm" / "ceremony.py",
    SOURCE / "ca_hsm" / "recovery.py",
}
SCCTL_OPERATIONS = {
    "initialize",
    "create_dkek_share",
    "import_dkek_share",
    "dkek_status",
    "wrap_key",
    "unwrap_key",
}


SHARED_SERVICE_FACTORIES = {
    "HSMCeremonyService",
    "HSMKeyRecoveryService",
    "hsm_ceremony_service",
    "hsm_recovery_service",
}


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_shared_service_receiver(node: ast.expr) -> bool:
    return isinstance(node, ast.Call) and _call_name(node.func) in SHARED_SERVICE_FACTORIES


def test_opensc_operations_are_confined_to_shared_hsm_services() -> None:
    violations: list[str] = []
    for path in SOURCE.rglob("*.py"):
        if path in OPENSC_SERVICE_FILES:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in SCCTL_OPERATIONS
                and not _is_shared_service_receiver(node.func.value)
            ):
                violations.append(f"{path.relative_to(SOURCE)}:{node.lineno}:{node.func.attr}")

    assert violations == []


def test_obsolete_split_ceremony_methods_are_removed() -> None:
    ceremony = (SOURCE / "ca_hsm" / "ceremony.py").read_text()

    assert "create_ephemeral_dkek_share" not in ceremony
    assert "create_persistent_dkek_share" not in ceremony
    assert "import_persistent_dkek_share" not in ceremony
