from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from myownca_release.license_keys import LICENSE_KEYS
from myownca_release.license_keys import read_license_keys, validate_license_keys
from myownca_release import cli
from myownca_release.sign import key_metadata, seal_wheel, signature, write_signed
from myownca_release.verify import (
    MANIFEST, SIGNATURE, VerificationError, fingerprint, inventory, json_bytes,
    load_trust, parse_json, safe_path, sha256, verify_installed, verify_release,
)

COMMIT = "a" * 40


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


@pytest.fixture
def trust(key):
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return {"schema": 1, "sequence": 1, "keys": {fingerprint(key.public_key()): pem}}


@pytest.fixture
def trust_path(tmp_path, trust):
    path = tmp_path / "trust.json"
    path.write_bytes(json_bytes(trust))
    return path


@pytest.fixture
def tree(tmp_path, key):
    root = tmp_path / "site-packages"
    for name in ("myownca", "myownca_core", "myownca_release"):
        (root / name).mkdir(parents=True)
        (root / name / "__init__.py").write_text("# application\n")
    (root / "myownca/test.py").write_text("print('original')\n")
    (root / "myownca/migrations").mkdir()
    (root / "myownca/migrations/0001.sql").write_text("CREATE TABLE example (id INTEGER);\n")
    reseal(root, key)
    return root


def licensing_ring(key):
    encoded = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )).decode()
    return {"schema": 1, "keys": {"producer-test": encoded}}


@pytest.fixture
def license_keys_path(tmp_path, key):
    path = tmp_path / "licensing-public-keys.json"
    path.write_bytes(json_bytes(licensing_ring(key)))
    return path


def reseal(root, key, version="1.2.3"):
    if not (root / LICENSE_KEYS).exists():
        (root / LICENSE_KEYS).write_bytes(json_bytes(licensing_ring(key)))
    value = {**key_metadata(key, "files"), "version": version, "commit": COMMIT,
             "files": inventory(root)}
    raw = json_bytes(value)
    (root / MANIFEST).write_bytes(raw)
    (root / SIGNATURE).write_bytes(signature(raw, key))


def release(bundle, key, version="1.2.3", images=None):
    value = {**key_metadata(key, "release"), "version": version, "commit": COMMIT,
             "images": images or {}, "artifacts": {
                 path.name: {"sha256": sha256(path), "size": path.stat().st_size}
                 for path in bundle.iterdir() if path.name not in ("release.json", "release.json.sig")
             }}
    write_signed(bundle / "release.json", value, key)
    return value


def test_clean_inventory_and_mutable_state(tree, trust):
    assert verify_installed(tree, trust)["version"] == "1.2.3"
    (tree.parent / "config.toml").write_text("changed = true")
    assert verify_installed(tree, trust)["files_checked"] == 6


@pytest.mark.parametrize("change", ["replace", "remove", "empty", "malformed"])
def test_licensing_key_tampering_is_an_integrity_failure(tree, trust, change):
    path = tree / LICENSE_KEYS
    if change == "remove":
        path.unlink()
    elif change == "replace":
        ring = json.loads(path.read_bytes())
        ring["keys"]["attacker"] = ring["keys"].pop("producer-test")
        path.write_bytes(json_bytes(ring))
    else:
        path.write_bytes(b'{"schema":1,"keys":{}}' if change == "empty" else b'broken')
    with pytest.raises(VerificationError):
        verify_installed(tree, trust)


@pytest.mark.parametrize("ring", [
    {"schema": 1, "keys": {}}, {"schema": True, "keys": {"x": "value"}},
    {"schema": 1, "keys": {"bad id": "value"}},
    {"schema": 1, "keys": {"id": "not-base64"}},
    {"schema": 1, "keys": {"id": 1}},
])
def test_invalid_licensing_ring_rejected_even_when_signed(tree, trust, key, ring):
    (tree / LICENSE_KEYS).write_bytes(json_bytes(ring))
    reseal(tree, key)
    with pytest.raises(VerificationError):
        verify_installed(tree, trust)


def test_duplicate_licensing_keys_rejected(tmp_path, key):
    path = tmp_path / "keys.json"
    encoded = licensing_ring(key)["keys"]["producer-test"]
    path.write_text('{"schema":1,"keys":{"id":"' + encoded + '","id":"' + encoded + '"}}')
    with pytest.raises(VerificationError):
        read_license_keys(path)


def test_signed_manifest_cannot_omit_licensing_ring(tree, trust, key):
    value = json.loads((tree / MANIFEST).read_bytes())
    del value["files"][LICENSE_KEYS]
    raw = json_bytes(value)
    (tree / MANIFEST).write_bytes(raw)
    (tree / SIGNATURE).write_bytes(signature(raw, key))
    with pytest.raises(VerificationError, match="must include"):
        verify_installed(tree, trust)


def test_licensing_rotation_keeps_authorized_tokens_valid(tree, trust, key):
    from myownca.licensing import LicenseError, verify_token
    from tests.test_production_licensing import Signer

    old, new, attacker = Signer("old"), Signer("new"), Signer("rogue")
    # Signer normally shares a test key; rotate to genuinely different material.
    new.private_key = key
    new.public_b64 = licensing_ring(key)["keys"]["producer-test"]
    attacker.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    token = old.sign(old.payload("00000000-0000-4000-8000-000000000001"))
    ring = {"schema": 1, "keys": {old.key_id: old.public_b64, new.key_id: new.public_b64}}
    (tree / LICENSE_KEYS).write_bytes(json_bytes(ring))
    reseal(tree, key)
    keys = verify_installed(tree, trust, include_license_keys=True)["license_public_keys"]
    assert verify_token(token, public_keys=keys).key_id == "old"
    assert verify_token(new.sign(new.payload("00000000-0000-4000-8000-000000000001")),
                        public_keys=keys).key_id == "new"
    forged = attacker.payload("00000000-0000-4000-8000-000000000001")
    forged["key_id"] = "old"
    with pytest.raises(LicenseError):
        verify_token(attacker.sign(forged), public_keys=keys)
    assert validate_license_keys(ring) == keys


def test_small_rsa_and_non_rsa_licensing_keys_rejected():
    from cryptography.hazmat.primitives.asymmetric import ec

    for key in (rsa.generate_private_key(public_exponent=65537, key_size=2048),
                ec.generate_private_key(ec.SECP256R1())):
        with pytest.raises(VerificationError, match="RSA-4096"):
            validate_license_keys(licensing_ring(key))


@pytest.mark.parametrize("attack", ["edit", "delete", "inject", "bytecode", "symlink"])
def test_file_tampering_fails(tree, trust, attack):
    path = tree / "myownca/test.py"
    if attack == "edit":
        path.write_text("print('tampered')")
    elif attack == "delete":
        path.unlink()
    elif attack == "inject":
        (path.parent / "extra.py").write_text("pass")
    elif attack == "bytecode":
        (path.parent / "test.pyc").write_bytes(b"cache")
    else:
        path.unlink()
        path.symlink_to(tree.parent / "external.py")
    with pytest.raises(VerificationError):
        verify_installed(tree, trust)


@pytest.mark.parametrize("attack", ["signature", "manifest", "missing", "unknown", "product"])
def test_metadata_tampering_fails(tree, trust, key, attack):
    path = tree / MANIFEST
    value = json.loads(path.read_bytes())
    if attack == "signature":
        (tree / SIGNATURE).write_bytes(base64.b64encode(b"x" * 512))
    elif attack == "manifest":
        path.write_bytes(path.read_bytes() + b" ")
    elif attack == "missing":
        path.unlink()
    else:
        value["key_id" if attack == "unknown" else "product"] = "wrong"
        raw = json_bytes(value)
        path.write_bytes(raw)
        (tree / SIGNATURE).write_bytes(signature(raw, key))
    with pytest.raises((VerificationError, OSError)):
        verify_installed(tree, trust)


@pytest.mark.parametrize("name", ["../evil", "/absolute", "a/../b", "a//b", "a\\b", "a/./b", "x\x00y"])
def test_unsafe_paths_rejected(name):
    with pytest.raises(VerificationError):
        safe_path(name)


def test_duplicate_json_rejected():
    with pytest.raises(VerificationError):
        parse_json(b'{"schema":1,"schema":1}')


def test_artifacts_are_bound_to_requested_release(tmp_path, key, trust):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    artifact = bundle / "app.whl"
    artifact.write_bytes(b"artifact")
    release(bundle, key, images={"ca": "registry.example/ca@sha256:" + "a" * 64})
    assert verify_release(bundle, trust, "1.2.3")["version"] == "1.2.3"
    with pytest.raises(VerificationError, match="requested version"):
        verify_release(bundle, trust, "1.2.4")
    artifact.write_bytes(b"tampered")
    with pytest.raises(VerificationError, match="Artifact integrity"):
        verify_release(bundle, trust, "1.2.3")


def test_trust_rotation_and_replay(tmp_path, trust_path, trust, key):
    update = tmp_path / "trust-update.json"
    new = {**trust, "sequence": 2}
    write_signed(update, {**key_metadata(key, "trust"), "trust": new}, key)
    assert cli.apply_trust_update(trust_path, update)["sequence"] == 2
    assert load_trust(trust_path)["sequence"] == 2
    with pytest.raises(VerificationError, match="sequence"):
        cli.apply_trust_update(trust_path, update)


def test_monitor_failure_alert_and_status(tree, trust_path, tmp_path, monkeypatch, capsys):
    (tree / "myownca/test.py").unlink()
    alerts = []
    monkeypatch.setattr(cli, "send_alert", lambda config, result: alerts.append(dict(result)))
    status = tmp_path / "status.json"
    code = cli.main(["--json", "--status-file", str(status), "--webhook-config", "webhook.json",
                     "installed", "--root", str(tree), "--trust", str(trust_path)])
    assert code == 1
    assert alerts[0]["status"] == "failed"
    assert json.loads(status.read_text())["alert"] == "delivered"
    assert json.loads(capsys.readouterr().out)["status"] == "failed"


def test_monitor_delivery_failure_does_not_hide_failure(tree, trust_path, monkeypatch, capsys):
    (tree / "myownca/test.py").unlink()

    def fail(*args):
        raise OSError("secret URL must not appear")

    monkeypatch.setattr(cli, "send_alert", fail)
    args = ["--json", "--webhook-config", "unused", "installed", "--root", str(tree),
            "--trust", str(trust_path)]
    assert cli.main(args) == 1
    output = capsys.readouterr().out
    assert "secret URL" not in output
    assert json.loads(output)["alert"] == "delivery_failed"


def test_webhook_rejects_http(tmp_path):
    path = tmp_path / "webhook.json"
    path.write_text('{"url":"http://example.com/hook"}')
    with pytest.raises(VerificationError, match="HTTPS"):
        cli.send_alert(path, {})


def test_missed_monitor_check_detected(tmp_path):
    path = tmp_path / "status.json"
    with pytest.raises(OSError):
        cli.check_freshness(path)
    value = {"event": "release_integrity", "status": "verified",
             "time": datetime.now(timezone.utc).isoformat()}
    path.write_bytes(json_bytes(value))
    assert cli.check_freshness(path)["age_seconds"] <= 1
    value["time"] = (datetime.now(timezone.utc) - timedelta(hours=27)).isoformat()
    path.write_bytes(json_bytes(value))
    with pytest.raises(VerificationError, match="stale"):
        cli.check_freshness(path)


def test_sealed_wheel_record_and_signature(tmp_path, key, trust, license_keys_path):
    source = tmp_path / "input"
    target = tmp_path / "output"
    source.mkdir()
    target.mkdir()
    wheel = source / "myownca-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for namespace in ("myownca", "myownca_core", "myownca_release"):
            archive.writestr(f"{namespace}/__init__.py", "# code")
        archive.writestr("myownca-1.2.3.dist-info/METADATA", "Name: myownca\nVersion: 1.2.3\n")
        archive.writestr("myownca-1.2.3.dist-info/RECORD", "")
    sealed = target / wheel.name
    seal_wheel(wheel, sealed, key, COMMIT, license_keys_path)
    with zipfile.ZipFile(sealed) as archive:
        archive.extractall(target / "unpacked")
        record = archive.read("myownca-1.2.3.dist-info/RECORD").decode()
        assert MANIFEST in record and SIGNATURE in record
    assert verify_installed(target / "unpacked", trust)["version"] == "1.2.3"
    # A release operator cannot seal an empty ring, even with a valid signing key.
    license_keys_path.write_text('{"schema":1,"keys":{}}')
    output = tmp_path / wheel.name
    with pytest.raises(VerificationError, match="empty"):
        seal_wheel(wheel, output, key, COMMIT, license_keys_path)
    assert not output.exists()


def test_guard_blocks_before_application_execution(tree, key, trust, tmp_path):
    source = Path(__file__).parents[1] / "src"
    shutil.copytree(source / "myownca_release", tree / "myownca_release", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copyfile(source / "myownca/__init__.py", tree / "myownca/__init__.py")
    prefix = tmp_path / "prefix"
    (prefix / "etc/myownca").mkdir(parents=True)
    (prefix / "etc/myownca/release-trust.json").write_bytes(json_bytes(trust))
    reseal(tree, key)
    code = (f"import sys; sys.path.insert(0, {str(tree)!r}); sys.prefix={str(prefix)!r}; "
            "import myownca; print('APPLICATION_RAN')")
    good = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True)
    assert good.returncode == 0, good.stderr
    assert "APPLICATION_RAN" in good.stdout
    (tree / "myownca/test.py").write_text("modified")
    bad = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True)
    assert bad.returncode == 78
    assert "APPLICATION_RAN" not in bad.stdout
    assert "Application integrity failure" in bad.stderr


def test_install_rejects_tamper_before_subprocess(tmp_path, trust_path, key, monkeypatch):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    path = bundle / "app.whl"
    path.write_bytes(b"valid")
    release(bundle, key)
    path.write_bytes(b"invalid")
    calls = []
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: calls.append(a))
    with pytest.raises(VerificationError):
        cli.install(bundle, trust_path, "1.2.3", tmp_path / "new")
    assert calls == []
    assert not (tmp_path / "new").exists()


def test_downgrade_requires_explicit_flag(tree, trust_path, tmp_path):
    prefix = tmp_path / "current"
    target = prefix / "lib/python3.12/site-packages"
    target.parent.mkdir(parents=True)
    shutil.copytree(tree, target)
    with pytest.raises(VerificationError, match="Downgrade"):
        cli.install(tmp_path, trust_path, "1.2.2", tmp_path / "new", prefix)


def test_image_digest_mismatch_fails_before_export(trust, monkeypatch):
    responses = iter([json.dumps([{"Image": "id", "Mounts": []}]).encode(),
                      json.dumps([{"RepoDigests": ["wrong"]}]).encode()])
    monkeypatch.setattr(cli.subprocess, "check_output", lambda *a, **kw: next(responses))
    with pytest.raises(VerificationError, match="digest"):
        cli.container_check("ca", "registry/ca@sha256:" + "a" * 64, trust)


@pytest.mark.parametrize("attack", [None, "changed-file", "mounted-code"])
def test_container_snapshot_verification(tree, trust, monkeypatch, attack):
    reference = "registry.example/ca@sha256:" + "a" * 64
    mounts = ([{"Destination": "/usr/local/lib/python3.12/site-packages"}]
              if attack == "mounted-code" else [])
    responses = iter([json.dumps([{"Id": "container-id", "Image": "image-id", "Mounts": mounts}]),
                      json.dumps([{"RepoDigests": [reference]}])])
    calls = []
    monkeypatch.setattr(cli.subprocess, "check_output", lambda *a, **kw: next(responses))
    if attack == "changed-file":
        (tree / "myownca/test.py").write_text("tampered")

    def export(command, **kwargs):
        calls.append(command)
        assert command[:3] == ["docker", "export", "--output"]
        with tarfile.open(command[3], "w") as archive:
            archive.add(tree, arcname="usr/local/lib/python3.12/site-packages")

    monkeypatch.setattr(cli.subprocess, "run", export)
    if attack:
        with pytest.raises(VerificationError):
            cli.container_check("ca", reference, trust)
        if attack == "mounted-code":
            assert not calls
    else:
        assert cli.container_check("ca", reference, trust)["version"] == "1.2.3"


def test_new_signer_requires_authenticated_rotation(tree, trust_path, trust, key, tmp_path):
    replacement = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pem = replacement.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    new = {"schema": 1, "sequence": 2,
           "keys": {**trust["keys"], fingerprint(replacement.public_key()): pem}}
    update = tmp_path / "rotation.json"
    write_signed(update, {**key_metadata(key, "trust"), "trust": new}, key)
    reseal(tree, replacement)
    with pytest.raises(VerificationError, match="Unknown release signer"):
        verify_installed(tree, trust)
    cli.apply_trust_update(trust_path, update)
    assert verify_installed(tree, load_trust(trust_path))["signer"] == fingerprint(replacement.public_key())


def test_real_sealed_wheel_launchers(tmp_path, key, trust, trust_path, monkeypatch, license_keys_path):
    """Build/install a real wheel, then exercise every production console entry."""
    from tests.test_wheel_packaging import _build_wheel

    wheel = _build_wheel(tmp_path)
    sealed_dir = tmp_path / "sealed"
    sealed_dir.mkdir()
    sealed = sealed_dir / wheel.name
    seal_wheel(wheel, sealed, key, COMMIT, license_keys_path)
    prefix = tmp_path / "installed"
    # Reuse the test runner's dependency environment without network downloads.
    # This is a fixture-only dependency path, not a production install procedure.
    run = subprocess.run

    def with_fixture_dependencies(command, **kwargs):
        result = run(command, **kwargs)
        if "venv" in command:
            root = cli.prefix_root(prefix)
            (root / "test-dependencies.pth").write_text(sysconfig.get_path("purelib") + "\n")
        return result

    (sealed_dir / "requirements.lock").write_text("# dependencies supplied by isolated test fixture\n")
    release(sealed_dir, key, version="0.0.0")
    with monkeypatch.context() as context:
        context.setattr(cli.subprocess, "run", with_fixture_dependencies)
        assert cli.install(sealed_dir, trust_path, "0.0.0", prefix)["version"] == "0.0.0"
    root = cli.prefix_root(prefix)
    assert verify_installed(root, trust)["version"] == "0.0.0"
    for name in ("myownca", "myownca-online", "myownca-offline", "myownca-auth-bootstrap",
                 "myownca-acme-renew", "myownca-notify-run", "myownca-key-cleanup",
                 "myownca-reencrypt-secrets"):
        # Tampering must abort before argument parsing, migration, or backend use.
        target = root / "myownca/launcher.py"
        original = target.read_bytes()
        target.write_bytes(original + b"\n# tampered\n")
        failed = subprocess.run([str(prefix / "bin" / name), "--help"],
                                capture_output=True, text=True, timeout=30)
        assert failed.returncode == 78, (name, failed.stdout, failed.stderr)
        assert "Application integrity failure" in failed.stderr
        target.write_bytes(original)
    good = subprocess.run([str(prefix / "bin/myownca"), "--help"],
                          capture_output=True, text=True, timeout=30)
    assert good.returncode == 0, good.stderr
    assert "verified" in good.stderr
    assert not list(root.glob("myownca*/**/*.pyc"))
    from tests.test_production_licensing import Signer

    signer = Signer("producer-test")
    signer.private_key = key
    token = signer.sign(signer.payload("00000000-0000-4000-8000-000000000001"))
    verify_code = ("from myownca.config import Settings; "
                   "from myownca.licensing import verify_token; "
                   f"print(verify_token({token!r}, "
                   "public_keys=Settings.from_mapping({}).license_public_keys).key_id)")
    licensed = subprocess.run([str(prefix / "bin/python"), "-I", "-B", "-c", verify_code],
                              capture_output=True, text=True, timeout=30)
    assert licensed.returncode == 0, licensed.stderr
    assert licensed.stdout.strip() == "producer-test"
    # Public-key changes fail before even --help can reach the application.
    path = root / LICENSE_KEYS
    original = path.read_bytes()
    for raw in (b"broken", b'{"schema":1,"keys":{}}'):
        path.write_bytes(raw)
        failed = subprocess.run([str(prefix / "bin/myownca"), "--help"],
                                capture_output=True, text=True, timeout=30)
        assert failed.returncode == 78
    path.write_bytes(original)
    import os

    for override in ("", "{}", json.dumps(licensing_ring(key)["keys"])):
        failed = subprocess.run([str(prefix / "bin/myownca"), "--help"],
                                env={**os.environ, "MYOWNCA_LICENSE_PUBLIC_KEYS": override},
                                capture_output=True, text=True, timeout=30)
        assert failed.returncode == 78
        assert "no longer supported" in failed.stderr
    for relative, body in (("config.toml", '[env]\nMYOWNCA_LICENSE_PUBLIC_KEYS = ""\n'),
                           ("secrets/secrets.env", "MYOWNCA_LICENSE_PUBLIC_KEYS={}\n")):
        state = tmp_path / relative.split("/")[0] / "state"
        legacy = state / relative
        legacy.parent.mkdir(parents=True)
        legacy.write_text(body)
        failed = subprocess.run([str(prefix / "bin/myownca"), "--state-dir", str(state), "serve"],
                                capture_output=True, text=True, timeout=30)
        assert failed.returncode == 78, failed.stderr
        assert "no longer supported" in failed.stderr
        assert not (state / "myownca.sqlite3").exists()
