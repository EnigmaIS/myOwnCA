"""Independent installation verification and external monitoring commands."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from myownca_release.verify import (
    ROOTS, VerificationError, json_bytes, load_trust, parse_json, read_metadata,
    safe_path, validate_trust, verify_installed, verify_release, verify_signed, version_tuple,
)


def atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".release-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def prefix_root(prefix: Path) -> Path:
    # No execution of an unverified target Python interpreter to discover paths.
    roots = list((prefix / "lib").glob("python*/site-packages"))
    if len(roots) != 1:
        raise VerificationError("Expected exactly one Python site-packages in installation")
    return roots[0]


def apply_trust_update(path: Path, update: Path) -> dict:
    current = load_trust(path)
    value = verify_signed(update, current, "trust")
    if set(value) != {"schema", "product", "kind", "key_id", "trust"}:
        raise VerificationError("Invalid trust update fields")
    new = validate_trust(value["trust"])
    if new["sequence"] != current["sequence"] + 1:
        raise VerificationError("Trust update must increment sequence by exactly one")
    atomic_write(path, json_bytes(new))
    return {"sequence": new["sequence"], "signer": value["key_id"]}


def install(bundle: Path, trust_path: Path, version: str, prefix: Path,
            current: Path | None = None, allow_rollback: bool = False) -> dict:
    trust = load_trust(trust_path)
    if prefix.exists() or prefix.is_symlink():
        raise VerificationError("Install into a new versioned prefix; existing prefixes are preserved")
    if current is not None:
        old = verify_installed(prefix_root(current), trust)
        if version_tuple(version) < version_tuple(old["version"]) and not allow_rollback:
            raise VerificationError("Downgrade requires explicit --allow-rollback")
    elif allow_rollback:
        raise VerificationError("Rollback requires --current-prefix")
    release = verify_release(bundle, trust, version)
    # Copy and reverify to close the artifact replacement window before invoking pip.
    with tempfile.TemporaryDirectory(prefix="myownca-install-") as directory:
        staged = Path(directory)
        for name in (*release["artifacts"], "release.json", "release.json.sig"):
            shutil.copyfile(bundle / name, staged / name, follow_symlinks=False)
        release = verify_release(staged, trust, version)
        wheels = list(staged.glob("myownca-*.whl"))
        if len(wheels) != 1 or "requirements.lock" not in release["artifacts"]:
            raise VerificationError("Missing application wheel or dependency lock")
        # Signed locks are deliberately restricted to offline, pinned wheel inputs.
        lock = (staged / "requirements.lock").read_text()
        import re

        logical = lock.replace("\\\n", " ").splitlines()
        for line in logical:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9.+!_-]+"
                r"(?:\s+--hash=sha256:[0-9a-f]{64})+", line
            ):
                raise VerificationError("Lock must contain only exact pins with SHA-256 hashes")
        from myownca_release.sign import wheel_contents

        wheel_root = staged / "unpacked"
        for name, raw in wheel_contents(wheels[0]).items():
            target = wheel_root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        checked = verify_installed(wheel_root, trust)
        if checked["version"] != version or checked["commit"] != release["commit"]:
            raise VerificationError("Release metadata and wheel identity differ")
        prefix.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([sys.executable, "-I", "-m", "venv", str(prefix)], check=True)
        python = prefix / "bin/python"
        base = [str(python), "-I", "-m", "pip", "--isolated", "install", "--no-index",
                "--no-compile", "--only-binary=:all:", "--find-links", str(staged)]
        subprocess.run([*base, "--require-hashes", "-r", str(staged / "requirements.lock")],
                       check=True, stdout=sys.stderr)
        subprocess.run([*base, "--no-deps", str(wheels[0])], check=True, stdout=sys.stderr)
        subprocess.run([str(python), "-I", "-m", "pip", "--isolated", "check"],
                       check=True, stdout=sys.stderr)
        result = verify_installed(prefix_root(prefix), trust)
        atomic_write(prefix / "etc/myownca/release-trust.json", json_bytes(trust))
        atomic_write(prefix / "etc/myownca/installed-release.json", json_bytes(release))
        # Writable operational state belongs outside this immutable environment.
        for path in prefix.rglob("*"):
            if path.is_symlink():
                continue
            os.chmod(path, path.stat().st_mode & ~0o022)
        return {**result, "prefix": str(prefix)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_alert(config_path: Path, result: dict) -> None:
    config = parse_json(read_metadata(config_path))
    if set(config) != {"url"} or not isinstance(config["url"], str):
        raise VerificationError("Webhook configuration must contain only an HTTPS url")
    url = urllib.parse.urlsplit(config["url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
        raise VerificationError("Webhook must use HTTPS without userinfo or fragment")
    request = urllib.request.Request(config["url"], data=json_bytes(result), method="POST",
                                     headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
        if not 200 <= response.status < 300:
            raise VerificationError("Webhook returned an unsuccessful status")


def check_freshness(path: Path, maximum_hours: int = 26) -> dict:
    value = parse_json(read_metadata(path))
    if value.get("status") != "verified" or value.get("event") != "release_integrity":
        raise VerificationError("Last integrity check did not succeed")
    try:
        moment = datetime.fromisoformat(value["time"])
        if moment.tzinfo is None:
            raise ValueError("Missing timezone")
        age = (datetime.now(timezone.utc) - moment).total_seconds()
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationError("Invalid integrity check timestamp") from exc
    if age < -300 or age > maximum_hours * 3600:
        raise VerificationError("Integrity check is missing, stale, or dated in the future")
    return {"age_seconds": round(age), "version": value.get("version"),
            "signer": value.get("signer")}


def container_check(container: str, reference: str, trust: dict) -> dict:
    def docker_json(*args):
        return json.loads(subprocess.check_output(["docker", *args], timeout=60))

    info = docker_json("inspect", container)[0]
    image = docker_json("image", "inspect", info["Image"])[0]
    if reference not in (image.get("RepoDigests") or []):
        raise VerificationError("Container image differs from the authenticated release digest")
    root_name = "usr/local/lib/python3.12/site-packages"
    for mount in info.get("Mounts", []):
        dest = mount["Destination"].rstrip("/")
        protected = ["/" + root_name, "/usr/local/bin", "/usr/local/etc/myownca"]
        if any(dest == p or p.startswith(dest + "/") or dest.startswith(p + "/")
               for p in protected):
            raise VerificationError("Mount obscures release code, entry points, or trust anchors")
    # Docker export reads the container filesystem even when startup has failed.
    # Never execute an interpreter or verifier supplied by the target container.
    with tempfile.TemporaryDirectory(prefix="myownca-container-check-") as directory:
        temp = Path(directory)
        archive_path = temp / "container.tar"
        subprocess.run(["docker", "export", "--output", str(archive_path), info["Id"]],
                       check=True, timeout=300)
        root = temp / "files"
        total = 0
        seen = set()
        with tarfile.open(archive_path) as archive:
            for member in archive:
                name = member.name.removeprefix("./")
                if not name.startswith(root_name + "/"):
                    continue
                relative = name[len(root_name) + 1:]
                if relative.split("/")[0] not in ROOTS:
                    continue
                safe_path(relative)
                if member.isdir():
                    continue
                total += member.size
                if not member.isfile() or relative in seen or total > 256 * 1024 * 1024:
                    raise VerificationError("Unsafe or oversized container application inventory")
                seen.add(relative)
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
        return {**verify_installed(root, trust), "container": info["Id"], "image": reference}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify myOwnCA without loading the CA application")
    parser.add_argument("--json", action="store_true", help="machine-readable result")
    parser.add_argument("--webhook-config", type=Path, help="send failures to this HTTPS endpoint")
    parser.add_argument("--status-file", type=Path, help="atomically record the last check result")
    commands = parser.add_subparsers(dest="command", required=True)
    installed = commands.add_parser("installed")
    installed.add_argument("--root", type=Path, default=Path(sysconfig.get_path("purelib")))
    artifact = commands.add_parser("artifact")
    image = commands.add_parser("image")
    image.add_argument("--name", required=True)
    container = commands.add_parser("container")
    container.add_argument("--name", required=True)
    container.add_argument("--container", required=True)
    installer = commands.add_parser("install")
    installer.add_argument("--prefix", type=Path, required=True)
    installer.add_argument("--current-prefix", type=Path)
    installer.add_argument("--allow-rollback", action="store_true")
    rotate = commands.add_parser("trust-update")
    rotate.add_argument("--update", type=Path, required=True)
    freshness = commands.add_parser("freshness")
    freshness.add_argument("--file", type=Path, required=True)
    for command in (installed, artifact, image, container, installer, rotate):
        command.add_argument("--trust", type=Path, required=True)
    for command in (artifact, image, container, installer):
        command.add_argument("--bundle", type=Path, required=True)
        command.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    result = {"event": "release_integrity", "time": datetime.now(timezone.utc).isoformat(),
              "operation": args.command, "status": "failed"}
    code = 1
    try:
        trust = load_trust(args.trust) if args.command != "freshness" else None
        if args.command == "freshness":
            result.update(check_freshness(args.file))
        elif args.command == "installed":
            result.update(verify_installed(args.root, trust))
        elif args.command == "trust-update":
            result.update(apply_trust_update(args.trust, args.update))
        elif args.command == "install":
            result.update(install(args.bundle, args.trust, args.version, args.prefix,
                                  args.current_prefix, args.allow_rollback))
        else:
            release = verify_release(args.bundle, trust, args.version)
            result.update(version=release["version"], signer=release["key_id"])
            if args.command in ("image", "container"):
                if args.name not in release["images"]:
                    raise VerificationError("Image not present in authenticated release")
                reference = release["images"][args.name]
                result["image"] = reference
                if args.command == "container":
                    result.update(container_check(args.container, reference, trust))
        result["status"] = "verified"
        code = 0
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as exc:
        result["error"] = str(exc)
    if code and args.webhook_config:
        try:
            send_alert(args.webhook_config, result)
            result["alert"] = "delivered"
        except (OSError, ValueError, urllib.error.URLError):
            # URLs may contain credentials; never log the exception or URL.
            result["alert"] = "delivery_failed"
    if args.status_file:
        try:
            atomic_write(args.status_file, json_bytes(result))
        except OSError:
            result["status_write"] = "failed"
            code = 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"myOwnCA {args.command}: {result['status']}")
        print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
