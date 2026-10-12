"""Release boundary tests: provenance, publication allowlists and acceptance binding."""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from myownca_release.sign import key_metadata, seal_wheel, write_signed
from myownca_release.verify import fingerprint
from myownca_release.verify import VerificationError, sha256

SPEC = importlib.util.spec_from_file_location(
    "release_workflow", Path(__file__).parents[1] / "scripts/releases/release.py"
)
workflow = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow)


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-b", "master")
    git(root, "config", "user.name", "Release Test")
    git(root, "config", "user.email", "release@example.test")
    (root / "app.txt").write_text("release input\n")
    git(root, "add", "app.txt")
    git(root, "commit", "-m", "test(release): add fixture")
    git(root, "update-ref", "refs/remotes/origin/master", "HEAD")
    git(root, "tag", "-a", "v1.2.3", "-m", "test release")
    return root


def test_release_requires_annotated_tag_on_master(repo):
    assert workflow.release_identity(repo, "v1.2.3") == {
        "tag": "v1.2.3", "version": "1.2.3", "commit": git(repo, "rev-parse", "HEAD")}
    git(repo, "tag", "v1.2.4")
    with pytest.raises(VerificationError, match="annotated"):
        workflow.release_identity(repo, "v1.2.4")
    git(repo, "checkout", "-b", "feature")
    (repo / "app.txt").write_text("not merged\n")
    git(repo, "commit", "-am", "test(release): change fixture")
    git(repo, "tag", "-a", "v1.3.0", "-m", "unmerged")
    with pytest.raises(subprocess.CalledProcessError):
        workflow.release_identity(repo, "v1.3.0")


def test_tag_proposal_never_creates_a_tag(repo, capsys):
    before = git(repo, "tag", "--list")
    workflow.propose_tag(argparse.Namespace(repo=repo, bump="minor",
                                           subject="feat(setup): publish signed releases"))
    proposal = json.loads(capsys.readouterr().out)
    assert (proposal["from"], proposal["to"], proposal["approval_required"]) == (
        "v1.2.3", "v1.3.0", True)
    assert git(repo, "tag", "--list") == before


@pytest.mark.parametrize("tag", ["1.2.3", "v1.2.3.dev1", "v01.2.3", "--all", "master"])
def test_release_refuses_nonrelease_refs(repo, tag):
    with pytest.raises(VerificationError, match="stable"):
        workflow.release_identity(repo, tag)


def test_release_refuses_untracked_dirty_and_version_override(repo, monkeypatch):
    stray = repo / "private.pem"
    stray.write_text("test-only sentinel")
    with pytest.raises(VerificationError, match="clean"):
        workflow.release_identity(repo, "v1.2.3")
    stray.unlink()
    monkeypatch.setenv("SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MYOWNCA", "1.2.3")
    with pytest.raises(VerificationError, match="overrides"):
        workflow.release_identity(repo, "v1.2.3")
    monkeypatch.delenv("SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MYOWNCA")
    (repo / "app.txt").write_text("changed")
    with pytest.raises(VerificationError, match="clean"):
        workflow.release_identity(repo, "v1.2.3")


def test_validation_cannot_hide_skipped_packaging(tmp_path):
    report = tmp_path / "pytest.xml"
    report.write_text('''<testsuites><testsuite>
      <testcase name="test_real_sealed_wheel_launchers"><skipped /></testcase>
      <testcase name="test_every_source_data_file_is_packaged" />
    </testsuite></testsuites>''')
    with pytest.raises(VerificationError, match="not skip"):
        workflow.require_passed_junit(report)
    report.write_text(report.read_text().replace("<skipped />", ""))
    workflow.require_passed_junit(report)


def test_validation_evidence_bound_to_commit_and_logs(tmp_path):
    for name in ("ruff.log", "pytest.log"):
        (tmp_path / name).write_text("passed")
    (tmp_path / "pytest.xml").write_text('''<testsuite>
      <testcase name="test_real_sealed_wheel_launchers" />
      <testcase name="test_every_source_data_file_is_packaged" />
    </testsuite>''')
    workflow.write_json(tmp_path / "validation.json", {
        "commit": "a" * 40, "status": "passed",
        "files": {p.name: sha256(p) for p in tmp_path.iterdir()}})
    workflow.check_validation(tmp_path, "a" * 40)
    with pytest.raises(VerificationError, match="exact release commit"):
        workflow.check_validation(tmp_path, "b" * 40)
    (tmp_path / "pytest.log").write_text("modified")
    with pytest.raises(VerificationError, match="evidence changed"):
        workflow.check_validation(tmp_path, "a" * 40)


@pytest.fixture
def work(tmp_path):
    for arch in workflow.ARCHES:
        bundle = tmp_path / arch / "bundle"
        bundle.mkdir(parents=True)
        (bundle / "release.json").write_text(json.dumps({"architecture": arch}))
        (bundle / "release.json.sig").write_text("fixture signature")
        (bundle / "app.whl").write_bytes(b"fixture wheel bytes")
    (tmp_path / "release-trust.json").write_text("fixture public trust")
    # Private workspace material must never enter publication assets.
    (tmp_path / "source").mkdir()
    (tmp_path / "source/private.pem").write_text("private sentinel")
    return tmp_path


def test_publication_contains_only_explicit_bundles(work):
    info = {"version": "1.2.3"}
    destination = work / "publication"
    workflow.publication_assets(work, info, destination)
    assert {p.name for p in destination.iterdir()} == {
        "myownca-1.2.3-linux-amd64.zip", "myownca-1.2.3-linux-arm64.zip",
        "release-trust.json", "BOOTSTRAP-SHA256SUMS"}
    expected = {"assets": {p.name: sha256(p) for p in destination.iterdir()}}
    workflow.verify_publication(work, info, expected)
    with zipfile.ZipFile(destination / "myownca-1.2.3-linux-amd64.zip") as archive:
        assert set(archive.namelist()) == {"app.whl", "release.json", "release.json.sig"}
    # A newly accepted bundle cannot reuse stale, previously staged export bytes.
    (work / "amd64/bundle/app.whl").write_bytes(b"changed wheel")
    with pytest.raises(VerificationError, match="accepted bundle"):
        workflow.verify_publication(work, info, expected)


def test_publication_rejects_extra_files_even_with_rehashed_inventory(work):
    workflow.publication_assets(work, {"version": "1.2.3"}, work / "publication")
    (work / "publication/private.pem").write_text("sentinel")
    expected = {"assets": {p.name: sha256(p) for p in (work / "publication").iterdir()}}
    with pytest.raises(VerificationError, match="Unexpected publication assets"):
        workflow.verify_publication(work, {"version": "1.2.3"}, expected)


def acceptance_reports(work, info):
    directory = work / "acceptance"
    for target in workflow.TARGETS:
        out = directory / target
        (out / "evidence").mkdir(parents=True)
        (out / "evidence/results.log").write_text("native acceptance output")
        workflow.write_json(out / "acceptance.json", {
            **info, "target": target, "operator": "Test operator",
            "manifest_sha256": sha256(work / target.rsplit("-", 1)[1] / "bundle/release.json"),
            "checks": dict.fromkeys(workflow.CHECKS, True),
            "evidence": {"results.log": sha256(out / "evidence/results.log")},
        })
    return directory


def test_all_native_acceptance_records_are_required_and_bound(work, monkeypatch):
    info = {"version": "1.2.3", "commit": "a" * 40}
    monkeypatch.setattr(workflow, "verify_bundles", lambda _: info)
    directory = acceptance_reports(work, info)
    assert {p.name for p in directory.iterdir()} == {"docker-amd64", "docker-arm64"}
    assert workflow.check_acceptance(work, directory) == info
    (work / "arm64/bundle/release.json").write_text("different release")
    with pytest.raises(VerificationError, match="stale acceptance for docker-arm64"):
        workflow.check_acceptance(work, directory)


def test_acceptance_rejects_missing_or_changed_evidence(work, monkeypatch):
    info = {"version": "1.2.3", "commit": "a" * 40}
    monkeypatch.setattr(workflow, "verify_bundles", lambda _: info)
    directory = acceptance_reports(work, info)
    (directory / "docker-amd64/evidence/results.log").write_text("changed")
    with pytest.raises(VerificationError, match="evidence changed"):
        workflow.check_acceptance(work, directory)


@pytest.mark.parametrize("system,machine", [("Darwin", "arm64"), ("Linux", "x86_64")])
def test_record_acceptance_rejects_wrong_host(system, machine, monkeypatch):
    monkeypatch.setattr(workflow.platform, "system", lambda: system)
    monkeypatch.setattr(workflow.platform, "machine", lambda: machine)
    with pytest.raises(VerificationError, match="native Linux"):
        workflow.record_acceptance(argparse.Namespace(target="docker-arm64"))


def test_record_acceptance_rejects_standalone_target():
    with pytest.raises(VerificationError, match="Unsupported acceptance target"):
        workflow.record_acceptance(argparse.Namespace(target="standalone-amd64"))


@pytest.mark.parametrize("target", ["docker-amd64", "docker-arm64"])
def test_each_docker_acceptance_record_is_required(work, monkeypatch, target):
    info = {"version": "1.2.3", "commit": "a" * 40}
    monkeypatch.setattr(workflow, "verify_bundles", lambda _: info)
    directory = acceptance_reports(work, info)
    (directory / target / "acceptance.json").unlink()
    with pytest.raises(VerificationError, match="Expected regular JSON file"):
        workflow.check_acceptance(work, directory)


@pytest.mark.parametrize("target,machine", [("docker-amd64", "x86_64"),
                                            ("docker-arm64", "aarch64")])
def test_record_docker_acceptance_with_real_signed_bundle(signed_work, monkeypatch, target, machine):
    work, info = signed_work
    monkeypatch.setattr(workflow.platform, "system", lambda: "Linux")
    monkeypatch.setattr(workflow.platform, "machine", lambda: machine)
    results = work / "results.json"
    results.write_text(json.dumps(dict.fromkeys(workflow.CHECKS, True)))
    evidence = work / "evidence"
    evidence.mkdir()
    (evidence / "checks.log").write_text("test fixture evidence")
    output = work / "acceptance"
    workflow.record_acceptance(argparse.Namespace(
        target=target, bundle=work / target.rsplit("-", 1)[1] / "bundle",
        version=info["version"], trust=work / "release-trust.json", results=results,
        evidence=evidence, output=output, operator="Test operator"))
    report = workflow.read_json(output / target / "acceptance.json")
    assert report["target"] == target
    assert report["native_machine"] == machine
    assert report["checks"]["wrong_image_digest_rejected"] is True
    assert "offline_install" not in report["checks"]
    assert report["evidence"]["checks.log"] == sha256(evidence / "checks.log")


@pytest.mark.parametrize("change", ["missing_digest_check", "failed_tamper_check", "offline_field"])
def test_docker_acceptance_keeps_required_security_checks(work, monkeypatch, change):
    info = {"version": "1.2.3", "commit": "a" * 40}
    monkeypatch.setattr(workflow, "verify_bundles", lambda _: info)
    directory = acceptance_reports(work, info)
    path = directory / "docker-amd64/acceptance.json"
    report = workflow.read_json(path)
    if change == "missing_digest_check":
        del report["checks"]["wrong_image_digest_rejected"]
    elif change == "failed_tamper_check":
        report["checks"]["tampered_code_rejected"] = False
    else:
        report["checks"]["offline_install"] = True
    path.write_text(json.dumps(report))
    with pytest.raises(VerificationError, match="stale acceptance for docker-amd64"):
        workflow.check_acceptance(work, directory)


def source_signing_key(directory, name="source"):
    key = ed25519.Ed25519PrivateKey.generate()
    private = directory / name
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.OpenSSH,
                                         serialization.NoEncryption()))
    private.chmod(0o600)
    public = directory / f"{name}.pub"
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                   serialization.PublicFormat.OpenSSH))
    return private, public


@pytest.fixture
def public_snapshot(tmp_path, repo, monkeypatch):
    for name in ("README.md", "docs/guide.md", "LICENSE", "AGENTS.md", "TODO", "archive/private.md"):
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"test-only source fixture: {name}\n")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "test(release): add source snapshot inputs")
    info = {"public_repo": "owner/releases", "tag": "v1.2.3", "commit": git(repo, "rev-parse", "HEAD")}
    private_key, signing_key = source_signing_key(tmp_path)
    public = tmp_path / "public"
    public.mkdir()
    git(public, "init", "-b", "main")
    for key, value in (("user.name", "Release Test"), ("user.email", "release@example.test"),
                       ("gpg.format", "ssh"), ("user.signingkey", str(private_key)),
                       ("commit.gpgsign", "true")):
        git(public, "config", key, value)
    for name in ("app.txt", "README.md", "docs/guide.md", "LICENSE"):
        path = public / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / name, path)
    git(public, "add", ".")
    message = f"chore(release): publish source snapshot\n\nSource-Tag: {info['tag']}\nSource-Commit: {info['commit']}"
    git(public, "commit", "-m", message)
    real_run = workflow.run
    def fake_run(*args, **kwargs):
        if args[:3] == ("gh", "repo", "view"):
            return json.dumps({"nameWithOwner": "owner/releases", "isPrivate": False,
                               "defaultBranchRef": {"name": "main"}})
        if len(args) > 5 and args[0] == "git" and args[3:5] == ("fetch", "--no-tags"):
            args = (*args[:5], public, *args[6:])
        return real_run(*args, **kwargs)
    monkeypatch.setattr(workflow, "run", fake_run)
    return public, repo, signing_key, info, message


def test_public_destination_accepts_signed_source_and_customer_docs(public_snapshot):
    public, source, key, info, message = public_snapshot
    (public / "README.md").write_text("Customer source inspection instructions.\n")
    (public / "docs/code-signing.md").write_text("Trusted source signing instructions.\n")
    git(public, "add", ".")
    git(public, "commit", "-m", message)
    assert workflow.public_destination(info, source, key) == git(public, "rev-parse", "HEAD")


@pytest.mark.parametrize("change", ["content", "mode", "missing", "licence"])
def test_public_destination_rejects_changed_source(public_snapshot, change):
    public, source, key, info, message = public_snapshot
    if change == "content":
        (public / "app.txt").write_text("tampered source\n")
    elif change == "mode":
        (public / "app.txt").chmod(0o755)
    elif change == "missing":
        git(public, "rm", "app.txt")
    else:
        (public / "LICENSE").write_text("substituted terms\n")
    git(public, "add", ".")
    git(public, "commit", "-m", message)
    with pytest.raises(VerificationError, match="missing source|source differs"):
        workflow.public_destination(info, source, key)


@pytest.mark.parametrize("name", ["private.pem", "AGENTS.md", "TODO", "archive/private.md",
                                  ".github/workflows/unreviewed.yml"])
def test_public_destination_rejects_unapproved_files(public_snapshot, name):
    public, source, key, info, message = public_snapshot
    path = public / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("test-only sentinel\n")
    git(public, "add", ".")
    git(public, "commit", "-m", message)
    with pytest.raises(VerificationError, match="Unexpected public snapshot file"):
        workflow.public_destination(info, source, key)


@pytest.mark.parametrize("change", ["unsigned", "wrong_key", "wrong_tag", "wrong_commit", "duplicate"])
def test_public_destination_rejects_wrong_identity(public_snapshot, tmp_path, change):
    public, source, key, info, message = public_snapshot
    if change == "unsigned":
        git(public, "config", "commit.gpgsign", "false")
    elif change == "wrong_key":
        private, _ = source_signing_key(tmp_path, "other")
        git(public, "config", "user.signingkey", str(private))
    elif change == "wrong_tag":
        message = message.replace("v1.2.3", "v1.2.4")
    elif change == "wrong_commit":
        message = message.replace(info["commit"], "a" * 40)
    else:
        message += f"\nSource-Commit: {info['commit']}"
    git(public, "commit", "--allow-empty", "-m", message)
    with pytest.raises(VerificationError, match="signature|version or source commit"):
        workflow.public_destination(info, source, key)


def test_public_destination_pins_snapshot_when_main_advances(public_snapshot):
    public, source, key, info, _ = public_snapshot
    reviewed = git(public, "rev-parse", "HEAD")
    (public / "app.txt").write_text("next release\n")
    git(public, "add", ".")
    git(public, "commit", "-m", f"chore(release): publish next snapshot\n\nSource-Tag: v1.2.4\nSource-Commit: {'b' * 40}")
    assert workflow.public_destination(info, source, key, reviewed) == reviewed
    with pytest.raises(VerificationError, match="version or source commit"):
        workflow.public_destination(info, source, key)


def test_public_destination_rejects_private_history(public_snapshot):
    public, source, key, info, message = public_snapshot
    git(public, "fetch", source, info["commit"])
    commit = git(public, "commit-tree", "HEAD^{tree}", "-p", info["commit"], "-S", "-m", message)
    git(public, "update-ref", "refs/heads/main", commit)
    with pytest.raises(VerificationError, match="private source history"):
        workflow.public_destination(info, source, key)


def test_registry_auth_failure_is_not_treated_as_image_absence(monkeypatch):
    monkeypatch.setattr(workflow.subprocess, "run", lambda *a, **k:
                        subprocess.CompletedProcess(a, 1, "", "unauthorized"))
    with pytest.raises(VerificationError, match="registry image absence"):
        workflow.require_absent_image("ghcr.io/owner/app:1.2.3")


def test_publisher_rechecks_remote_before_finalizing(work, monkeypatch):
    info = {"version": "1.2.3", "tag": "v1.2.3", "public_repo": "owner/releases"}
    monkeypatch.setattr(workflow, "check_acceptance", lambda *a: info)
    monkeypatch.setattr(workflow, "public_destination", lambda *a: "b" * 40)
    def reject(*args):
        raise VerificationError("remote mismatch")
    monkeypatch.setattr(workflow, "verify_remote", reject)
    calls = []
    monkeypatch.setattr(workflow, "run", lambda *a, **k: calls.append(a))
    workflow.write_json(work / "publication.json", {"public_commit": "b" * 40})
    with pytest.raises(VerificationError, match="remote mismatch"):
        workflow.publish(argparse.Namespace(work=work, acceptance=work / "acceptance",
                                           source_signing_key=work / "test-source.pub"))
    assert calls == []


def test_customer_compose_has_no_source_build_or_floating_application():
    public = Path(__file__).parents[1] / "scripts/releases/public"
    compose = (public / "compose.yaml").read_text()
    assert "build:" not in compose
    assert 'image: "@CA_IMAGE@"' in compose
    assert 'image: "@PROXY_IMAGE@"' in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert "external: true" in compose
    assert "127.0.0.1:8765:8765" in compose
    assert "create_host_path: false" in compose


@pytest.fixture(scope="module")
def release_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


@pytest.fixture
def signed_work(tmp_path, release_key, monkeypatch):
    info = {"version": "1.2.3", "tag": "v1.2.3", "commit": "a" * 40,
            "public_repo": "owner/releases"}
    public = release_key.public_key()
    trust = {"schema": 1, "sequence": 1, "keys": {fingerprint(public): public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}}
    workflow.write_json(tmp_path / "release-trust.json", trust)
    workflow.write_json(tmp_path / "ring.json", {"schema": 1, "keys": {"test": base64.b64encode(
        public.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)).decode()}})
    source = tmp_path / "input/myownca-1.2.3-py3-none-any.whl"
    source.parent.mkdir()
    with zipfile.ZipFile(source, "x") as archive:
        for namespace in ("myownca", "myownca_core", "myownca_release"):
            archive.writestr(f"{namespace}/__init__.py", "# fixture\n")
        archive.writestr("myownca-1.2.3.dist-info/METADATA", "Name: myownca\nVersion: 1.2.3\n")
        archive.writestr("myownca-1.2.3.dist-info/RECORD", "")
    images = {"ca": "ghcr.io/owner/app@sha256:" + "b" * 64}
    workflow.write_json(tmp_path / "images.json", images)
    for arch in workflow.ARCHES:
        bundle = tmp_path / arch / "bundle"
        bundle.mkdir(parents=True)
        seal_wheel(source, bundle / source.name, release_key, info["commit"], tmp_path / "ring.json")
        (bundle / "myownca_release_tools-1.2.3-py3-none-any.whl").write_bytes(b"fixture verifier")
        for name in (*workflow.DOC_FILES, "requirements.lock"):
            (bundle / name).write_text("fixture deployment material\n")
        write_signed(bundle / "release.json", {
            **key_metadata(release_key, "release"), "version": info["version"],
            "commit": info["commit"], "images": images,
            "artifacts": {p.name: {"size": p.stat().st_size, "sha256": sha256(p)}
                          for p in bundle.iterdir()},
        }, release_key)
    monkeypatch.setattr(workflow, "metadata", lambda _: info)
    return tmp_path, info


def test_real_signed_bundles_reject_unsigned_extra_files(signed_work):
    work, info = signed_work
    assert workflow.verify_bundles(work) == info
    (work / "arm64/bundle/secret.env").write_text("sentinel")
    with pytest.raises(VerificationError, match="Unlisted"):
        workflow.verify_bundles(work)


def test_sign_includes_canonical_license_and_rejects_its_tampering(
        signed_work, release_key, monkeypatch):
    work, info = signed_work
    root = Path(__file__).parents[1]
    source = work / "source"
    shutil.copytree(root / "scripts/releases/public", source / "scripts/releases/public")
    shutil.copytree(root / "deploy/integrity", source / "deploy/integrity")
    shutil.copyfile(root / "nginx.conf", source / "nginx.conf")
    shutil.copyfile(root / "LICENSE", source / "LICENSE")
    images = workflow.read_json(work / "images.json")
    images["proxy"] = "nginx@sha256:" + "c" * 64
    (work / "images.json").write_text(json.dumps(images))
    for arch in workflow.ARCHES:
        bundle = work / arch / "bundle"
        for name in (*workflow.DOC_FILES, "release.json", "release.json.sig"):
            (bundle / name).unlink()
        workflow.write_json(work / arch / "image.json", {
            "files": {p.name: sha256(p) for p in bundle.iterdir()}})
    monkeypatch.setattr("myownca_release.sign.load_private", lambda _: release_key)
    workflow.sign(argparse.Namespace(work=work, private_key=work / "unused-test-key"))
    assert workflow.verify_bundles(work) == info
    for arch in workflow.ARCHES:
        assert (work / arch / "bundle/LICENSE").read_bytes() == (root / "LICENSE").read_bytes()
        names = {p.name for p in (work / arch / "bundle").iterdir()}
        assert "myownca-integrity.service" not in names
        assert "myownca-integrity.timer" not in names
        assert {"myownca-container-integrity.service", "myownca-container-integrity.timer"} <= names
        instructions = (work / arch / "bundle/INSTALL.md").read_text()
        assert "## Standalone" not in instructions
        assert "myownca-verify --json install" not in instructions
    (work / "amd64/bundle/LICENSE").write_text("substituted terms")
    with pytest.raises(VerificationError, match="integrity"):
        workflow.verify_bundles(work)


def test_stage_roundtrip_and_remote_tamper_block_publication(signed_work, monkeypatch):
    work, info = signed_work
    acceptance = acceptance_reports(work, info)
    assert {p.name for p in acceptance.iterdir()} == {"docker-amd64", "docker-arm64"}
    notes = work / "notes.md"
    notes.write_text("Reviewed customer release notes.\n")
    destinations = []
    def destination(*args):
        destinations.append(args)
        return "c" * 40
    monkeypatch.setattr(workflow, "public_destination", destination)
    monkeypatch.setattr(workflow, "release_exists", lambda _: False)
    monkeypatch.setattr(workflow, "public_tags", lambda _: {})
    uploads = {}
    calls = []
    def fake_gh(*args, **kwargs):
        calls.append(args)
        if args[:3] == ("gh", "release", "upload"):
            for path in args[6:]:
                uploads[path.name] = path.read_bytes()
        elif args[:3] == ("gh", "release", "view"):
            return json.dumps({"isDraft": True, "assets": [{"name": name} for name in uploads],
                               "body": notes.read_text(), "targetCommitish": "c" * 40})
        elif args[:3] == ("gh", "release", "download"):
            destination = Path(args[-1])
            for name, data in uploads.items():
                (destination / name).write_bytes(data)
        return ""
    monkeypatch.setattr(workflow, "run", fake_gh)
    source_key = work / "test-source.pub"
    workflow.stage(argparse.Namespace(work=work, acceptance=acceptance, notes=notes,
                                     source_signing_key=source_key))
    assert len(uploads) == 4
    assert calls[0][0:3] == ("gh", "release", "create")
    assert "--draft" in calls[0]
    original = uploads["myownca-1.2.3-linux-amd64.zip"]
    uploads["myownca-1.2.3-linux-amd64.zip"] += b"tampered"
    with pytest.raises(VerificationError, match="Downloaded publication asset"):
        workflow.publish(argparse.Namespace(work=work, acceptance=acceptance,
                                           source_signing_key=source_key))
    assert not any(call[:3] == ("gh", "release", "edit") for call in calls)
    uploads["myownca-1.2.3-linux-amd64.zip"] = original
    audits = []
    monkeypatch.setattr(workflow, "audit_public", lambda args: audits.append(args.work))
    workflow.publish(argparse.Namespace(work=work, acceptance=acceptance,
                                       source_signing_key=source_key))
    assert destinations[0] == (info, work / "source", source_key)
    assert destinations[-1] == (info, work / "source", source_key, "c" * 40)
    assert any(call[:3] == ("gh", "release", "edit") for call in calls)
    assert audits == [work]


def test_image_inputs_cannot_change_between_build_and_sign(tmp_path):
    bundle = tmp_path / "amd64/bundle"
    bundle.mkdir(parents=True)
    (bundle / "requirements.lock").write_text("original")
    workflow.write_json(tmp_path / "amd64/image.json", {
        "files": {"requirements.lock": sha256(bundle / "requirements.lock")}})
    workflow.image_inputs(tmp_path, "amd64")
    (bundle / "requirements.lock").write_text("replacement")
    with pytest.raises(VerificationError, match="inputs changed"):
        workflow.image_inputs(tmp_path, "amd64")


def test_private_key_inside_signed_application_is_not_publishable(tmp_path, release_key):
    source = tmp_path / "source/myownca-1.2.3-py3-none-any.whl"
    source.parent.mkdir()
    with zipfile.ZipFile(source, "x") as archive:
        archive.writestr("myownca/static/accidental.pem", "-----BEGIN PRIVATE KEY-----\nfixture")
    with pytest.raises(VerificationError, match="Private or development"):
        workflow.verify_wheel(source, {}, {})


def test_anonymous_audit_uses_empty_docker_credentials(signed_work, monkeypatch):
    work, info = signed_work
    workflow.publication_assets(work, info, work / "publication")
    assets = {p.name: sha256(p) for p in (work / "publication").iterdir()}
    workflow.write_json(work / "publication.json", {"assets": assets, "public_commit": "c" * 40})
    monkeypatch.setattr(workflow, "public_tags", lambda _: {info["tag"]: "c" * 40})
    urls = []
    def urlopen(url, **kwargs):
        urls.append(url)
        return (work / "publication" / url.rsplit("/", 1)[1]).open("rb")
    monkeypatch.setattr(workflow.urllib.request, "urlopen", urlopen)
    pulls = []
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    def run(*args, **kwargs):
        if args[:3] == ("docker", "context", "inspect"):
            return "unix:///test/docker.sock"
        assert args[:2] == ("docker", "--config")
        assert json.loads((args[2] / "config.json").read_text()) == {"auths": {}}
        assert args[3:5] == ("--host", "unix:///test/docker.sock")
        pulls.append(args)
    monkeypatch.setattr(workflow, "run", run)
    workflow.audit_public(argparse.Namespace(work=work))
    assert len(urls) == 4
    assert {call[7] for call in pulls} == {"linux/amd64", "linux/arm64"}
