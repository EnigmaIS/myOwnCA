#!/usr/bin/env python3
"""Operator-only release workflow. Never mirror the private Git repository.

Run with a trusted Python environment containing myownca-release-tools and build.
Publication is explicit; prepare/seal/wheelhouse/build-image never publish.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from myownca_release.sign import load_private, seal_wheel, wheel_contents
from myownca_release.sign import main as sign_main
from myownca_release.verify import (
    VerificationError, json_bytes, load_trust, sha256, verify_installed, verify_release,
)

ARCHES = ("amd64", "arm64")
TARGETS = ("docker-amd64", "docker-arm64")
CHECKS = (
    "fresh_install", "setup", "restart_preserves_state", "certificate_issuance",
    "valid_license", "wrong_installation_license_rejected", "tampered_code_rejected",
    "tampered_license_keys_rejected", "missing_signature_rejected", "upgrade",
    "explicit_rollback", "external_integrity", "wrong_image_digest_rejected",
)
DOC_FILES = (
    "LICENSE", "INSTALL.md", "compose.yaml", "nginx.conf", "deploy-compose.sh",
    "myownca-container-integrity.service", "myownca-container-integrity.timer",
)
REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
IMAGE_RE = re.compile(r"ghcr\.io/[a-z0-9][a-z0-9._/-]*\Z")
DIGEST_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}\Z")


def run(*args, cwd=None, capture=False, env=None):
    if args and args[0] == "gh":
        env = {**(os.environ if env is None else env), "GH_HOST": "github.com"}
    result = subprocess.run([str(arg) for arg in args], cwd=cwd, env=env,
                            check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def write_json(path, value):
    with path.open("xb") as stream:
        stream.write(json_bytes(value))


def read_json(path):
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"Expected regular JSON file: {path}")
    return json.loads(path.read_text())


def git(repo, *args):
    return run("git", "-C", repo, *args, capture=True)


def clean_commit(repo):
    if git(repo, "status", "--porcelain", "--untracked-files=all"):
        raise VerificationError("Release source tree must be clean, including untracked files")
    if git(repo, "rev-parse", "--is-shallow-repository") != "false":
        raise VerificationError("A complete Git history is required")
    if any(name.startswith("SETUPTOOLS_SCM_PRETEND_") for name in os.environ):
        raise VerificationError("SCM version overrides are forbidden")
    return git(repo, "rev-parse", "HEAD")


def release_identity(repo, tag):
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise VerificationError("An annotated stable vX.Y.Z tag is required")
    clean_commit(repo)
    if git(repo, "cat-file", "-t", f"refs/tags/{tag}") != "tag":
        raise VerificationError("Release tag must be annotated")
    commit = git(repo, "rev-parse", f"refs/tags/{tag}^{{commit}}")
    run("git", "-C", repo, "merge-base", "--is-ancestor", commit, "refs/remotes/origin/master")
    return {"tag": tag, "version": tag[1:], "commit": commit}


def propose_tag(args):
    tags = git(args.repo, "tag", "--merged", "HEAD", "--list", "v*").splitlines()
    versions = [tuple(map(int, tag[1:].split("."))) for tag in tags
                if re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
                and git(args.repo, "cat-file", "-t", f"refs/tags/{tag}") == "tag"]
    previous = max(versions, default=(0, 0, 0))
    following = list(previous)
    index = {"major": 0, "minor": 1, "patch": 2}[args.bump]
    following[index] += 1
    following[index + 1:] = [0] * (2 - index)
    print(json.dumps({"from": "v" + ".".join(map(str, previous)),
                      "to": "v" + ".".join(map(str, following)), "transition": args.bump,
                      "subject": args.subject, "approval_required": True}))


def require_passed_junit(path):
    cases = list(ET.parse(path).iter("testcase"))
    if not cases or any(case.find("failure") is not None or case.find("error") is not None
                        for case in cases):
        raise VerificationError("Regression suite did not pass")
    required = {"test_real_sealed_wheel_launchers", "test_every_source_data_file_is_packaged"}
    passed = {case.attrib.get("name") for case in cases if case.find("skipped") is None}
    if not required <= passed:
        raise VerificationError("Packaging / real sealed-wheel tests must run, not skip")


def validate(args):
    repo = args.repo.resolve()
    commit = clean_commit(repo)
    if not os.environ.get("MYOWNCA_TEST_MARIADB_ADMIN_URL"):
        raise VerificationError("Configure the isolated MariaDB test service before release validation")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="myownca-validation-") as directory:
        source = Path(directory) / "source"
        run("git", "clone", "--no-local", repo, source)
        run("git", "-C", source, "checkout", "--detach", commit)
        venv = Path(directory) / "venv"
        run(sys.executable, "-m", "venv", venv)
        python = venv / "bin/python"
        run(python, "-m", "pip", "install", "-e", f"{source}[dev]", "build")
        for name, command in (
            ("ruff.log", [python, "-m", "ruff", "check", "src", "core", "tests",
                          "scripts/releases", "tools/license-issuer/src"]),
            ("pytest.log", [python, "-m", "pytest", "-q", f"--junitxml={out / 'pytest.xml'}"]),
        ):
            with (out / name).open("x") as log:
                subprocess.run([str(x) for x in command], cwd=source, check=True,
                               stdout=log, stderr=subprocess.STDOUT)
        require_passed_junit(out / "pytest.xml")
    write_json(out / "validation.json", {"commit": commit, "status": "passed",
               "files": {p.name: sha256(p) for p in out.iterdir()},
               "time": datetime.now(timezone.utc).isoformat()})


def check_validation(directory, commit):
    report = read_json(directory / "validation.json")
    if report.get("status") != "passed" or report.get("commit") != commit:
        raise VerificationError("Validation must cover the exact release commit")
    files = report.get("files", {})
    if set(files) != {"ruff.log", "pytest.log", "pytest.xml"}:
        raise VerificationError("Incomplete validation evidence")
    for name, digest in files.items():
        if (directory / name).is_symlink() or sha256(directory / name) != digest:
            raise VerificationError("Validation evidence changed")
    require_passed_junit(directory / "pytest.xml")


def prepare(args):
    repo = args.repo.resolve()
    clean_commit(repo)
    # Fetch explicitly: a stale local origin/master is not release approval evidence.
    run("git", "-C", repo, "fetch", "origin", "+refs/heads/master:refs/remotes/origin/master",
        "--tags")
    identity = release_identity(repo, args.tag)
    check_validation(args.validation, identity["commit"])
    if not REPO_RE.fullmatch(args.public_repo) or not IMAGE_RE.fullmatch(args.image):
        raise VerificationError("Provide owner/repo and a lowercase ghcr.io/owner/image")
    for reference in (args.base_image, args.proxy_image):
        if not DIGEST_RE.fullmatch(reference):
            raise VerificationError("Base and proxy images must be pinned by sha256 digest")
    work = args.work.resolve()
    if work.is_relative_to(repo):
        raise VerificationError("Release workspace must be outside the source repository")
    work.mkdir(parents=True, exist_ok=False)
    source = work / "source"
    run("git", "clone", "--no-local", repo, source)
    run("git", "-C", source, "checkout", "--detach", identity["commit"])
    shutil.copytree(args.validation, work / "validation")
    for project, dest in ((source, "application"), (source / "release-tools", "verifier")):
        run(sys.executable, "-m", "build", "--wheel", "--outdir", work / dest, project)
    app = one_wheel(work / "application", "myownca-")
    if app.name != f"myownca-{identity['version']}-py3-none-any.whl":
        raise VerificationError("Built wheel version does not match the approved tag")
    write_json(work / "release-work.json", {**identity, "public_repo": args.public_repo,
               "image": args.image, "base_image": args.base_image, "proxy_image": args.proxy_image})


def metadata(work):
    value = read_json(work / "release-work.json")
    if clean_commit(work / "source") != value["commit"]:
        raise VerificationError("Isolated release source changed")
    if release_identity(work / "source", value["tag"]) != {
        key: value[key] for key in ("tag", "version", "commit")
    }:
        raise VerificationError("Release identity changed")
    check_validation(work / "validation", value["commit"])
    return value


def one_wheel(directory, prefix):
    paths = list(directory.glob(prefix + "*.whl"))
    if len(paths) != 1 or paths[0].is_symlink():
        raise VerificationError(f"Expected one {prefix} wheel in {directory}")
    return paths[0]


def seal(args):
    work = args.work.resolve()
    info = metadata(work)
    trust = load_trust(args.trust)
    key = load_private(args.private_key)
    source = one_wheel(work / "application", "myownca-")
    destination = work / "sealed"
    destination.mkdir()
    seal_wheel(source, destination / source.name, key, info["commit"], args.license_public_keys)
    verify_wheel(destination / source.name, trust, info)
    shutil.copyfile(args.trust, work / "release-trust.json")


def verify_wheel(path, trust, info):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, raw in wheel_contents(path).items():
            if (name.split("/")[0] in {".git", "tests", "tools", "license_issuer"}
                    or Path(name).name in {".env", "secrets.env"}
                    or re.match(rb"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----", raw)):
                raise VerificationError("Private or development material in application wheel")
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        result = verify_installed(root, trust)
    if any(result[name] != info[name] for name in ("version", "commit")):
        raise VerificationError("Wheel identity does not match release")


def wheelhouse(args):
    work = args.work.resolve()
    info = metadata(work)
    trust = load_trust(work / "release-trust.json")
    app = one_wheel(work / "sealed", "myownca-")
    verify_wheel(app, trust, info)
    bundle = work / args.arch / "bundle"
    bundle.mkdir(parents=True, exist_ok=False)
    verifier = one_wheel(work / "verifier", "myownca_release_tools-")
    shutil.copyfile(app, bundle / app.name)
    shutil.copyfile(verifier, bundle / verifier.name)
    command = ["docker", "run", "--rm", "--platform", f"linux/{args.arch}",
               "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
               "--mount", f"type=bind,src={bundle},dst=/out"]
    extra = []
    if args.wheels:
        command += ["--mount", f"type=bind,src={args.wheels.resolve()},dst=/reviewed,readonly"]
        extra = ["--find-links", "/reviewed"]
    run(*command, info["base_image"], "python", "-c",
        "import sys; assert sys.version_info[:2] == (3, 12), 'Python 3.12 is required'")
    run(*command, info["base_image"], "python", "-m", "pip", "download",
        "--only-binary=:all:", "--dest", "/out", *extra,
        f"/out/{app.name}", f"/out/{verifier.name}")
    run(sys.executable, work / "source/scripts/releases/lock-wheelhouse.py", bundle)


def candidate_files(bundle):
    allowed = {"requirements.lock"}
    for path in bundle.iterdir():
        if path.is_symlink() or not path.is_file():
            raise VerificationError("Bundle must contain regular files only")
        if path.name not in allowed and path.suffix != ".whl":
            raise VerificationError(f"Unexpected build input: {path.name}")


def build_image(args):
    work = args.work.resolve()
    info = metadata(work)
    bundle = work / args.arch / "bundle"
    candidate_files(bundle)
    verify_wheel(one_wheel(bundle, "myownca-"), load_trust(work / "release-trust.json"), info)
    context = work / args.arch / "context"
    context.mkdir()
    shutil.copytree(bundle, context / "bundle")
    shutil.copyfile(work / "release-trust.json", context / "release-trust.json")
    shutil.copyfile(work / "source/Dockerfile.release", context / "Dockerfile")
    tag = f"{info['image']}:{info['version']}-{args.arch}"
    run("docker", "buildx", "build", "--load", "--platform", f"linux/{args.arch}",
        "--build-arg", f"MYOWNCA_BASE_IMAGE={info['base_image']}",
        "--label", f"org.opencontainers.image.source=https://github.com/{info['public_repo']}",
        "--label", f"org.opencontainers.image.revision={info['commit']}", "--tag", tag, context)
    image_id = run("docker", "image", "inspect", "--format", "{{.Id}}", tag, capture=True)
    run("docker", "run", "--rm", "--network=none", "--read-only", "--tmpfs", "/tmp",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
        "--platform", f"linux/{args.arch}", image_id, "--help")
    write_json(work / args.arch / "image.json", {"tag": tag, "id": image_id,
               "files": {p.name: sha256(p) for p in bundle.iterdir()}})


def require_absent_image(reference):
    result = subprocess.run(["docker", "buildx", "imagetools", "inspect", reference],
                            text=True, capture_output=True)
    if result.returncode == 0:
        raise VerificationError(f"Refusing to replace registry image: {reference}")
    if not any(message in result.stderr.lower()
               for message in ("not found", "manifest unknown", "name unknown")):
        raise VerificationError("Cannot establish registry image absence; check registry access")


def image_inputs(work, arch):
    image = read_json(work / arch / "image.json")
    bundle = work / arch / "bundle"
    candidate_files(bundle)
    if image["files"] != {p.name: sha256(p) for p in bundle.iterdir()}:
        raise VerificationError("Image inputs changed after build")
    return image


def push_images(args):
    work = args.work.resolve()
    info = metadata(work)
    tag = f"{info['image']}:{info['version']}"
    require_absent_image(tag)
    images = [image_inputs(work, arch) for arch in ARCHES]
    # Complete all local checks before the first external write.
    for arch, image in zip(ARCHES, images, strict=True):
        if run("docker", "image", "inspect", "--format", "{{.Id}}", image["tag"],
               capture=True) != image["id"]:
            raise VerificationError("Local image tag changed after build")
        require_absent_image(image["tag"])
    for image in images:
        run("docker", "push", image["tag"])
    run("docker", "buildx", "imagetools", "create", "--tag", tag,
        *(image["tag"] for image in images))
    descriptor = json.loads(run("docker", "buildx", "imagetools", "inspect", tag,
                                "--format", "{{json .Manifest}}", capture=True))
    platforms = {(entry.get("platform", {}).get("os"),
                  entry.get("platform", {}).get("architecture"))
                 for entry in descriptor.get("manifests", [])}
    if not {("linux", arch) for arch in ARCHES} <= platforms:
        raise VerificationError("Registry index does not contain both required Linux architectures")
    reference = f"{info['image']}@{descriptor['digest']}"
    if not DIGEST_RE.fullmatch(reference):
        raise VerificationError("Registry did not return a sha256 image digest")
    write_json(work / "images.json", {"ca": reference, "proxy": info["proxy_image"]})


def sign(args):
    work = args.work.resolve()
    info = metadata(work)
    images = read_json(work / "images.json")
    templates = work / "source/scripts/releases/public"
    for arch in ARCHES:
        image_inputs(work, arch)
    for arch in ARCHES:
        bundle = work / arch / "bundle"
        candidate_files(bundle)
        for name in DOC_FILES:
            source = templates / name
            if name == "LICENSE":
                source = work / "source/LICENSE"
            elif name == "nginx.conf":
                source = work / "source/nginx.conf"
            elif name.startswith("myownca-"):
                source = work / "source/deploy/integrity" / name
            contents = source.read_text()
            for placeholder, value in {"@VERSION@": info["version"], "@ARCH@": arch,
                                       "@CA_IMAGE@": images["ca"],
                                       "@PROXY_IMAGE@": images["proxy"]}.items():
                contents = contents.replace(placeholder, value)
            with (bundle / name).open("x") as stream:
                stream.write(contents)
        image_args = [part for name, ref in images.items() for part in ("--image", f"{name}={ref}")]
        sign_main(["release", "--bundle", str(bundle), "--version", info["version"],
                   "--commit", info["commit"], "--private-key", str(args.private_key), *image_args])
    verify_bundles(work)


def verify_bundles(work):
    info = metadata(work)
    trust = load_trust(work / "release-trust.json")
    images = read_json(work / "images.json")
    for arch in ARCHES:
        bundle = work / arch / "bundle"
        release = verify_release(bundle, trust, info["version"])
        if release["commit"] != info["commit"] or release["images"] != images:
            raise VerificationError("Signed release differs from workspace identity")
        names = set(release["artifacts"])
        if not set(DOC_FILES) | {"requirements.lock"} <= names:
            raise VerificationError("Missing customer deployment files")
        if any(name not in (*DOC_FILES, "requirements.lock") and not name.endswith(".whl")
               for name in names):
            raise VerificationError("Unexpected public artifact")
        if {p.name for p in bundle.iterdir()} != names | {"release.json", "release.json.sig"}:
            raise VerificationError("Unlisted files in bundle")
        if any(name.startswith(("myownca_core-", "myownca_license_issuer-")) for name in names):
            raise VerificationError("Internal distribution in public bundle")
        one_wheel(bundle, "myownca_release_tools-")
        verify_wheel(one_wheel(bundle, "myownca-"), trust, info)
    return info


def record_acceptance(args):
    """Record an operator's native-platform acceptance, not a simulated test run."""
    if args.target not in TARGETS:
        raise VerificationError("Unsupported acceptance target; Docker amd64 and arm64 are required")
    expected_arch = args.target.rsplit("-", 1)[1]
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or machine != expected_arch:
        raise VerificationError("Acceptance must be recorded on the native Linux target")
    verified = verify_release(args.bundle, load_trust(args.trust), args.version)
    checks = read_json(args.results)
    required = set(CHECKS)
    if set(checks) != required or any(value is not True for value in checks.values()):
        raise VerificationError("Every required acceptance scenario must explicitly pass")
    files = list(args.evidence.iterdir())
    if not files or any(not p.is_file() or p.is_symlink() for p in files):
        raise VerificationError("Provide a flat directory of acceptance evidence files")
    out = args.output / args.target
    out.mkdir(parents=True, exist_ok=False)
    shutil.copytree(args.evidence, out / "evidence")
    write_json(out / "acceptance.json", {
        "target": args.target, "version": args.version, "commit": verified["commit"],
        "manifest_sha256": sha256(args.bundle / "release.json"),
        "checks": checks, "operator": args.operator, "native_machine": platform.machine(),
        "time": datetime.now(timezone.utc).isoformat(),
        "evidence": {p.name: sha256(p) for p in files},
    })


def check_acceptance(work, directory):
    info = verify_bundles(work)
    for target in TARGETS:
        report = read_json(directory / target / "acceptance.json")
        arch = target.rsplit("-", 1)[1]
        required = set(CHECKS)
        if (report.get("target") != target or report.get("version") != info["version"]
                or report.get("commit") != info["commit"] or not report.get("operator")
                or report.get("manifest_sha256") != sha256(work / arch / "bundle/release.json")
                or set(report.get("checks", {})) != required
                or any(value is not True for value in report["checks"].values())
                or not report.get("evidence")):
            raise VerificationError(f"Missing or stale acceptance for {target}")
        for name, digest in report["evidence"].items():
            if Path(name).name != name or name in (".", ".."):
                raise VerificationError("Unsafe acceptance evidence name")
            path = directory / target / "evidence" / name
            if path.is_symlink() or sha256(path) != digest:
                raise VerificationError("Acceptance evidence changed")
    return info


def publication_assets(work, info, destination):
    destination.mkdir()
    for arch in ARCHES:
        bundle = work / arch / "bundle"
        name = f"myownca-{info['version']}-linux-{arch}.zip"
        with zipfile.ZipFile(destination / name, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(bundle.iterdir()):
                archive.write(path, arcname=path.name)
    shutil.copyfile(work / "release-trust.json", destination / "release-trust.json")
    checksums = "".join(f"{sha256(p)}  {p.name}\n" for p in sorted(destination.iterdir()))
    (destination / "BOOTSTRAP-SHA256SUMS").write_text(checksums)


def public_destination(info):
    repo = info["public_repo"]
    value = json.loads(run("gh", "repo", "view", repo, "--json",
                           "nameWithOwner,isPrivate,defaultBranchRef", capture=True))
    if value["isPrivate"] or value["nameWithOwner"].lower() != repo.lower():
        raise VerificationError("Publication requires the explicitly selected public repository")
    branch = value["defaultBranchRef"]["name"]
    commit = json.loads(run("gh", "api", f"repos/{repo}/commits/{branch}", capture=True))["sha"]
    if commit == info["commit"]:
        raise VerificationError("Public repository must have independent documentation history")
    tree = json.loads(run("gh", "api", f"repos/{repo}/git/trees/{commit}?recursive=1", capture=True))
    if tree.get("truncated"):
        raise VerificationError("Cannot inspect the entire public repository tree")
    for item in tree["tree"]:
        if item["type"] == "tree":
            continue
        name = item["path"]
        if (item["type"] != "blob" or item.get("mode") == "120000"
                or not (name in {"README.md", "CHANGELOG.md", "SECURITY.md", "LICENSE", ".gitignore"}
                        or name.startswith("docs/") and name.endswith(".md"))):
            raise VerificationError("Public repository must contain only customer documentation")
    return commit


def release_exists(info):
    pages = json.loads(run("gh", "api", "--paginate", "--slurp",
                          f"repos/{info['public_repo']}/releases?per_page=100", capture=True))
    return any(release["tag_name"] == info["tag"] for page in pages for release in page)


def public_tags(info):
    pages = json.loads(run("gh", "api", "--paginate", "--slurp",
                          f"repos/{info['public_repo']}/tags?per_page=100", capture=True))
    return {tag["name"]: tag["commit"]["sha"] for page in pages for tag in page}


def stage(args):
    work = args.work.resolve()
    info = check_acceptance(work, args.acceptance)
    public_commit = public_destination(info)
    if release_exists(info) or info["tag"] in public_tags(info):
        raise VerificationError("Public release or tag already exists; refusing to replace it")
    destination = work / "publication"
    publication_assets(work, info, destination)
    assets = {p.name: sha256(p) for p in destination.iterdir()}
    notes = args.notes.read_text()
    if not notes.strip():
        raise VerificationError("Provide reviewed customer-facing release notes")
    shutil.copyfile(args.notes, work / "release-notes.md")
    write_json(work / "publication.json", {"assets": assets, "public_commit": public_commit,
               "notes_sha256": sha256(work / "release-notes.md")})
    run("gh", "release", "create", info["tag"], "--repo", info["public_repo"], "--draft",
        "--target", public_commit, "--title", info["tag"], "--notes-file", work / "release-notes.md")
    run("gh", "release", "upload", info["tag"], "--repo", info["public_repo"],
        *(destination / name for name in sorted(assets)))
    verify_remote(work, info)


def verify_remote(work, info):
    expected = read_json(work / "publication.json")
    verify_publication(work, info, expected)
    release = json.loads(run("gh", "release", "view", info["tag"], "--repo", info["public_repo"],
                             "--json", "isDraft,assets,body,targetCommitish", capture=True))
    if not release["isDraft"]:
        raise VerificationError("Only an unpublished draft may be finalized")
    if release["targetCommitish"] != expected["public_commit"]:
        raise VerificationError("Public release target changed")
    tag_commit = public_tags(info).get(info["tag"])
    if tag_commit is not None and tag_commit != expected["public_commit"]:
        raise VerificationError("Public tag differs from the reviewed documentation commit")
    if release["body"].strip() != (work / "release-notes.md").read_text().strip():
        raise VerificationError("Remote release notes differ from the reviewed notes")
    if sha256(work / "release-notes.md") != expected["notes_sha256"]:
        raise VerificationError("Reviewed release notes changed")
    if {asset["name"] for asset in release["assets"]} != set(expected["assets"]):
        raise VerificationError("Unexpected or missing remote assets")
    with tempfile.TemporaryDirectory() as directory:
        run("gh", "release", "download", info["tag"], "--repo", info["public_repo"],
            "--dir", directory)
        for name, digest in expected["assets"].items():
            if sha256(Path(directory) / name) != digest:
                raise VerificationError("Downloaded publication asset differs from approved bytes")
            if sha256(work / "publication" / name) != digest:
                raise VerificationError("Local publication asset changed")


def verify_publication(work, info, expected):
    """Bind export bytes back to the currently verified, accepted bundles."""
    directory = work / "publication"
    names = {f"myownca-{info['version']}-linux-{arch}.zip" for arch in ARCHES}
    names |= {"release-trust.json", "BOOTSTRAP-SHA256SUMS"}
    if set(expected["assets"]) != names or {p.name for p in directory.iterdir()} != names:
        raise VerificationError("Unexpected publication assets")
    for name in names:
        path = directory / name
        if path.is_symlink() or sha256(path) != expected["assets"][name]:
            raise VerificationError("Publication asset changed")
    if (directory / "release-trust.json").read_bytes() != (work / "release-trust.json").read_bytes():
        raise VerificationError("Publication trust differs from verified trust")
    for arch in ARCHES:
        bundle = work / arch / "bundle"
        with zipfile.ZipFile(directory / f"myownca-{info['version']}-linux-{arch}.zip") as archive:
            wanted = {p.name for p in bundle.iterdir()}
            if set(archive.namelist()) != wanted or len(archive.namelist()) != len(wanted):
                raise VerificationError("Unexpected archive members")
            for name in wanted:
                with archive.open(name) as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if digest != sha256(bundle / name):
                    raise VerificationError("Publication archive differs from accepted bundle")
    sums = "".join(f"{sha256(directory / name)}  {name}\n"
                   for name in sorted(names - {"BOOTSTRAP-SHA256SUMS"}))
    if (directory / "BOOTSTRAP-SHA256SUMS").read_text() != sums:
        raise VerificationError("Bootstrap checksums differ from publication assets")


def publish(args):
    work = args.work.resolve()
    info = check_acceptance(work, args.acceptance)
    public_destination(info)
    verify_remote(work, info)
    run("gh", "release", "edit", info["tag"], "--repo", info["public_repo"], "--draft=false")
    print("Release is now public. Checking anonymous access; failure will not unpublish it.")
    audit_public(args)


def audit_public(args):
    work = args.work.resolve()
    info = verify_bundles(work)
    expected = read_json(work / "publication.json")
    verify_publication(work, info, expected)
    if public_tags(info).get(info["tag"]) != expected["public_commit"]:
        raise VerificationError("Published tag differs from the reviewed documentation commit")
    with tempfile.TemporaryDirectory(prefix="myownca-public-audit-") as directory:
        root = Path(directory)
        for name, digest in expected["assets"].items():
            url = (f"https://github.com/{info['public_repo']}/releases/download/"
                   f"{info['tag']}/{name}")
            # No gh credentials or Authorization header: test actual public downloads.
            with urllib.request.urlopen(url, timeout=60) as response, (root / name).open("xb") as out:
                shutil.copyfileobj(response, out)
            if sha256(root / name) != digest:
                raise VerificationError("Anonymous download differs from accepted publication")
        config = root / "docker-config"
        config.mkdir()
        (config / "config.json").write_text('{"auths":{}}')
        # Keep the selected Docker daemon (including Docker Desktop's socket)
        # while discarding registry credentials and credential-helper settings.
        host = os.environ.get("DOCKER_HOST") or run(
            "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}", capture=True)
        reference = read_json(work / "images.json")["ca"]
        for arch in ARCHES:
            run("docker", "--config", config, "--host", host,
                "pull", "--platform", f"linux/{arch}", reference)
    print("Anonymous artifact downloads and image pulls verified for both architectures.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, function in (("propose-tag", propose_tag), ("validate", validate),
                           ("prepare", prepare), ("seal", seal),
                           ("wheelhouse", wheelhouse), ("build-image", build_image),
                           ("push-images", push_images), ("sign", sign),
                           ("verify", lambda a: check_acceptance(a.work.resolve(), a.acceptance)),
                           ("record-acceptance", record_acceptance), ("stage", stage),
                           ("publish", publish), ("audit-public", audit_public)):
        command = commands.add_parser(name)
        command.set_defaults(function=function)
        if name not in ("propose-tag", "validate", "record-acceptance"):
            command.add_argument("--work", type=Path, required=True)
        if name in ("propose-tag", "validate", "prepare"):
            command.add_argument("--repo", type=Path, default=Path.cwd())
        if name == "propose-tag":
            command.add_argument("--bump", choices=("patch", "minor", "major"), required=True)
            command.add_argument("--subject", required=True)
        if name in ("validate", "record-acceptance"):
            command.add_argument("--output", type=Path, required=True)
        if name == "prepare":
            for option in ("tag", "public-repo", "image", "base-image", "proxy-image"):
                command.add_argument("--" + option, required=True)
            command.add_argument("--validation", type=Path, required=True)
        if name in ("seal", "sign"):
            command.add_argument("--private-key", type=Path, required=True)
        if name == "seal":
            command.add_argument("--license-public-keys", type=Path, required=True)
        if name in ("seal", "record-acceptance"):
            command.add_argument("--trust", type=Path, required=True)
        if name in ("wheelhouse", "build-image"):
            command.add_argument("--arch", choices=ARCHES, required=True)
        if name == "wheelhouse":
            command.add_argument("--wheels", type=Path, help="Reviewed prebuilt dependency wheels")
        if name in ("verify", "stage", "publish"):
            command.add_argument("--acceptance", type=Path, required=True)
        if name == "stage":
            command.add_argument("--notes", type=Path, required=True)
        if name == "record-acceptance":
            command.add_argument("--target", choices=TARGETS, required=True)
            for option in ("bundle", "results", "evidence"):
                command.add_argument("--" + option, type=Path, required=True)
            command.add_argument("--version", required=True)
            command.add_argument("--operator", required=True)
    args = parser.parse_args(argv)
    try:
        args.function(args)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Release operation failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
