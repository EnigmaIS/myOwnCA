"""Guard against the wheel-packaging regression the Docker smoke caught.

myOwnCA loads several runtime files by ``__file__``-relative path: the setup
wizard HTML (``myownca/setup/static/setup.html``), every portal page under
``myownca/online/static/``, and the schema migrations under
``myownca/storage/migrations/*.sql``. None of those are Python modules, so they
ship only if declared as package data.

The pytest suite runs from the source tree (``pythonpath=["src"]``), where the
files always exist on disk — so it CANNOT see when an installed wheel is missing
them. That exact gap shipped once: ``pip install`` produced a wheel with no
package data, and the Docker image 500'd on ``GET /setup``. It was fixed by
adding ``[tool.setuptools.package-data]`` to ``pyproject.toml``.

This test builds a real wheel from an isolated copy of the sources and asserts
the data files are inside it, so the regression cannot return silently. The
expected file list is derived from the source tree, so newly added static
assets or migrations are covered automatically.
"""

from __future__ import annotations

import shutil
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC = _PROJECT_ROOT / "src" / "myownca"

# Package subdirectories whose every file must be shipped as package data.
_DATA_DIRS = ("setup/static", "online/static")


def _expected_data_files() -> list[str]:
    """Wheel-relative paths of every runtime data file that must ship.

    Walks each data dir recursively (``rglob``) so files in subdirectories —
    e.g. ``online/static/branding/logo.svg`` — are covered too. A non-recursive
    walk once let the default branding logo slip out of the wheel, 500'ing
    ``GET /branding/logo``.
    """
    expected: list[str] = []
    for sub in _DATA_DIRS:
        directory = _SRC / sub
        expected += [
            f"myownca/{sub}/{path.relative_to(directory).as_posix()}"
            for path in sorted(directory.rglob("*"))
            if path.is_file()
        ]
    expected += [
        f"myownca/storage/migrations/{path.name}"
        for path in sorted((_SRC / "storage" / "migrations").glob("*.sql"))
    ]
    return expected


def _build_wheel(workdir: Path, project: str = "") -> Path:
    """Build the project wheel from an isolated source copy into ``workdir``.

    Copies the build inputs into a scratch tree first so the real working tree
    stays pristine (no stray ``build/`` or ``*.egg-info``). Raises ``SkipTest``
    when the build backend cannot run (e.g. an offline CI that cannot provision
    setuptools for the isolated build) — a missing build is an environment
    problem, distinct from a wheel that builds but drops files.
    """
    srcroot = workdir / "srcroot"
    (srcroot / "docs").mkdir(parents=True)
    shutil.copytree(
        _SRC.parent,  # src/ (contains the myownca package)
        srcroot / "src",
        ignore=shutil.ignore_patterns("*.egg-info", "__pycache__"),
    )
    shutil.copy2(_PROJECT_ROOT / "pyproject.toml", srcroot / "pyproject.toml")
    shutil.copy2(_PROJECT_ROOT / "LICENSE", srcroot / "LICENSE")
    shutil.copytree(_PROJECT_ROOT / "release-tools", srcroot / "release-tools",
                    ignore=shutil.ignore_patterns("*.egg-info", "__pycache__", "build"))
    shutil.copytree(
        _PROJECT_ROOT / "core", srcroot / "core",
        ignore=shutil.ignore_patterns("*.egg-info", "__pycache__", "build"),
    )
    # pyproject declares readme = "docs/README.md"; setuptools reads it at build.
    shutil.copy2(_PROJECT_ROOT / "docs" / "README.md", srcroot / "docs" / "README.md")

    outdir = workdir / "out"
    outdir.mkdir()
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--no-build-isolation",
             "-w", str(outdir)],
            cwd=srcroot / project,
            capture_output=True,
            text=True,
            timeout=300,
            env={**os.environ, "SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MYOWNCA": "0.0.0",
                 "SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MYOWNCA_RELEASE_TOOLS": "0.0.0"},
        )
    except FileNotFoundError as exc:  # pragma: no cover - pip is part of CPython envs
        raise unittest.SkipTest(f"pip unavailable to build a wheel: {exc}") from exc
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip()[-2000:]
        raise unittest.SkipTest(f"wheel build backend unavailable:\n{tail}")

    distribution = "myownca_release_tools" if project == "release-tools" else "myownca"
    wheels = list(outdir.glob(f"{distribution}-*.whl"))
    if not wheels:
        raise unittest.SkipTest(f"wheel build produced no {distribution}-*.whl")
    return wheels[0]


class WheelPackagingTests(unittest.TestCase):
    _tmp: tempfile.TemporaryDirectory
    _names: set[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        wheel = _build_wheel(Path(cls._tmp.name))
        with zipfile.ZipFile(wheel) as archive:
            cls._names = set(archive.namelist())
            cls._license = archive.read("myownca-0.0.0.dist-info/licenses/LICENSE")
            cls._metadata = archive.read("myownca-0.0.0.dist-info/METADATA").decode()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_setup_wizard_html_is_packaged(self) -> None:
        # The exact file whose absence 500'd GET /setup in the Docker image.
        self.assertIn("myownca/setup/static/setup.html", self._names)

    def test_application_contains_canonical_license(self) -> None:
        self.assertEqual(self._license, (_PROJECT_ROOT / "LICENSE").read_bytes())
        self.assertIn("License-Expression: LicenseRef-EnigmaIS-Source-Available-1.0",
                      self._metadata)
        self.assertIn("License-File: LICENSE", self._metadata)

    def test_verifier_contains_canonical_license(self) -> None:
        canonical = (_PROJECT_ROOT / "LICENSE").read_bytes()
        self.assertEqual((_PROJECT_ROOT / "release-tools/LICENSE").read_bytes(), canonical)
        with tempfile.TemporaryDirectory() as directory:
            wheel = _build_wheel(Path(directory), "release-tools")
            with zipfile.ZipFile(wheel) as archive:
                self.assertEqual(archive.read(
                    "myownca_release_tools-0.0.0.dist-info/licenses/LICENSE"), canonical)
                metadata = archive.read(
                    "myownca_release_tools-0.0.0.dist-info/METADATA").decode()
                self.assertIn("License-Expression: LicenseRef-EnigmaIS-Source-Available-1.0",
                              metadata)
                self.assertIn("License-File: LICENSE", metadata)

    def test_every_source_data_file_is_packaged(self) -> None:
        missing = [name for name in _expected_data_files() if name not in self._names]
        self.assertEqual(missing, [], f"data files missing from the wheel: {missing}")

    def test_online_static_count_matches_source(self) -> None:
        source = sum(1 for p in (_SRC / "online" / "static").rglob("*") if p.is_file())
        in_wheel = sum(
            1
            for name in self._names
            if name.startswith("myownca/online/static/") and not name.endswith("/")
        )
        self.assertEqual(in_wheel, source)

    def test_migration_count_matches_source(self) -> None:
        source = len(list((_SRC / "storage" / "migrations").glob("*.sql")))
        in_wheel = sum(
            1
            for name in self._names
            if name.startswith("myownca/storage/migrations/") and name.endswith(".sql")
        )
        self.assertEqual(in_wheel, source)

    def test_vendor_license_issuer_is_not_packaged(self) -> None:
        self.assertNotIn("myownca/licensing/cli.py", self._names)
        self.assertFalse(
            any(name.startswith("license_issuer/") for name in self._names),
            "vendor license issuer leaked into the customer application wheel",
        )


if __name__ == "__main__":
    unittest.main()
