from __future__ import annotations

import importlib.metadata
import tomllib
import unittest
from pathlib import Path

from myownca import __version__
from myownca_core import __version__ as core_version


REPO_ROOT = Path(__file__).resolve().parents[1]


class VersioningTests(unittest.TestCase):
    def test_runtime_version_uses_distribution_metadata(self) -> None:
        self.assertEqual(__version__, importlib.metadata.version("myownca"))
        self.assertEqual(core_version, importlib.metadata.version("myownca"))

    def test_both_packages_use_setuptools_scm_from_the_repository_tag(self) -> None:
        for project_path in (REPO_ROOT / "pyproject.toml", REPO_ROOT / "core/pyproject.toml"):
            with project_path.open("rb") as project_file:
                project = tomllib.load(project_file)

            self.assertNotIn("version", project["project"])
            self.assertIn("version", project["project"]["dynamic"])
            self.assertEqual(project["tool"]["setuptools_scm"]["tag"]["prefix"], "v")
            self.assertTrue(project["tool"]["setuptools_scm"]["tag"]["strict"])

        with (REPO_ROOT / "core/pyproject.toml").open("rb") as project_file:
            core_project = tomllib.load(project_file)
        self.assertEqual(core_project["tool"]["setuptools_scm"]["root"], "..")

    def test_main_distribution_bundles_the_shared_core_package(self) -> None:
        with (REPO_ROOT / "pyproject.toml").open("rb") as project_file:
            project = tomllib.load(project_file)

        package_find = project["tool"]["setuptools"]["packages"]["find"]
        self.assertEqual(package_find["where"], ["src", "core"])
        self.assertIn("myownca_core*", package_find["include"])

    def test_docker_build_mounts_scm_metadata_without_persisting_it(self) -> None:
        dockerfile = (REPO_ROOT / "Dockerfile").read_text()
        dockerignore = (REPO_ROOT / ".dockerignore").read_text().splitlines()

        self.assertEqual(dockerfile.count("\nFROM "), 1)
        self.assertIn(
            "RUN --mount=type=bind,source=.git,target=/opt/myownca/.git,readonly",
            dockerfile,
        )
        self.assertIn(
            "--mount=type=cache,target=/root/.cache/pip,sharing=locked",
            dockerfile,
        )
        self.assertIn("RUN apt-get update", dockerfile)
        self.assertLess(
            dockerfile.index("RUN apt-get update"),
            dockerfile.index("COPY pyproject.toml ./"),
        )
        self.assertIn("apt-get install --no-install-recommends -y git", dockerfile)
        self.assertIn("tomllib.load(open('pyproject.toml', 'rb'))", dockerfile)
        self.assertIn("config['project']['dependencies']", dockerfile)
        self.assertIn("pip install --no-deps --no-build-isolation -e .", dockerfile)
        self.assertIn("Signed production images use Dockerfile.release", dockerfile)
        self.assertLess(
            dockerfile.index("config['project']['dependencies']"),
            dockerfile.index("COPY src/ ./src/"),
        )
        self.assertNotIn("apt-get purge", dockerfile)
        self.assertNotIn("rm -rf /var/lib/apt/lists", dockerfile)
        self.assertNotIn("COPY .git", dockerfile)
        self.assertNotIn("COPY --from=", dockerfile)
        self.assertNotIn("pip install --no-cache-dir ./core", dockerfile)
        self.assertNotIn("--no-cache-dir", dockerfile)
        self.assertNotIn("PIP_NO_CACHE_DIR", dockerfile)
        self.assertNotIn(".git/", dockerignore)
        self.assertIn(".git/*", dockerignore)
        self.assertIn("!.git/objects/**", dockerignore)
        self.assertIn("!.git/refs/**", dockerignore)


if __name__ == "__main__":
    unittest.main()
