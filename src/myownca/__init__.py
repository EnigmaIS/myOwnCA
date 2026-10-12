"""myOwnCA shared package."""

from importlib.metadata import PackageNotFoundError, version

from myownca_release.bootstrap import require_verified

require_verified()

try:
    __version__ = version("myownca")
except PackageNotFoundError:  # pragma: no cover - source checkout without a build
    __version__ = "0+unknown"
