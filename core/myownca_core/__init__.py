"""myownca-core — shared CA primitives (storage engine, key generation)."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Prefer the application distribution when this package is bundled there.
    __version__ = version("myownca")
except PackageNotFoundError:
    try:
        __version__ = version("myownca-core")
    except PackageNotFoundError:  # pragma: no cover - source checkout without a build
        __version__ = "0+unknown"
