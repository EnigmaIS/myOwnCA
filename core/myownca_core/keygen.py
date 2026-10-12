"""Private-key generation shared by every software key producer.

Centralises the algorithm catalogue (previously duplicated in the software HSM
and the service-cert keystore) and adds optional mixing from an external
entropy device (``/dev/trng``, ``/dev/hwrng``, ...) before each generation.

The mixing is strictly additive: bytes read from the device are stirred into
the kernel pool (and, best-effort, OpenSSL's DRBG) with zero entropy credit,
so a weak or malicious device can never make key generation worse than the OS
CSPRNG alone. When a device is configured but unusable, generation fails
closed instead of silently falling back.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import select
import stat
import time
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes


class KeygenError(ValueError):
    """Unsupported algorithm or failed key generation."""


class EntropyError(KeygenError):
    """The configured external entropy source could not be used."""


_GENERATORS: dict[str, Callable[[], CertificateIssuerPrivateKeyTypes]] = {
    "rsa-2048": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "rsa-3072": lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072),
    "rsa-4096": lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096),
    "ecdsa-p256": lambda: ec.generate_private_key(ec.SECP256R1()),
    "ecdsa-p384": lambda: ec.generate_private_key(ec.SECP384R1()),
    "ecdsa-p521": lambda: ec.generate_private_key(ec.SECP521R1()),
}

SUPPORTED_ALGORITHMS: tuple[str, ...] = tuple(_GENERATORS)
CERTIFICATE_ALGORITHMS: tuple[str, ...] = (
    "rsa-2048",
    "rsa-3072",
    "rsa-4096",
    "ecdsa-p256",
    "ecdsa-p384",
    "ecdsa-p521",
)

ENTROPY_SAMPLE_BYTES = 64
_READ_TIMEOUT_SECONDS = 2.0

EntropySource = str | Callable[[], "str | None"] | None


def resolve_entropy_source(source: EntropySource) -> str | None:
    """Allow callers to hand over either a path or a runtime-config getter."""
    return source() if callable(source) else source


def generate_private_key(
    algorithm: str, *, entropy_source: EntropySource = None
) -> CertificateIssuerPrivateKeyTypes:
    """Generate a key, mixing external entropy first when one is configured.

    Raises :class:`KeygenError` for unknown algorithms and
    :class:`EntropyError` (fail-closed) when a configured source is unusable.
    """
    generator = _GENERATORS.get(algorithm)
    if generator is None:
        raise KeygenError(f"Unsupported key algorithm: {algorithm}")
    feed_entropy(resolve_entropy_source(entropy_source))
    return generator()


def certificate_algorithm_for_public_key(public_key) -> str:
    """Return the canonical issuable algorithm for ``public_key``.

    This is the complete product key catalogue; no unsupported key families are
    accepted by certificate validation.
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        algorithm = f"rsa-{public_key.key_size}"
        if public_key.public_numbers().e != 65537:
            algorithm = ""
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curves = {
            "secp256r1": "ecdsa-p256",
            "secp384r1": "ecdsa-p384",
            "secp521r1": "ecdsa-p521",
        }
        algorithm = curves.get(public_key.curve.name, "")
    else:
        algorithm = ""
    if algorithm not in CERTIFICATE_ALGORITHMS:
        raise KeygenError(
            f"Unsupported certificate key type or parameters: {type(public_key).__name__}"
        )
    return algorithm


def validate_entropy_source(source: str, *, timeout: float = _READ_TIMEOUT_SECONDS) -> None:
    """Raise :class:`EntropyError` unless the device yields plausible bytes.

    Checks readability, a full sample within the timeout, and that the output
    is not constant. This is a wiring check, not a statistical randomness test.
    """
    _read_entropy(source, timeout=timeout)


def feed_entropy(source: str | None) -> None:
    """Mix one sample from ``source`` into the system RNG state.

    The kernel pool is the primary sink: writing to ``/dev/urandom`` stirs the
    data into the input pool (without crediting entropy), which reseeds the
    CSPRNG every userspace DRBG chains from. OpenSSL's ``RAND_add`` is a
    secondary, best-effort sink — pip wheels of ``cryptography`` statically
    link their own OpenSSL, so the system libcrypto we can reach from ctypes
    is not always the instance that generates the key.
    """
    if not source:
        return
    data = _read_entropy(source)
    mixed = _mix_into_kernel(data)
    mixed = _mix_into_openssl(data) or mixed
    if not mixed:
        raise EntropyError(
            f"Read {len(data)} bytes from {source} but no RNG sink accepted them"
        )


def _read_entropy(source: str, *, timeout: float = _READ_TIMEOUT_SECONDS) -> bytes:
    try:
        fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as exc:
        raise EntropyError(
            f"Cannot open entropy source {source}: {exc.strerror or exc}"
        ) from exc
    try:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise EntropyError(f"Entropy source is a directory: {source}")
        data = bytearray()
        deadline = time.monotonic() + timeout
        while len(data) < ENTROPY_SAMPLE_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise EntropyError(
                    f"Entropy source produced {len(data)}/{ENTROPY_SAMPLE_BYTES} bytes "
                    f"within {timeout:.1f}s: {source}"
                )
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                continue
            try:
                chunk = os.read(fd, ENTROPY_SAMPLE_BYTES - len(data))
            except BlockingIOError:
                continue
            except OSError as exc:
                raise EntropyError(
                    f"Error reading entropy source {source}: {exc.strerror or exc}"
                ) from exc
            if not chunk:
                raise EntropyError(
                    f"Entropy source ended after {len(data)}/{ENTROPY_SAMPLE_BYTES} "
                    f"bytes: {source}"
                )
            data.extend(chunk)
    finally:
        os.close(fd)
    if len(set(data)) <= 1:
        raise EntropyError(f"Entropy source produced constant output: {source}")
    return bytes(data)


def _mix_into_kernel(data: bytes) -> bool:
    try:
        with open("/dev/urandom", "wb", buffering=0) as pool:
            pool.write(data)
        return True
    except OSError:
        return False


_libcrypto_cache: ctypes.CDLL | None = None
_libcrypto_resolved = False


def _libcrypto() -> ctypes.CDLL | None:
    global _libcrypto_cache, _libcrypto_resolved
    if _libcrypto_resolved:
        return _libcrypto_cache
    _libcrypto_resolved = True
    name = ctypes.util.find_library("crypto")
    if name is None:
        return None
    try:
        lib = ctypes.CDLL(name)
        lib.RAND_add.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_double]
        lib.RAND_add.restype = None
    except (OSError, AttributeError):
        return None
    _libcrypto_cache = lib
    return lib


def _mix_into_openssl(data: bytes) -> bool:
    lib = _libcrypto()
    if lib is None:
        return False
    try:
        # Zero entropy credit: stir the bytes in without claiming randomness.
        lib.RAND_add(data, len(data), 0.0)
        return True
    except (OSError, ctypes.ArgumentError):
        return False
