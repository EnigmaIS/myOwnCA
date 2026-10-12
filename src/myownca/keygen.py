"""Compatibility shim — keygen now lives in myownca-core."""
from myownca_core.keygen import (  # noqa: F401
    ENTROPY_SAMPLE_BYTES,
    CERTIFICATE_ALGORITHMS,
    EntropyError,
    EntropySource,
    KeygenError,
    SUPPORTED_ALGORITHMS,
    certificate_algorithm_for_public_key,
    feed_entropy,
    generate_private_key,
    resolve_entropy_source,
    validate_entropy_source,
)
