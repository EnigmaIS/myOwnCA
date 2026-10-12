# Application backup format v1

See [audit integrity](audit-integrity.md) for audit hash version coverage and the
fresh-database requirement. Audit rows are preserved exactly during restore;
the backup format does not upgrade older audit records.

An application backup is a `.myownca-backup` binary container. The unencrypted,
bounded header contains only the format version, fixed KDF parameters, two random
salts, chunk size, and random nonce prefix. It contains no installation metadata.

Each administrator share is independently processed with Argon2id using three
passes, 64 MiB, four lanes, a 128-bit salt, and a 256-bit result. HKDF-SHA-256
combines the two results into the archive key. The compressed ZIP byte stream is
split into 4 MiB chunks and protected with AES-256-GCM. Every chunk authenticates
the header digest, monotonically increasing chunk number, plaintext length, and
final-marker flag. Nonces are the random 64-bit prefix followed by the 32-bit
chunk number. Restore rejects missing, duplicated, reordered, oversized, or
trailing chunks.

The encrypted ZIP contains `manifest.json`, portable runtime config/secrets,
allow-listed local files, and one JSON Lines member per database table. The
manifest authenticates member paths, sizes and SHA-256 values and records the
exact application version and migration fingerprint. Restore accepts only safe,
unique paths and the exact release/schema, and enforces aggregate member limits
before applying data.
