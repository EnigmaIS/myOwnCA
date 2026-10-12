# Audit record integrity

Audit hash format 2 requires a fresh database. This pre-launch change updates
the original audit table migration; databases that already applied that migration
must be reset separately. The application does not reset databases, rehash old
records, or support legacy or mixed-format chains. Previously unhashed fields
have no retroactive integrity protection.

Each new record stores `hash_version = 2`. Its authenticated payload is a JSON
object containing exactly these fields:

`hash_version`, `id`, `sequence`, `occurred_at`, `category`, `action`, `outcome`,
`actor_id`, `actor_email`, `actor_role`, `source_ip`, `object_type`, `object_id`,
`details_json`, and `prev_hash`.

Python's `json.dumps` serializes the object with `sort_keys=True`,
`separators=(",", ":")`, and `ensure_ascii=True`. Version and sequence are JSON
integers; nullable values remain JSON null, distinct from empty strings. The
timestamp and `details_json` are the exact stored strings, not parsed or
normalized during verification. The UTF-8 payload is authenticated with
HMAC-SHA256 using the existing key derivation:
`SHA256(UTF8("audit:" + MYOWNCA_AUTH_ENCRYPTION_SECRET))`.
`record_hash` is the lowercase hexadecimal HMAC and is not part of its own
payload. The first record uses 64 zero characters as `prev_hash`.

Verification checks the supported integer version, each record's HMAC, and its
link to the previous record. Unsupported versions fail verification at their
sequence without fallback. Event API responses and syslog messages include
`hash_version`; the verification response remains `ok` and `first_bad_sequence`.

This detects changes to authenticated fields and broken interior chain links
when the attacker cannot access the secret. It does not prevent database writes.
Deleting a suffix (including the entire chain) or restoring an older valid
database cannot be detected without an independently protected checkpoint or
audit copy. An attacker controlling both the database and secret can recompute
the chain. Best-effort syslog forwarding alone does not guarantee completeness.

Application backups preserve the stored fields, versions, and hashes. Restore
continues to require the exact application release and migration fingerprint,
verifies the restored chain with the archived secret, and appends a version 2
restore event. Older archives require their matching application release;
carrying their audit history into this fresh-database release is unsupported.
