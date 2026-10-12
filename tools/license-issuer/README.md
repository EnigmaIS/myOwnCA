# myOwnCA license issuer

Vendor-only tooling for generating RSA-4096 PSS/SHA-256 signing keys and issuing
installation-bound myOwnCA license tokens. It is deliberately packaged and
built separately from the customer application.

Private keys and generated tokens are written directly to the directory from
which the wrapper is invoked. This works from any directory, including the
application checkout. Keep the encrypted production signing key outside the application checkout and
never copy it into either Docker image.

Direct `docker compose -f /absolute/path/to/compose.yaml run ...` calls behave
the same way: Compose mounts the caller's `$PWD` at `/work`.

Set the checkout path, then change to a private directory in which the signing
key and token should be created:

```bash
export MYOWNCA_HOME="/absolute/path/to/EnigmaIS"
export MYOWNCA_ISSUER="$MYOWNCA_HOME/tools/license-issuer/run"
export MYOWNCA_LICENSE_KEY_ID="local-lab-2026-01"
cd /path/where/files/should/be/created
```

## Generate the producer licensing key

Build the issuer image after updating its code:

```sh
docker compose -f "$MYOWNCA_HOME/tools/license-issuer/compose.yaml" build issuer
```

Set `MYOWNCA_LICENSE_KEY_PASSWORD` interactively in the operator shell (do not
store it in customer configuration). Then generate an encrypted key in the
private directory selected above:

```sh
"$MYOWNCA_ISSUER" keygen --key-id "$MYOWNCA_LICENSE_KEY_ID" \
  --out license.pem --public-out license.public.b64
```

Use new filenames: the current issuer overwrites existing output files.
The issuer currently signs with encrypted PEM files; HSM/KMS signing would require
an additional integration. Keep the private key and its backup with the producer.
`--unsafe-unencrypted-dev` is only for disposable test keys.

## Embed the public key in a signed release

Public keys are immutable application data, not runtime settings. Create the
producer's public ring from the generated Base64 DER/SPKI public key:

```sh
python - license.public.b64 "$MYOWNCA_LICENSE_KEY_ID" > license-public-keys.json <<'PYKEY'
import json
import sys
from pathlib import Path
print(json.dumps({"schema": 1, "keys": {
    sys.argv[2]: Path(sys.argv[1]).read_text().strip()
}}))
PYKEY
```

For rotation, merge the new entry into the existing ring instead of replacing
still-supported keys. Supply this JSON to `myownca-release seal-wheel
--license-public-keys`, or to the local release workflow's `seal` command. The
release signature protects the ring. Customers receive it inside the application;
they never receive `license.pem`.

**Do not set `MYOWNCA_LICENSE_PUBLIC_KEYS`.** The setting has been removed and
causes startup failure, even when empty and even in development. Remove any old
occurrence from process environment, `config.toml`, and `secrets.env`.
Source development without a ring uses the free tier. For licence tests, use
disposable test fixtures or an isolated source checkout with a disposable public
ring at `src/myownca_release/license-public-keys.json`; never add private keys.

See [licensing](../../docs/licensing.md) and
[release publishing](../../docs/release-publishing.md) for the current trust model.

## Issue the installation-bound token

Copy the installation UUID from **Admin → License**. With the encrypted-key
password available to the issuer:

```sh
"$MYOWNCA_ISSUER" sign \
  --key license.pem --key-id "$MYOWNCA_LICENSE_KEY_ID" \
  --licensed-to "Customer company" \
  --installation-id "PASTE-ID-FROM-ADMIN-LICENSE" \
  --max-lineages 100 --days 365 --out customer.lic
unset MYOWNCA_LICENSE_KEY_PASSWORD
```

The customer uploads `customer.lic` through **Admin → License**. The licence
`key_id` must match an entry in the signed application's producer ring. A new
installation UUID requires reissuing the token; an upgrade preserving the database
does not. Changing the public ring requires a new signed application release.

## Company name shown in customer portals

For a customer licence, supply its company name with the required `--licensed-to`
argument, for example `--licensed-to "Acme Corporation Ltd"`. The value is embedded
in schema 2's `licensed_to` field and covered by the vendor signature. The customer
application displays that exact name beneath its branding logo for every logged-in
account role and for secure-link holders after OTP or certificate verification.

Names must contain 1–256 characters without leading or trailing whitespace.
Unicode and punctuation are supported; spelling and capitalization are preserved.
Names are rendered as plain text, and long names wrap without truncation.

To change a company name, issue a replacement token with the corrected
`--licensed-to` value and the customer's existing Installation ID, using the
intended capacity and validity options, then install it in **Admin → License**.
Editing an existing token's name invalidates its signature. Existing schema 2
tokens already support the display and do not need reissuing for the UI upgrade.

The name remains visible after expiry with an expiry label. A previously verified
cached name may remain visible with an availability warning when current licence
state cannot be verified or loaded. Status and warning fields belong to the
application's runtime API; the issuer does not add them to the signed payload.
After updating issuer tooling, rebuild its separate image as described above.

## Encrypted signing keys

For an encrypted PEM, omit `--unsafe-unencrypted-dev` and export
`MYOWNCA_LICENSE_KEY_PASSWORD` before running the wrapper.
