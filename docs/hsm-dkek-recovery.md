# SmartCard-HSM DKEK backup and recovery runbook

This workflow applies to SmartCard-HSM and Nitrokey HSM devices managed through
OpenSC. It is destructive when a token is initialized. Never use a production
token as the recovery target unless its contents have been independently
inventoried. First-run setup can erase an initialized token only after a
User-PIN-authenticated probe displays its keys and the operator explicitly
confirms **Erase and initialize HSM**.

## Process isolation and live token state

myOwnCA never loads the configured PKCS#11 module into the long-running web
process. Token status, PIN verification, key inventory, key generation/import,
public-key reads, deletion, signing, and self-tests each run in a fresh worker
launched with the application's Python interpreter. The worker accepts one
structured request on standard input, returns one sanitized response, closes its
PKCS#11 session, and exits. User PINs are sent only in the worker's standard-input
request; they are not added to its command line or environment.

This boundary prevents OpenSC's process-local slot and object caches from
surviving between operations. A probe after token reinitialization, replacement,
or an external key change therefore reads the current hardware state without an
application restart. Certificate, CRL, and CSR structures are assembled in the
web process, but the live worker verifies that the token public key still matches
the structure before performing the private-key operation.

SmartCard-HSM initialization, DKEK share management, and wrapped-key operations
remain in `sc-hsm-tool`. These operations are vendor-specific and are not
portable PKCS#11 operations. `sc-hsm-tool` is already invoked once per operation
as a short-lived process, so placing another Python worker around it would not
improve provider-state isolation. PINs and share passwords are referenced through
the child process environment rather than included in command-line arguments.

## Recovery set

SmartCard-HSM DKEK is native **N-of-N**. Every distinct share is required; there
is no effective threshold setting below N. Generate every `.pbe` share with a
different password and keep at least two copies of each share in separate
locations.

Create the complete share set only during the **Setup** ceremony, before token
initialization. The Admin portal can inventory, download, import, and delete
server-side copies of existing shares, but it cannot create new ones.

Keep these items separate:

- DKEK shares;
- each share's password;
- native SmartCard-HSM `wrapped-key-<reference>.bin` files;
- SO-PIN and User PIN records;
- database and application-state backups.

The `.bin` files are the native output of OpenSC `sc-hsm-tool --wrap-key`.
See the [OpenSC `sc-hsm-tool` documentation](https://github.com/OpenSC/OpenSC/blob/master/doc/tools/sc-hsm-tool.1.xml)
for the corresponding `--unwrap-key` import operation.
myOwnCA does not add a manifest, signature, public-key sidecar, application
metadata, DKEK share, or password. The Admin whole-token download is only a
plain ZIP transport containing one untouched `.bin` per live token key. Extract
the files before restoring them individually in Setup. A `.bin` is usable on a
replacement SmartCard-HSM only when the target has the same DKEK; transfer and
import DKEK shares separately.

OpenSC exposes both a PKCS#11 object ID (`CKA_ID`) and the SmartCard-HSM's
native **Key ref**. They are different identifiers: the native key reference
is the value required by `sc-hsm-tool --wrap-key` and is the value used in the
transport ZIP filenames. myOwnCA resolves that native reference from the
PKCS#15 inventory rather than treating `CKA_ID` as the native reference.

## New HSM during setup

1. Select **Smartcard / HSM**, the OpenSC PKCS#11 module, token label, and the
   intended reader. Run **Probe local token**.
2. Choose **New HSM and new DKEK**.
3. Generate and download exactly N distinct `.pbe` files. Use a separate
   password for every file and make the redundant offline copies now.
4. Enter the current User PIN when the token is already initialized. If the
   probe finds keys, review their inventory and confirm the red **Erase and
   initialize HSM** action. Setup is the only initialization mechanism and
   cannot bypass this guard.
5. Enter the SO-PIN, new User PIN, reason, and exact phrase `INITIALIZE HSM`.
   Initialization erases and reinitializes the token in one OpenSC operation.
6. Re-upload all N shares and enter their passwords in the same file order.
   Import completes only when OpenSC reports no missing shares and a KCV.
7. Record the KCV in the ceremony record. Issuing CA provisioning remains
   blocked until the token serial and KCV match the setup readiness marker.

PINs, share passwords, and share bytes are never written to setup state,
configuration, the database, or audit details.

## Existing HSM during setup

1. Select the exact module, token label, and reader.
2. Probe with the User PIN and review initialization, PIN state, key inventory,
   DKEK share count, and KCV.
3. Choose **Existing prepared HSM** and adopt it.
4. In the Issuing CA step, choose the detected key from the dropdown and create
   the CSR. No new private key is generated.

Adoption verifies the PIN and requires a complete DKEK with a KCV. It never
calls token initialization. A later change to module, token label, or reader
invalidates readiness. Before issuer provisioning and final setup, myOwnCA also
compares the live token serial and KCV with the marker. The selected key is
registered as attached, so resetting setup removes only its local binding.

## Export native HSM backups

1. In **Admin → HSM & Keys**, verify that DKEK is complete and that the displayed
   KCV matches the ceremony record.
2. Choose **Request native HSM backup export** and type `REQUEST EXPORT ENTIRE HSM`.
   This creates a pending action; it does not generate the ZIP.
3. A different administrator opens **Admin → Privileged users → Pending admin
   proposals**, reviews the request, unlocks the token User PIN in their own
   session, and chooses **Approve & export**. Type `APPROVE EXPORT ENTIRE HSM`.
4. Move the returned ZIP to protected storage separate from the DKEK material,
   PIN records, and database backup.
5. If an external operator needs one key only, use the per-key raw `.bin`
   endpoint or extract the matching file from the transport ZIP.

The export includes every live token key, including keys not registered in the
myOwnCA lifecycle registry. If any live key lacks a valid SmartCard-HSM
reference or cannot be wrapped, the entire export fails and no partial archive
is returned.

## Recover onto a replacement HSM

1. Use a second dedicated empty token. Choose **Recovery HSM with existing DKEK
   shares** in setup.
2. Initialize it with the same N, then import all original shares with their
   individual passwords.
3. Stop if the resulting KCV differs from the source ceremony record.
4. Restore the application database/state backup that contains the original
   lifecycle registry and bindings.
5. Extract one `.bin` from the Admin transport ZIP, or obtain a native `.bin`
   directly from an external SmartCard-HSM operator.
6. In Setup, choose **Restore Sub CA key from wrapped backup**, provide the
   `.bin`, target reference, Sub CA certificate, and any required CRL material,
   then run the dry-run validation.
7. Confirm the restore. Setup calls OpenSC with `--force` disabled, rejects an
   occupied reference or label, verifies the restored public key against the
   supplied certificate, and rolls back the newly created key if validation or
   issuer activation fails.

Repeat the Setup operation for each extracted `.bin`. User accounts, lifecycle
bindings, database state, and issuer state remain application backups rather
than native HSM backup material.

## Destructive two-token hardware acceptance

The normal hardware suite never initializes a token. The full two-device
ceremony is separately gated because it erases both selected HSMs:

```text
MYOWNCA_HSM_TEST_DESTRUCTIVE_DKEK_RECOVERY=1
MYOWNCA_PKCS11_LIB=/path/to/opensc-pkcs11.so
MYOWNCA_HSM_TEST_SOURCE_READER=...
MYOWNCA_HSM_TEST_TARGET_READER=...
MYOWNCA_HSM_TEST_SOURCE_SO_PIN=...
MYOWNCA_HSM_TEST_TARGET_SO_PIN=...
MYOWNCA_HSM_TEST_SOURCE_PIN=...
MYOWNCA_HSM_TEST_TARGET_PIN=...
pytest -q tests/test_hsm_dkek_recovery_hardware.py
```

Run it only on two dedicated disposable HSMs. The reader selectors must differ.
