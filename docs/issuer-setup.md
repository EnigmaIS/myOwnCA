# First-run issuing CA provisioning

The first active issuing Sub CA is a mandatory part of the one-time setup. The
normal portal does not start until setup can prove that exactly one Sub CA is
active, that it chains directly to the selected Root CA, and that its private key
is accessible through the configured backend.

## Before the Issuing CA step

Complete and save the install type, database, HSM or cloud-key backend, service
addresses, and Root CA certificate. Production setup imports only the public Root
CA certificate; the Root private key remains offline. Saving or importing issuer
key material locks those foundation choices.

The setup URL is protected by its one-time token, a setup session, CSRF checks,
and a typed confirmation phrase for every provisioning mutation. Provisioning
audit events use the actor `bootstrap/setup`; passwords, PINs, and key material
are not written to the audit log.

## Provisioning choices

### Create a new key and use the offline Root CA

1. Choose **Create new key + offline ceremony**.
2. Select the subject, algorithm, and allowed leaf profiles. Type `CREATE SUBCA`.
3. Copy the displayed PEM CSR. On the offline Root machine, save it as
   `sub.csr` and use the OpenSSL signing command in the
   [offline Root ceremony guide](offline-root.md#sign-the-issuing-sub-ca-csr).
   The offline signer controls certificate validity and any name constraints.
4. Paste the resulting PEM Sub CA certificate into the same setup step and type
   `ACTIVATE SUBCA`.

The pending CSR and key reference live in the target state directory. Restarting
setup displays the same CSR instead of creating another key.

### Create a CSR with a key from an existing prepared HSM

Use this path after **Existing prepared HSM** was probed and adopted in the
key-storage step.

1. Open the offline ceremony option, which is shown as **Use adopted HSM key +
   offline ceremony** for an adopted token.
2. Select one of the live keys in the dropdown. Its algorithm is derived from
   the HSM rather than supplied by the browser.
3. Enter the subject, allowed leaf profiles, and User PIN, then create the CSR.
4. Sign and import the certificate using the same offline Root procedure as for
   a new key.

The selected key is recorded as attached. No new HSM key is generated, and
resetting an unfinished setup removes only the local binding.

### Import an already-certified PKCS#11, AWS KMS, or Azure Key Vault key

Use this path when the Sub CA private key already exists in the selected backend
and already has its Root-signed Sub CA certificate.

1. Choose **Import existing Sub CA certificate**.
2. Enter the PKCS#11 label, AWS KMS key ARN, or versioned Azure Key Vault URL.
3. Upload the Sub CA certificate and select its expected algorithm and allowed
   leaf profiles.
4. Run **Analyze**, verify the subject, Root fingerprint, certificate
   fingerprint, validity, backend, and algorithm, then type
   `IMPORT EXISTING SUBCA` and activate it.

The certificate must match the live provider key. myOwnCA records this key as
attached: resetting an unfinished setup only removes the local binding and never
deletes the provider key.

### Import an existing P12/PFX or PEM Sub CA

Use this path with Software HSM or PKCS#11 when the private key is available for
import.

1. Choose **Import P12 or PEM**.
2. Upload a P12/PFX or combined PEM. If the certificate and key are in separate
   PEM files, upload the private-key PEM separately.
3. Enter the bundle/key password when encrypted, a destination key label, the
   PKCS#11 User PIN when applicable, and at least one allowed profile.
4. Run **Analyze**, review the result, then type `IMPORT SUBCA KEY` and activate.

The Root certificate is taken from the earlier setup step. It is not requested
again. A Root certificate included in the bundle is accepted only if its SHA-256
fingerprint is identical to the configured Root.

### Restore a SmartCard-HSM key with DKEK

Prepare or adopt the HSM in the earlier key-storage step first. DKEK is N-of-N:
import every share there with its distinct password and confirm the resulting
KCV. The Issuing CA step never asks for the shares or their passwords again.
In **Restore SmartCard-HSM key**, upload the native OpenSC raw wrapped-key bundle,
provide a free target reference in `1..255`, Sub CA certificate, and User PIN.
Analyze the native wrapped-key input, then type `RESTORE SUBCA KEY`.

Setup verifies the live token against the readiness marker and KCV, unwraps
without overwriting an existing key reference, proves the restored private key
matches the certificate, and only then activates the issuer.

For native `.bin` export, HSM replacement, DKEK separation, and the destructive
two-token acceptance procedure, follow the
[SmartCard-HSM DKEK backup and recovery runbook](hsm-dkek-recovery.md).

### Automatic Test/Lab CA

For Test/Lab with Software HSM, choose **Test/Lab — create local CA**, type
`CREATE LAB CA`, and confirm. Setup persists a throwaway local Root CA and one
active Sub CA. Do not use this path for certificates that need production trust.

## Validation applied to every import

Activation is mandatory. Setup rejects a second issuer and enforces:

- a live private key matching the Sub CA certificate;
- a direct signature by the configured, currently valid Root CA;
- a currently valid Sub CA certificate;
- a Sub CA validity interval entirely within the Root CA validity: its start
  must be no earlier than the Root's start, and its expiry no later than the
  Root's expiry; equality at either boundary is accepted;
- supported RSA 2048/3072/4096 or NIST ECDSA P-256/P-384/P-521 keys;
- `BasicConstraints: CA=true, pathLength=0` for a new Sub CA created from a
  myOwnCA CSR;
- `KeyUsage` containing `keyCertSign` and `cRLSign`;
- at least one non-duplicated allowed leaf profile;
- bounded pasted-certificate size.

Analysis, activation, and final setup completion all enforce these validity
bounds. An out-of-bounds certificate is rejected with the relevant timestamps;
its dates are never adjusted. Obtain a corrected Sub CA certificate from the
offline Root signer and retry. A rejected CSR response preserves the pending
request and its key. This check also applies to imports of existing issuers,
including legacy certificates without `pathLength`.

For compatibility with an established issuer, an existing-key, P12/PEM, or DKEK
import may omit `pathLength` entirely. The dry run shows a compatibility warning
and the activation audit event records it. A positive `pathLength` is always
rejected; a newly created Sub CA must still have `pathLength=0`.

## Reset and completion

Before **Finish setup**, **Reset issuer step** with the phrase `RESET ISSUER`
removes the pending/active bootstrap record and unlocks the foundation fields.
Keys created or imported by myOwnCA are synchronously deleted (or setup remains
locked if safe cleanup cannot complete). Existing HSM/cloud keys are detached
only. Reset is refused once setup is complete.

Finalization preserves the secrets already generated for the provisioning
context. It refuses to write the completion marker if the issuer count, pending
state, Root chain, backend, or live key check is wrong. The completion marker is
the final operation.

After launch, **CA management** is read-only for the Root/Sub CA chain. It still
provides issuer health and metadata plus CRL, OCSP, AIA, and service-URL
configuration. If an older Production installation has a completion marker but
no active Sub CA, the launcher opens a restricted setup-completion mode with a
new one-time token instead of starting the normal portal.
