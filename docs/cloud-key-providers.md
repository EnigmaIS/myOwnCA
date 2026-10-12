# Cloud signing keys

AWS KMS and Microsoft Azure Key Vault are bundled signing-key backends. They do
not replace the existing software keystore or local PKCS#11 support:

- `software` remains the default and needs no cloud account;
- `pkcs11` keeps the issuing sub-CA on the local token;
- `aws_kms` and `azure_key_vault` keep the issuing sub-CA private key in the
  selected cloud provider;
- the root CA remains offline in every production configuration;
- holder/device private keys keep their existing lifecycle and are not moved to
  the cloud.

Only one cloud provider can be active for an installation. Changing from AWS to
Azure (or the reverse) is a migration/rotation ceremony, not a hot failover.
There is no automatic fallback to a local key when cloud signing fails.

## Installation

All provider adapters and SDKs are installed with the main distribution:

```bash
pip install .
```

The Docker image includes the same complete set; changing the selected provider
does not require rebuilding the image. The `aws-kms`, `azure-key-vault`, and
`cloud` extras are retained as empty compatibility aliases for older commands.

## First-run setup

Choose **Local software**, **PKCS#11**, **AWS KMS**, or **Azure Key Vault** in
the setup wizard. Cloud-specific fields appear only for a cloud choice. The
wizard tests provider access and provisions or attaches the first issuing key
before it finalizes the installation. An existing provider key is selected under
**Issuing CA / Sub CA → Use existing HSM/cloud key** and activated with its
Root-signed Sub CA certificate.

The non-secret configuration is written to `config.toml`. Static provider
credentials are written only to `secrets/secrets.env` (mode `0600` in a
mode-`0700` directory):

| Provider | Non-secret configuration | Secret configuration |
| --- | --- | --- |
| AWS | `MYOWNCA_AWS_REGION` | `MYOWNCA_AWS_ACCESS_KEY_ID`, `MYOWNCA_AWS_SECRET_ACCESS_KEY`, optional `MYOWNCA_AWS_SESSION_TOKEN` |
| Azure | `MYOWNCA_AZURE_VAULT_URL`, `MYOWNCA_AZURE_KEY_PROTECTION=standard\|hsm` | `MYOWNCA_AZURE_TENANT_ID`, `MYOWNCA_AZURE_CLIENT_ID`, `MYOWNCA_AZURE_CLIENT_SECRET` |

Rotate a credential by replacing its value in `secrets/secrets.env` (or an overriding
process environment variable) and restarting myOwnCA. The application does not
use AWS AssumeRole and does not refresh an AWS session token. If
`MYOWNCA_AWS_SESSION_TOKEN` is set, signing stops when that token expires; put a
fresh access-key/secret/token triplet in `secrets/secrets.env` and restart before its
expiry. Never combine a new token with an access-key pair from another session.

## Minimum provider permissions

Grant permissions to the application's dedicated identity, at the narrowest
account/region/vault scope that contains its signing keys.

### AWS KMS

Create a dedicated IAM identity for myOwnCA and create an access key for
application access. Record the access key ID and secret access key when AWS
shows them; the wizard stores them in `secrets/secrets.env`. Do not reuse a human
administrator's access key.

myOwnCA calls `CreateKey`, `ListKeys`, `DescribeKey`, `GetPublicKey`, `Sign`,
`ScheduleKeyDeletion`, `CancelKeyDeletion`, and `EnableKey`. Creating a managed
key with the `myownca:managed` and `myownca:label` tags also requires
`kms:TagResource`. It does not create aliases or generate data keys, so
`CreateAlias`, `ListAliases`, `GenerateDataKey`, and
`GenerateDataKeyWithoutPlaintext` are not required.

Use this policy while myOwnCA creates and manages signing keys. Replace
`YOUR_REGION` with the region entered in the setup wizard and
`YOUR_ACCOUNT_ID` with the 12-digit AWS account ID:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowListingKmsKeys",
      "Effect": "Allow",
      "Action": "kms:ListKeys",
      "Resource": "*"
    },
    {
      "Sid": "AllowCreatingTaggedKmsKeys",
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:TagResource"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestTag/myownca:managed": "true"
        },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": [
            "myownca:managed",
            "myownca:label"
          ]
        }
      }
    },
    {
      "Sid": "AllowManagedKmsKeyUseAndLifecycle",
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:Sign",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:EnableKey"
      ],
      "Resource": "arn:aws:kms:YOUR_REGION:YOUR_ACCOUNT_ID:key/*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/myownca:managed": "true"
        }
      }
    }
  ]
}
```

After all required cloud keys have been created, the identity can be reduced to
an exact-key policy. Replace all three placeholders. If the installation uses
more than one KMS signing key, make `Resource` an array of exact key ARNs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowListingKmsKeys",
      "Effect": "Allow",
      "Action": "kms:ListKeys",
      "Resource": "*"
    },
    {
      "Sid": "AllowUseOfSpecificKmsKey",
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:Sign",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:EnableKey"
      ],
      "Resource": "arn:aws:kms:YOUR_REGION:YOUR_ACCOUNT_ID:key/KEY_ID"
    }
  ]
}
```

This reduced policy intentionally prevents myOwnCA from creating another
cloud-backed service-certificate key. Restore the bootstrap create/tag statement
before creating another managed KMS key, then add the new exact key ARN to the
restricted policy.

For an attached key that myOwnCA does not manage, grant only `DescribeKey`,
`GetPublicKey`, and `Sign` on its exact ARN, in addition to `ListKeys` on `*`
for the setup connection check. The IAM policy is only one side of KMS
authorization: each attached key's key policy must also permit the application
principal.

AWS documents the complete
[KMS permissions reference](https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html),
[how to identify KMS keys in IAM policies](https://docs.aws.amazon.com/kms/latest/developerguide/cmks-in-iam-policies.html),
and the extra permission required for
[tags supplied to CreateKey](https://docs.aws.amazon.com/kms/latest/developerguide/tag-permissions.html).
An exact key ARN ends at `key/KEY_ID`; do not add `/*` after the key ID.

### Azure Key Vault

Prepare Azure before opening the cloud configuration in the wizard:

1. Create a resource group, unless the installation already has one.
2. Create a Key Vault with the **Azure role-based access control** permission
   model. The myOwnCA host must be able to reach the vault's data-plane endpoint;
   enable public access as needed for the deployment, or provide an allowed
   private/network path.
3. Copy the **Vault URI**, such as `https://example.vault.azure.net`.
4. In Microsoft Entra ID, create an application registration with the default
   settings. Copy the **Application (client) ID** and **Directory (tenant) ID**.
5. Under the app registration's **Certificates & secrets**, create a client
   secret. Copy its **Value** immediately. The secret ID is not the credential
   required by myOwnCA.
6. In the Key Vault, open **Access control (IAM)** and select
   **Add → Add role assignment**.
7. Select **Key Vault Crypto Officer**. Under **Members**, select
   **User, group, or service principal**, choose the app registration, then
   select **Review + assign**.
8. Paste the Vault URI, tenant ID, client ID, and secret value into the setup
   wizard and select **Check cloud configuration**. A new assignment can take a
   few minutes to become effective.

Use a Premium Key Vault when the wizard's default
**HSM-protected** key option is selected. A Standard Key Vault supports the
wizard's **Software-protected** option.

**Key Vault Crypto Officer** at vault scope is the recommended role when
myOwnCA creates, deletes, or recovers managed keys. **Key Vault Crypto User**
is sufficient for reading public key metadata and signing with attached keys,
but does not permit the managed lifecycle. A custom role limited to
`keys/read`, `keys/sign/action`, and the exact attached-key scope is another
option when the built-in Crypto User role is broader than policy allows.

Do not grant Key Vault secrets or certificate roles; myOwnCA uses only the keys
data plane. See Microsoft's
[Key Vault RBAC guide](https://learn.microsoft.com/azure/key-vault/general/rbac-guide),
[Key Vault authentication guide](https://learn.microsoft.com/azure/key-vault/general/authentication),
and [key protection overview](https://learn.microsoft.com/azure/key-vault/keys/about-keys).

## Key lifecycle

The first-run Issuing CA step supports both lifecycle models:

- **Create** — myOwnCA creates the key and records it as managed.
- **Attach** — enter an existing AWS key ARN or a versioned Azure key URL.
  myOwnCA validates that it is an enabled asymmetric signing key and records it
  as attached.

Supported key algorithms are RSA 2048/3072/4096 and ECDSA P-256/P-384/P-521.
ECDSA P-384 is the default for a new sub-CA.

Managed keys can be scheduled for deletion only after myOwnCA verifies that no
sub-CA, service certificate, or queued signing operation refers to them.
Attached keys are detached from myOwnCA only; they are never deleted in the
provider. AWS scheduled deletion and Azure soft-delete/recovery remain governed
by the provider's own retention policy. After **Finish setup**, the Root/Sub CA
chain is immutable and CA management exposes no key creation, attachment, or
replacement action.

Service certificates can select software, local PKCS#11, or the configured
cloud provider per certificate. For a cloud-backed service certificate the API
exports only the certificate and chain. Its private key is non-exportable, so
PKCS#12/private-key export and use as the portal's local TLS key are disabled.

## Failure handling

Cloud signing failures never trigger a software/PKCS#11 fallback. Signing work
is durably identified in the `signing_jobs` queue, uses leases and idempotency
keys, and distinguishes transient provider/transport errors from permanent
configuration or key errors. Transient work retries for at most 24 hours. A job
that has remained unsuccessful for 15 minutes is an operational alert; an
operator can retry or cancel it from the administrative API without exposing
provider credentials in job payloads or responses.

Back up the database and `secrets/secrets.env` even though cloud private keys
themselves are non-exportable. The database contains the provider key
references, ownership metadata, certificate state, and durable signing queue
needed to resume work.
