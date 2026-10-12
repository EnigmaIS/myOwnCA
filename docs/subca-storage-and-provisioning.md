# Sub CA storage and provisioning maps

These diagrams summarize where the Issuing Sub CA signing key can live and
which provisioning technique applies to each setup choice.

## 1. Storage topology

```mermaid
flowchart LR
    Root[Offline Root CA certificate]
    SubCA[Issuing Sub CA signer]
    Leaves[Leaf certificates]

    Software[Local Software keys]
    PKCS11[Smartcard / HSM<br/>PKCS#11]
    Cloud[AWS KMS or Azure Key Vault]

    Software --> SubCA
    PKCS11 --> SubCA
    Cloud --> SubCA
    Root -->|signs Sub CA certificate| SubCA
    SubCA -->|signs| Leaves
    Leaves -. private keys stay with requester or encrypted locally .-> Leaves
```

The storage choice applies to the Sub CA signing key. Leaf private keys are not
stored in the HSM or cloud backend.

## 2. New HSM

```mermaid
flowchart TD
    Start[Select Smartcard / HSM] --> New[New HSM]
    New --> Init[Initialize token]
    Init --> Choice{DKEK migration?}
    Choice -->|No| Key[Create new Sub CA key]
    Choice -->|Yes| Shares[Create N-of-N DKEK shares]
    Shares --> Key
    Key --> CSR[Create CSR]
    CSR --> Root[Offline Root signs CSR]
    Root --> Activate[Paste certificate and activate]
```

## 3. Existing prepared HSM

```mermaid
flowchart TD
    Start[Select Smartcard / HSM] --> Existing[Existing prepared HSM]
    Existing --> Probe[Probe and adopt token]
    Probe --> Technique{Sub CA technique}
    Technique -->|Use existing key| ExistingKey[Import existing Sub CA certificate]
    Technique -->|Create another key| NewKey[Create new key + offline ceremony]
    Technique -->|Use backup| Wrapped[Restore Sub CA key from wrapped backup]
    ExistingKey --> Active[Verify certificate and activate]
    NewKey --> CSR[Create CSR, sign offline, activate]
    Wrapped --> Active
    CSR --> Active
```

## 4. Recover HSM from existing DKEKs

```mermaid
flowchart TD
    Start[Select Smartcard / HSM] --> Recovery[Recover HSM from existing DKEKs]
    Recovery --> Init[Initialize target token]
    Init --> Import[Import every existing DKEK share]
    Import --> Verify[Verify complete DKEK state and KCV]
    Verify --> Backup[Restore Sub CA key from wrapped backup]
    Backup --> Match[Match restored public key to Sub CA certificate]
    Match --> Activate[Activate recovered Sub CA]
```

The recovery path restores the existing Sub CA identity; it does not create a
replacement Sub CA key.

## 5. Provisioning technique map

```mermaid
flowchart LR
    Backend{Selected key backend}
    Backend --> Software[Software keys]
    Backend --> NewHSM[New HSM]
    Backend --> ExistingHSM[Existing prepared HSM]
    Backend --> RecoverHSM[Recover HSM from existing DKEKs]
    Backend --> Cloud[Cloud key storage]

    Software --> S1[Import P12 or PEM]
    Software --> S2[Create new key + offline ceremony]

    NewHSM --> P1[Create new Sub CA key]
    ExistingHSM --> P2[Import existing Sub CA certificate]
    ExistingHSM --> P3[Create new key + offline ceremony]
    ExistingHSM --> P4[Restore Sub CA key from wrapped backup]
    RecoverHSM --> P5[Initialize token and import DKEK shares]
    P5 --> P6[Restore Sub CA key from wrapped backup]

    Cloud --> C1[Create new KMS / Key Vault key]
    Cloud --> C2[Import existing Sub CA certificate and attach cloud key]

    S1 --> Active[Verify certificate and activate Sub CA]
    S2 --> Active
    P1 --> Active
    P2 --> Active
    P3 --> Active
    P4 --> Active
    P6 --> Active
    C1 --> Active
    C2 --> Active
```
