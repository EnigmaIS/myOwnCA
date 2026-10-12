# Offline Root ceremony

This guide uses the same OpenSSL commands displayed as helpers in the
Production setup wizard. The wizard accepts only the Root certificate and the
Root-signed Sub CA certificate; the Root private key must remain on the offline
host. An organization with an established external Root CA may use its approved
ceremony instead, provided it supplies equivalent Root and Sub CA certificates.

## Create the Root

On the offline host, generate an encrypted Root key:

```bash
openssl genpkey \
  -algorithm RSA \
  -aes-256-cbc \
  -pkeyopt rsa_keygen_bits:4096 \
  -out root-ca.key
```

Keep `root-ca.key` on the offline host. Create the self-signed Root
certificate:

```bash
openssl req -new -x509 \
  -key root-ca.key \
  -sha256 -days 3650 \
  -out root-ca.crt \
  -subj "/C=PL/O=Example Organization/CN=Example Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "authorityKeyIdentifier=keyid:always,issuer"
```

Import only `root-ca.crt` into the Production setup wizard on the online host.

## Sign the Issuing Sub CA CSR

In the wizard, select **Create new key + offline ceremony** and copy the PEM
CSR. Transfer it using your approved offline process as `sub.csr`, then sign
it on the offline host:

```bash
openssl x509 -req \
  -in sub.csr \
  -CA root-ca.crt \
  -CAkey root-ca.key \
  -out subca.crt \
  -days 1825 -sha256 \
  -copy_extensions copy
```

`-copy_extensions copy` preserves the required Sub CA
`BasicConstraints` and `KeyUsage` extensions from the CSR. The command creates
or advances `root-ca.srl`; retain it with the offline Root CA records.

Return `subca.crt` to the wizard and activate it. Setup verifies
the Root signature and the match to the locally held Issuing Sub CA key.

## Sign a Root CRL

The setup helpers do not provide a Root CRL command. Manage Root CRLs and any
Root/Sub CA incident procedure through the organization's approved offline Root
CA process.

## Lifecycle boundary

The online installation requires exactly one validated active Issuing Sub CA at
first-run completion. Once setup is complete, Root and Issuing Sub CA trust
material is read-only: the normal portal cannot add, replace, rotate, or retire
an issuer. Do not use this ceremony to plan an in-place issuing-CA rollover.

For the online setup validation and supported issuer-import alternatives, see
[Issuing CA provisioning](issuer-setup.md).
