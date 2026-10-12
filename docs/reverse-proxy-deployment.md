# Reverse-proxy deployment

For production-oriented deployments, run myOwnCA behind an operator-managed TLS
reverse proxy. The application can serve direct HTTPS, but a proxy provides the
network controls needed to isolate administrative access and publish CRL, OCSP,
and ACME endpoints deliberately.

The supplied Compose nginx configuration is a single-host reference. Docker can
run a Production installation, but this configuration does not by itself supply
high availability, independent portal network isolation, or an organization's
other production controls.

## Deployment contract

- Bind the online service to loopback or a private container network. Do not
  publish its normal service port directly to untrusted networks.
- Terminate TLS at the proxy, set `MYOWNCA_SESSION_COOKIE_SECURE=true`, and pass
  the original `Host`, client address chain, and `X-Forwarded-Proto: https`.
- Keep the first-run setup listener private. Remove the Compose loopback port
  mapping after setup, or remove the listener from the deployment boundary.
- Publish stable public URLs for CRL, AIA, and OCSP before issuing production
  certificates. Those values are embedded into subsequently issued certificates.
- Allow the ACME HTTP-01 path on port 80 when using external HTTP-01 issuance;
  redirect other HTTP traffic to HTTPS according to local policy.
- Set an upload limit large enough for certificate material and proxy timeouts
  long enough for synchronous ACME/DNS-01 work. The supplied nginx reference
  uses an 8 MiB request limit and 300-second upstream read/send timeouts.

The application exposes all role portals from one FastAPI process. Separate
Admin, Certificate Operator, Auditor, and holder hostnames or paths are useful
only when the proxy/network policy enforces the separation.

## Nginx baseline

Adapt the following to the organization's hostname, certificate paths, and
network topology. The upstream must not be reachable directly by clients.

```nginx
upstream myownca {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name ca.example.test;

    location /.well-known/acme-challenge/ {
        proxy_pass http://myownca;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name ca.example.test;
    ssl_certificate /etc/nginx/tls/ca.crt;
    ssl_certificate_key /etc/nginx/tls/ca.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 8m;

    location / {
        proxy_pass http://myownca;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 30s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
}
```

If CRL, AIA, or OCSP are published over HTTP, create explicit read-only proxy
locations for `/crl/`, `/aia/`, and `/ocsp`, as in the repository's
[`nginx.conf`](../nginx.conf). Do not expose the online service's setup port to
provide those endpoints.

## Portal isolation

Map the organization’s Admin, Certificate Operator, Auditor, and holder URLs in
the setup/service URL settings, then enforce access at the proxy or firewall.
At minimum, restrict the Admin and Certificate Operator portals to intended
administrative networks or identity-aware proxy policies. Do not assume that a
different web path alone isolates an administrative role.

Test login redirects and secure claim/renewal links through every configured
public hostname after a proxy change. Ensure that proxy logs do not retain
secret-bearing claim URLs longer than organizational policy permits.

## Optional holder mTLS forwarding

Holder mTLS proof is disabled until an administrator configures its proxy shared
secret. When enabled, the trusted proxy must remove client-supplied versions of
these headers and set both itself after client-certificate validation:

- `X-BB-Proxy-Auth`: the configured shared secret;
- `X-BB-Client-Cert`: the URL-escaped PEM client certificate.

For nginx, `$ssl_client_escaped_cert` is appropriate for the latter after a
successful `ssl_verify_client` policy. Never send these headers from an
untrusted intermediary and never allow direct client access to the upstream;
otherwise a client could attempt to forge the mTLS assertion.

## Change validation

After a proxy change, verify HTTPS login, `/health`, CRL/AIA/OCSP publication,
HTTP-01 when used, cookie `Secure` behavior, role-network restrictions, and
the absence of the setup listener from untrusted networks. Record the endpoint
and certificate changes in the operational record described in
[monitoring and operations](monitoring-and-operations.md).
