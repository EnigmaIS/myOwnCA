from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Http01InfraTests(unittest.TestCase):
    def test_nginx_serves_acme_challenge_on_port_80(self) -> None:
        nginx = (ROOT / "nginx.conf").read_text()
        self.assertIn("listen 80;", nginx)
        self.assertIn("location /.well-known/acme-challenge/", nginx)
        # Everything else on :80 must redirect to https.
        self.assertIn("return 301 https://$host$request_uri;", nginx)

    def test_nginx_serves_crl_on_port_80_read_only(self) -> None:
        nginx = (ROOT / "nginx.conf").read_text()
        self.assertIn("location /crl/", nginx)
        # CRLs are read-only; non-GET methods are rejected at the edge.
        self.assertIn("limit_except GET", nginx)

    def test_compose_exposes_port_80(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertIn('"80:80"', compose)


if __name__ == "__main__":
    unittest.main()
