"""Pure policy helpers for the public access-request gate.

No DB, no app state — fully unit-tested. The web layer reads the two settings
(`access_request_enabled`, `access_request_allowed_domains`) and feeds them here.
"""

from __future__ import annotations

import re

# A DNS label: alphanumeric, internal hyphens allowed, 1-63 chars.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")


def normalize_domains(raw: str) -> list[str]:
    """Parse the admin textarea into a canonical, validated domain list.

    Accepts commas, whitespace, and newlines as separators. Each token is
    lowercased and trimmed, with a leading '@' stripped. A single leading '*.'
    wildcard is allowed (see ``email_allowed``). Raises ValueError on a malformed
    entry. De-duplicates, preserving first-seen order.
    """
    seen: list[str] = []
    for token in re.split(r"[,\s]+", raw or ""):
        token = token.strip().lower()
        if not token:
            continue
        if token.startswith("@"):
            token = token[1:]
        domain = token[2:] if token.startswith("*.") else token
        if not _DOMAIN_RE.match(domain):
            raise ValueError(f"invalid domain: {token}")
        if token not in seen:
            seen.append(token)
    return seen


def domain_of(email: str) -> str | None:
    """The lowercased domain part of ``email`` (after the last '@'), or None."""
    email = (email or "").strip().lower()
    if "@" not in email:
        return None
    return email.rsplit("@", 1)[1] or None


def email_allowed(email: str, allowed_domains: list[str]) -> bool:
    """True iff ``email``'s domain matches an allow-list entry.

    Exact entry -> domain must equal it. ``*.example.com`` -> domain must end with
    ``.example.com`` (at least one extra label), so it matches subdomains but not
    the apex and not a look-alike like ``evil-example.com``.
    """
    domain = domain_of(email)
    if domain is None:
        return False
    for entry in allowed_domains:
        if entry.startswith("*."):
            suffix = entry[1:]  # ".example.com"
            if domain.endswith(suffix) and len(domain) > len(suffix):
                return True
        elif domain == entry:
            return True
    return False


def is_request_allowed(enabled: bool, allowed_domains: list[str], email: str) -> bool:
    """Top-level gate: enabled AND a non-empty allow-list AND the email matches."""
    return enabled and bool(allowed_domains) and email_allowed(email, allowed_domains)
