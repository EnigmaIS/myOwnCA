from __future__ import annotations

import re
from pathlib import Path

MAX_LOGO_BYTES = 2_000_000
DEFAULT_ACCENT_COLOR = "#246b5b"
_TYPE_TO_EXT = {"image/png": ".png", "image/jpeg": ".jpg", "image/svg+xml": ".svg"}
_EXT_TO_TYPE = {ext: ctype for ctype, ext in _TYPE_TO_EXT.items()}
_HEX_COLOR_RE = re.compile(r"^#?([0-9a-fA-F]{6})$")


class BrandingError(Exception):
    """An uploaded logo was rejected."""


def normalize_theme_color(value: str) -> str:
    match = _HEX_COLOR_RE.fullmatch(value.strip())
    if match is None:
        raise BrandingError("Theme color must be a 6-digit hex color")
    return f"#{match.group(1).lower()}"


def theme_css_for_color(value: str) -> str:
    accent = normalize_theme_color(value)
    rgb = _hex_to_rgb(accent)
    accent_strong = _rgb_to_hex(_mix(rgb, (0, 0, 0), 0.32))
    accent_soft = _rgb_to_hex(_mix(rgb, (255, 255, 255), 0.86))
    hero_wash = _rgb_to_hex(_mix(rgb, (255, 255, 255), 0.92))
    code = _rgb_to_hex(_mix(rgb, (255, 255, 255), 0.90))
    contrast = "#172026" if _relative_luminance(rgb) > 0.58 else "#ffffff"
    return "\n".join(
        (
            ":root {",
            f"  --accent: {accent};",
            f"  --accent-strong: {accent_strong};",
            f"  --accent-soft: {accent_soft};",
            f"  --code: {code};",
            f"  --surface-soft: {code};",
            f"  --hero-wash: {hero_wash};",
            f"  --hero-wash-clear: rgba({rgb[0]}, {rgb[1]}, {rgb[2]}, 0);",
            f"  --focus-ring: rgba({rgb[0]}, {rgb[1]}, {rgb[2]}, 0.22);",
            f"  --accent-contrast: {contrast};",
            "}",
            "",
        )
    )


def _hex_to_rgb(value: str) -> tuple[int, int, int]:
    normalized = normalize_theme_color(value).lstrip("#")
    return (
        int(normalized[0:2], 16),
        int(normalized[2:4], 16),
        int(normalized[4:6], 16),
    )


def _rgb_to_hex(rgb: tuple[int, int, int]) -> str:
    return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"


def _mix(
    source: tuple[int, int, int], target: tuple[int, int, int], amount: float
) -> tuple[int, int, int]:
    return tuple(
        round(source_channel * (1 - amount) + target_channel * amount)
        for source_channel, target_channel in zip(source, target, strict=True)
    )


def _relative_luminance(rgb: tuple[int, int, int]) -> float:
    def channel(value: int) -> float:
        normalized = value / 255
        if normalized <= 0.03928:
            return normalized / 12.92
        return ((normalized + 0.055) / 1.055) ** 2.4

    red, green, blue = (channel(value) for value in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def sniff_content_type(declared: str, data: bytes) -> str:
    """Return ``declared`` if the bytes actually match it (and it's allowed), else raise.

    Does not trust the client-declared type: PNG/JPEG are checked by magic bytes,
    SVG by a leading ``<?xml``/``<svg`` (no XML parsing, so no XXE on untrusted input).
    """
    if declared not in _TYPE_TO_EXT:
        raise BrandingError(f"Unsupported logo type: {declared}")
    if len(data) > MAX_LOGO_BYTES:
        raise BrandingError("Logo is too large (max 2 MB)")
    if declared == "image/png":
        ok = data.startswith(b"\x89PNG\r\n\x1a\n")
    elif declared == "image/jpeg":
        ok = data.startswith(b"\xff\xd8\xff")
    else:  # image/svg+xml
        head = data[:512].lstrip().lstrip(b"\xef\xbb\xbf").lstrip().lower()
        ok = (
            head.startswith(b"<?xml") or head.startswith(b"<svg")
        ) and b"<svg" in data[:8192].lower()
    if not ok:
        raise BrandingError(f"File content does not match {declared}")
    return declared


def _branding_dir(state_dir: str | Path) -> Path:
    return Path(state_dir) / "branding"


def save_logo(state_dir: str | Path, content_type: str, data: bytes) -> None:
    content_type = sniff_content_type(content_type, data)
    directory = _branding_dir(state_dir)
    directory.mkdir(parents=True, exist_ok=True)
    for old in directory.glob("logo.*"):
        old.unlink()
    (directory / ("logo" + _TYPE_TO_EXT[content_type])).write_bytes(data)


def load_logo(state_dir: str | Path) -> tuple[bytes, str] | None:
    directory = _branding_dir(state_dir)
    for ext, content_type in _EXT_TO_TYPE.items():
        candidate = directory / ("logo" + ext)
        if candidate.is_file():
            return candidate.read_bytes(), content_type
    return None


def reset_logo(state_dir: str | Path) -> None:
    for old in _branding_dir(state_dir).glob("logo.*"):
        old.unlink()
