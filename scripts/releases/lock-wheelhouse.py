#!/usr/bin/env python3
"""Create an offline hash lock from the exact dependency wheels to be signed."""

import argparse
import hashlib
import re
import zipfile
from email.parser import BytesParser
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    requirements = {}
    for path in sorted(args.bundle.glob("*.whl")):
        with zipfile.ZipFile(path) as archive:
            names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(names) != 1:
                parser.error(f"invalid wheel metadata: {path.name}")
            metadata = BytesParser().parsebytes(archive.read(names[0]))
        name, version = metadata["Name"], metadata["Version"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name or ""):
            parser.error("invalid dependency name")
        if not re.fullmatch(r"[A-Za-z0-9.+!_-]+", version or ""):
            parser.error("invalid dependency version")
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized == "myownca":
            continue
        if normalized in requirements and requirements[normalized][0] != version:
            parser.error(f"multiple versions of {name}")
        hashes = requirements.setdefault(normalized, (version, []))[1]
        with path.open("rb") as stream:
            hashes.append(hashlib.file_digest(stream, "sha256").hexdigest())
    if "cryptography" not in requirements:
        parser.error("wheelhouse is missing cryptography")
    output = "# Exact offline dependency wheels included in this release bundle.\n"
    for name, (version, hashes) in sorted(requirements.items()):
        output += f"{name}=={version}" + "".join(f" --hash=sha256:{h}" for h in hashes) + "\n"
    path = args.bundle / "requirements.lock"
    with path.open("x") as stream:
        stream.write(output)
    print(path)


if __name__ == "__main__":
    main()
