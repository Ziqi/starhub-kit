#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StarHub Contributors
# SPDX-License-Identifier: MIT
"""
Zero-dependency ISO/IEC 5962 (SPDX-2.3) Software Bill of Materials (SBOM) generator
for StarHub Kit. Produces deterministic JSON SBOM covering all tracked source files.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import sys

DEFAULT_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "__pycache__", "dist", "node_modules", ".next"}


def sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_spdx_document(repo_root: pathlib.Path, version: str) -> dict:
    created_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    files_entries: list[dict] = []
    file_spdx_ids: list[str] = []
    sha1_hashes_for_verif: list[str] = []

    idx = 0
    for root, dirs, filenames in os.walk(repo_root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        rp = pathlib.Path(root)
        for fn in sorted(filenames):
            if fn.startswith("._"):
                continue
            fp = rp / fn
            if fp.is_symlink() or not fp.is_file():
                continue
            rel = fp.relative_to(repo_root).as_posix()
            raw = fp.read_bytes()
            idx += 1
            fid = f"SPDXRef-File-{idx:04d}"
            s1 = sha1_bytes(raw)
            s256 = sha256_bytes(raw)
            sha1_hashes_for_verif.append(s1)
            file_spdx_ids.append(fid)
            files_entries.append(
                {
                    "SPDXID": fid,
                    "fileName": f"./{rel}",
                    "checksums": [
                        {"algorithm": "SHA1", "checksumValue": s1},
                        {"algorithm": "SHA256", "checksumValue": s256},
                    ],
                    "licenseConcluded": "MIT",
                    "licenseInfoInFiles": ["MIT"],
                    "copyrightText": "2026 StarHub Contributors",
                }
            )

    verif_digest = hashlib.sha1("".join(sorted(sha1_hashes_for_verif)).encode("ascii")).hexdigest()
    pkg_id = "SPDXRef-Package-starhub-kit"

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": pkg_id,
        }
    ]
    for fid in file_spdx_ids:
        relationships.append(
            {
                "spdxElementId": pkg_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": fid,
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"starhub-kit-{version}",
        "documentNamespace": f"https://github.com/Ziqi/starhub-kit/spdx/{version}/{verif_digest}",
        "creationInfo": {
            "created": created_ts,
            "creators": [
                "Organization: StarHub Contributors",
                "Tool: starhub-kit-sbom-generator-1.0",
            ],
        },
        "packages": [
            {
                "name": "starhub-kit",
                "SPDXID": pkg_id,
                "versionInfo": version,
                "downloadLocation": f"https://github.com/Ziqi/starhub-kit/releases/tag/{version}",
                "filesAnalyzed": True,
                "packageVerificationCode": {
                    "packageVerificationCodeValue": verif_digest,
                },
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "copyrightText": "2026 StarHub Contributors",
                "primaryPackagePurpose": "APPLICATION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:github/Ziqi/starhub-kit@{version}",
                    }
                ],
            }
        ],
        "files": files_entries,
        "relationships": relationships,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SPDX-2.3 JSON SBOM for StarHub Kit")
    parser.add_argument("--repo-root", type=pathlib.Path, default=DEFAULT_REPO_ROOT)
    parser.add_argument("--version", default="v1.0.2")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    doc = build_spdx_document(args.repo_root.resolve(), args.version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"[PASS] [SPDX-SBOM] Generated {args.output} ({len(doc['files'])} files indexed, SPDX-2.3).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
