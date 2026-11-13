#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
StarHub Kit Fuzzing Harness (tests/fuzz_starhub_ctl.py)

Dual-mode fuzzer for OpenSSF Scorecard & Continuous Integration:
  1. Native Google Atheris mode (when `atheris` is installed and `--atheris` is passed).
  2. Zero-dependency deterministic & randomized property-based mutation mode
     (`python3 tests/fuzz_starhub_ctl.py --iterations 2000`) executed on every PR/push.

Targets:
  - scripts/starhub-ctl.py: JSON-compatible topology parser, dual-stack firewall
    compiler (`STARHUB-BOT-NOSSH` / `NOSSH6` TCP :22 hard-DROP invariants),
    Mihomo split-DNS & surgical QUIC renderer, and systemd Lifeline renderer.
  - scripts/starhub-doctor.py: Mihomo secret scrubber, Markdown slugifier, and
    Zero-PII regex detectors.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import pathlib
import random
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load_module(name: str, rel_path: str):
    target = REPO_ROOT / rel_path
    spec = importlib.util.spec_from_file_location(name, target)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {target}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CTL = _load_module("starhub_ctl", "scripts/starhub-ctl.py")
DOC = _load_module("starhub_doctor", "scripts/starhub-doctor.py")
BASE_GT = CTL.load_json_compatible(REPO_ROOT / "topology.example.json")

# Strictly RFC 5737 TEST-NET & RFC 3849 documentation prefixes only (Zero-PII safe)
SAFE_V4_POOL = [
    "192.0.2.10",
    "192.0.2.11",
    "192.0.2.22",
    "198.51.100.10",
    "198.51.100.42",
    "203.0.113.7",
    "203.0.113.88",
]
SAFE_V6_POOL = [
    "2001:db8::10",
    "2001:db8::22",
    "2001:db8:4a6::11",
    "2001:db8:cafe::99",
]


def fuzz_one_bytes(data: bytes) -> None:
    """Exercise parser, scrubber, and compiler on arbitrary fuzzed byte streams."""
    text = data.decode("utf-8", errors="replace")

    # 1. Doctor text normalizers & regexes must never hang or raise on arbitrary UTF-8
    scrubbed = DOC.normalize_mihomo_text(text)
    if "\nsecret:" in f"\n{scrubbed}" and 'secret: ""' not in scrubbed:
        raise AssertionError("Mihomo secret scrubber failed to redact secret line")
    _ = DOC.strip_yaml_comments(text)
    for line in text.splitlines()[:8]:
        slug = DOC.github_slugify(line)
        if " " in slug:
            raise AssertionError("github_slugify produced whitespace")

    # 2. JSON-compatible loader on arbitrary bytes
    try:
        parsed = CTL.load_json_compatible_from_str(text)
    except (json.JSONDecodeError, ValueError):
        return

    if not isinstance(parsed, dict):
        return

    # Guard optional nested types when raw JSON fuzzing produces non-dict fields
    try:
        rendered = CTL.canonical_repo_targets(parsed)
    except (TypeError, ValueError, KeyError, AttributeError):
        return

    for rel_path, (body, _mode) in rendered.items():
        if not isinstance(body, str) or not body:
            raise AssertionError(f"Empty rendered artifact for {rel_path}")


def mutate_valid_topology(rng: random.Random) -> dict:
    """Structure-aware mutator verifying security invariants across valid schemas."""
    gt = copy.deepcopy(BASE_GT)
    gt["home_lan_cidr"] = rng.choice(["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"])

    nodes = gt.get("nodes", {})
    for key in ("air", "studio", "gw", "panel", "home"):
        if key in nodes and isinstance(nodes[key], dict):
            nodes[key]["tailscale_ip"] = rng.choice(SAFE_V4_POOL)
            nodes[key]["tailscale_ip6"] = rng.choice(SAFE_V6_POOL)
            if rng.random() < 0.25:
                nodes[key]["rescue_port"] = rng.randint(2201, 2299)

    b2 = nodes.setdefault("grokbot_b2", {})
    k_v4 = rng.randint(1, 3)
    k_v6 = rng.randint(1, 3)
    b2["tailscale_ips"] = rng.sample(SAFE_V4_POOL, k=k_v4)
    b2["tailscale_ip6s"] = rng.sample(SAFE_V6_POOL, k=k_v6)

    dash_port = rng.choice([3001, 8081, 9090])
    gt.setdefault("ssot_workspace", {})["dashboard_port"] = dash_port

    targets = CTL.canonical_repo_targets(gt)
    dash_fw = targets["scripts/starhub-dash-fw.sh"][0]
    home_fw = targets["scripts/starhub-home-fw.sh"][0]

    # Security Invariant 1: B2 guest sandbox MUST always be blocked from TCP :22 on IPv4 & IPv6
    for fw_name, fw_body in (("dash", dash_fw), ("home", home_fw)):
        if "STARHUB-BOT-NOSSH" not in fw_body or "--dport 22 -j DROP" not in fw_body:
            raise AssertionError(f"{fw_name} firewall lost IPv4 B2 SSH DROP invariant")
        if "STARHUB-BOT-NOSSH6" not in fw_body:
            raise AssertionError(f"{fw_name} firewall lost IPv6 B2 SSH DROP invariant")

    # Security Invariant 2: Mihomo skeleton must never enable blind fallback DNS racing
    mihomo_cfg = targets["scripts/mihomo-config-backup.yaml"][0]
    if "\n  fallback:" in mihomo_cfg:
        raise AssertionError("Mihomo skeleton unexpectedly emitted forbidden DNS fallback block")
    if 'secret: ""' not in mihomo_cfg:
        raise AssertionError("Mihomo skeleton leaked non-empty controller secret")

    # Security Invariant 3: Lifeline systemd units render cleanly for every rescue_port
    units = CTL.render_lifeline_units(gt)
    for unit_body in units.values():
        if "127.0.0.1:" not in unit_body or "ExitOnForwardFailure=yes" not in unit_body:
            raise AssertionError("Lifeline systemd unit missing loopback bind or forward guard")

    return gt


def run_atheris() -> None:
    import atheris  # OpenSSF Scorecard recognized Python coverage-guided fuzzer

    atheris.Setup(sys.argv, fuzz_one_bytes)
    atheris.Fuzz()


def run_stdlib_campaign(iterations: int, seed: int) -> int:
    rng = random.Random(seed)
    base_bytes = (REPO_ROOT / "topology.example.json").read_bytes()

    # Dynamic secret-header probe without embedding literal private-key marker in repo text
    dyn_priv_probe = ("-----BEGIN " + "OPENSSH PRIVATE KEY-----\nfake\n").encode("utf-8")
    if not DOC.PRIVATE_KEY_RE.search(dyn_priv_probe.decode("utf-8")):
        raise AssertionError("PRIVATE_KEY_RE failed to detect synthetic private key header")

    for i in range(iterations):
        # Half structure-aware topology mutations, half raw byte/JSON fuzzing
        if i % 2 == 0:
            mutated_gt = mutate_valid_topology(rng)
            fuzz_one_bytes(json.dumps(mutated_gt).encode("utf-8"))
        else:
            buf = bytearray(base_bytes)
            if buf:
                flips = rng.randint(1, 16)
                for _ in range(flips):
                    idx = rng.randrange(len(buf))
                    buf[idx] = rng.randrange(256)
            fuzz_one_bytes(bytes(buf))

    # Edge-case corpus
    edge_inputs = [
        b"",
        b"# comment only\n{}",
        b'{"nodes": []}',
        b'{"nodes": {"air": null, "grokbot_b2": "invalid"}}',
        b"secret: super-secret-token\n# comment\n",
        b"### Heading With `Code` & Symbols! 2026",
    ]
    for sample in edge_inputs:
        fuzz_one_bytes(sample)

    print(
        f"[PASS] [FUZZ-HARNESS] Completed {iterations} fuzz iterations + {len(edge_inputs)} edge corpus cases (0 crashes, all B2/DNS/Secret invariants held)."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="StarHub Kit Dual-Mode Fuzzing Harness")
    parser.add_argument("--atheris", action="store_true", help="Run native Google Atheris libFuzzer loop")
    parser.add_argument("--iterations", type=int, default=2000, help="Number of stdlib fuzz iterations")
    parser.add_argument("--seed", type=int, default=20261113, help="Deterministic PRNG seed")
    args, _unknown = parser.parse_known_args()

    if args.atheris:
        run_atheris()
        return 0
    return run_stdlib_campaign(args.iterations, args.seed)


if __name__ == "__main__":
    sys.exit(main())
