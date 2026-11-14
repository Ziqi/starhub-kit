#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StarHub Contributors
# SPDX-License-Identifier: MIT
"""
Zero-dependency executable statement coverage gate for StarHub Kit
(satisfies OpenSSF Best Practices Silver `test_statement_coverage80`).

Uses Python standard-library `dis` + `trace` to measure exact executable line
coverage across `scripts/starhub-ctl.py` while exercising all CLI subcommands,
compiler targets, error branches, and bundle export modes in an isolated tempdir.
"""

from __future__ import annotations

import argparse
import dis
import importlib.util
import io
import pathlib
import shutil
import sys
import tempfile
import trace
import types
from contextlib import redirect_stderr, redirect_stdout

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_SCRIPT = (REPO_ROOT / "scripts" / "starhub-ctl.py").resolve()


def collect_executable_lines(py_file: pathlib.Path) -> set[int]:
    source = py_file.read_text(encoding="utf-8")
    code_obj = compile(source, str(py_file), "exec")
    lines: set[int] = set()

    def _walk(co: types.CodeType) -> None:
        for _offset, lineno in dis.findlinestarts(co):
            if lineno is not None and lineno > 0:
                lines.add(lineno)
        for const in co.co_consts:
            if isinstance(const, types.CodeType):
                _walk(const)

    _walk(code_obj)
    # Exclude module-level `if __name__ == "__main__": sys.exit(main())` guard line
    src_lines = source.splitlines()
    for idx, text in enumerate(src_lines, start=1):
        if "sys.exit(main())" in text:
            lines.discard(idx)
    return lines


def load_ctl_module():
    spec = importlib.util.spec_from_file_location("starhub_ctl_cov", TARGET_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {TARGET_SCRIPT}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def exercise_suite(ctl_mod, temp_root: pathlib.Path) -> None:
    # Copy clean workspace fixture into temp_root
    for item in (
        "topology.example.json",
        "STARHUB_GROUND_TRUTH.json",
        "AGENTS.md",
        "README.md",
        "README.zh-CN.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CODE_OF_CONDUCT.md",
        "GOVERNANCE.md",
        "REUSE.toml",
        "CITATION.cff",
        "LICENSE",
        "flake.nix",
    ):
        src = REPO_ROOT / item
        if src.is_file():
            shutil.copy2(src, temp_root / item)
    for link_name in ("CLAUDE.md", "GROK.md"):
        (temp_root / link_name).symlink_to("AGENTS.md")
    for sub_dir in ("docs", "scripts", "bin", "templates", "LICENSES", "profiles", ".github", "assets"):
        shutil.copytree(REPO_ROOT / sub_dir, temp_root / sub_dir)

    buf_out, buf_err = io.StringIO(), io.StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        # 1. init when STARHUB_GROUND_TRUTH.json already exists & with --force
        (temp_root / "STARHUB_GROUND_TRUTH.json").unlink()
        assert ctl_mod.cmd_init(temp_root, force=False) == 0
        assert ctl_mod.cmd_init(temp_root, force=False) == 0
        assert ctl_mod.cmd_init(temp_root, force=True) == 0

        # Missing topology.example.json error branch
        bak_ex = temp_root / "topology.example.json.bak"
        (temp_root / "topology.example.json").rename(bak_ex)
        assert ctl_mod.cmd_init(temp_root, force=True) == 1
        bak_ex.rename(temp_root / "topology.example.json")

        # 2. render --in-place & render --check (pass + drift detection + missing GT)
        assert ctl_mod.cmd_render(temp_root, check_only=False, in_place=True, out_dir=None) == 0
        assert ctl_mod.cmd_render(temp_root, check_only=True, in_place=False, out_dir=None) == 0

        # Introduce deliberate 1-line drift and verify --check catches it (rc == 1)
        dash_fw = temp_root / "scripts" / "starhub-dash-fw.sh"
        orig_fw = dash_fw.read_text(encoding="utf-8")
        dash_fw.write_text(orig_fw + "# drift\n", encoding="utf-8")
        assert ctl_mod.cmd_render(temp_root, check_only=True, in_place=False, out_dir=None) == 1
        dash_fw.unlink()
        assert ctl_mod.cmd_render(temp_root, check_only=True, in_place=False, out_dir=None) == 1
        assert ctl_mod.cmd_render(temp_root, check_only=False, in_place=True, out_dir=None) == 0

        # Missing GT branch on render
        gt_bak = temp_root / "STARHUB_GROUND_TRUTH.json.bak"
        (temp_root / "STARHUB_GROUND_TRUTH.json").rename(gt_bak)
        assert ctl_mod.cmd_render(temp_root, check_only=True, in_place=False, out_dir=None) == 1
        gt_bak.rename(temp_root / "STARHUB_GROUND_TRUTH.json")

        # 3. render --out-dir bundle mode
        bundle_dir = temp_root / "dist_test"
        assert ctl_mod.cmd_render(temp_root, check_only=False, in_place=False, out_dir=bundle_dir) == 0
        assert (bundle_dir / "ssh_config.starhub").is_file()
        assert (bundle_dir / "mihomo-gateway.yaml").is_file()
        min_bundle = temp_root / "dist_minimal_direct"
        assert ctl_mod.cmd_render(temp_root, check_only=False, in_place=False, out_dir=min_bundle, profile="minimal") == 0
        assert (min_bundle / "mihomo-gateway.yaml").is_file()
        assert not (min_bundle / "starhub-dash-fw.sh").exists()

        # 4. Modular --only + --dry-run + reproducible archive verification
        for mod_name in ("mihomo", "firewall", "ai-sandbox", "lifeline"):
            assert (
                ctl_mod.cmd_render(
                    temp_root,
                    check_only=False,
                    in_place=False,
                    out_dir=None,
                    profile="full",
                    only_module=mod_name,
                    dry_run=True,
                )
                == 0
            )
        # Dry-run empty match branch (minimal omits optional ai-sandbox)
        assert (
            ctl_mod.cmd_render(
                temp_root,
                check_only=False,
                in_place=False,
                out_dir=None,
                profile="minimal",
                only_module="ai-sandbox",
                dry_run=True,
            )
            == 0
        )

        # Reproducible archive build, verify & mismatch detection
        tar_out = temp_root / "dist_test" / "repro-test.tar.gz"
        assert ctl_mod.cmd_archive(temp_root, output=None, prefix="starhub-kit", verify=True) == 0
        assert ctl_mod.cmd_archive(temp_root, output=tar_out, prefix="starhub-kit-v1.3.0", verify=True) == 0
        assert (
            ctl_mod.cmd_archive(
                temp_root,
                output=None,
                prefix="starhub-kit-v1.3.0",
                verify=False,
                verify_file=tar_out,
            )
            == 0
        )
        assert (
            ctl_mod.cmd_archive(
                temp_root,
                output=None,
                prefix="wrong-prefix",
                verify=False,
                verify_file=tar_out,
            )
            == 1
        )
        assert (
            ctl_mod.cmd_archive(
                temp_root,
                output=None,
                prefix="starhub-kit",
                verify=False,
                verify_file=temp_root / "nonexistent.tar.gz",
            )
            == 1
        )

        # 5. Cross-platform targets (nftables, macos-pf, tailscale-acl, singbox, all) & ai-sandbox profile
        ai_out = temp_root / "dist_ai_all"
        assert (
            ctl_mod.cmd_render(
                temp_root,
                check_only=False,
                in_place=False,
                out_dir=ai_out,
                profile="ai-sandbox",
                only_module="all",
                dry_run=False,
                target="all",
            )
            == 0
        )
        assert (ai_out / "nftables" / "starhub-ai-sandbox.nft").is_file()
        assert (ai_out / "macos-pf" / "com.starhub.ai-sandbox.pf.conf").is_file()
        assert (ai_out / "tailscale-acl" / "tailscale-policy.json").is_file()
        assert (ai_out / "singbox" / "singbox-tailscale-quic-guard.json").is_file()

        for tgt in ("nftables", "macos-pf", "tailscale-acl", "singbox"):
            assert (
                ctl_mod.cmd_render(
                    temp_root,
                    check_only=False,
                    in_place=False,
                    out_dir=None,
                    profile="ai-sandbox",
                    only_module="all",
                    dry_run=True,
                    target=tgt,
                )
                == 0
            )

        # Audit clean & risky topologies
        assert ctl_mod.cmd_audit(temp_root, profile="ai-sandbox") == 0
        risky_verdict = ctl_mod.audit_topology_security(
            {
                "home_lan_cidr": "192.168.0.0/24",
                "admin_allowlist_nodes": [],
                "nodes": {"agent_sandbox": {"allowed_targets": ["100.64.0.15:22"]}},
            }
        )
        assert risky_verdict["passed"] is False and risky_verdict["risk_count"] == 3

        # 6. Zero-dependency MCP JSON-RPC 2.0 server (newline + Content-Length framing)
        mcp_requests = [
            b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n',
            b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
            b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n',
            b'{"jsonrpc":"2.0","id":3,"method":"tools/list"}\n',
            b'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"compile_ai_sandbox_policy","arguments":{"backend":"nftables","sandbox_ips":["100.64.0.210"],"allowed_api_targets":["100.64.0.15:3001"]}}}\n',
            b'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"compile_ai_sandbox_policy","arguments":{"backend":"macos-pf"}}}\n',
            b'{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"compile_ai_sandbox_policy","arguments":{"backend":"tailscale-acl"}}}\n',
            b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"compile_ai_sandbox_policy","arguments":{"backend":"iptables"}}}\n',
            b'{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"render_quic_mesh_guardrails","arguments":{"engine":"singbox"}}}\n',
            b'{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"render_quic_mesh_guardrails","arguments":{"engine":"mihomo"}}}\n',
            b'{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"audit_topology_security","arguments":{}}}\n',
            b'{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}\n',
            b'{"jsonrpc":"2.0","id":12,"method":"unknown/method"}\n',
        ]
        framed_body = b'{"jsonrpc":"2.0","id":99,"method":"ping"}'
        framed_msg = f"Content-Length: {len(framed_body)}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n".encode("ascii") + framed_body
        mcp_in = io.BytesIO(b"".join(mcp_requests) + b"\n" + framed_msg)
        mcp_out = io.BytesIO()
        assert ctl_mod.serve_mcp_stdio(temp_root, mcp_in, mcp_out) == 0
        assert b"starhub-kit" in mcp_out.getvalue() and b"Content-Length:" in mcp_out.getvalue()

        # 7. CLI main() dispatch across subcommands (init, render, audit, archive, export-workstation, doctor)
        orig_argv = sys.argv[:]
        try:
            min_dir = temp_root / "dist_min_test"
            for argv in (
                ["starhub-ctl.py", "--repo-root", str(temp_root), "init"],
                ["starhub-ctl.py", "--repo-root", str(temp_root), "render", "--check"],
                ["starhub-ctl.py", "--repo-root", str(temp_root), "render", "--profile", "minimal", "--only", "mihomo", "--dry-run"],
                ["starhub-ctl.py", "--repo-root", str(temp_root), "render", "--profile", "ai-sandbox", "--target", "tailscale-acl", "--dry-run"],
                ["starhub-ctl.py", "--repo-root", str(temp_root), "render", "--profile", "minimal", "--out-dir", str(min_dir)],
                ["starhub-ctl.py", "--repo-root", str(temp_root), "audit", "--profile", "ai-sandbox"],
                ["starhub-ctl.py", "--repo-root", str(temp_root), "archive", "--verify"],
                ["starhub-ctl.py", "--repo-root", str(temp_root), "export-workstation"],
                ["starhub-ctl.py", "--repo-root", str(temp_root), "doctor", "--local-docs-only"],
            ):
                sys.argv = argv
                assert ctl_mod.main() == 0
        finally:
            sys.argv = orig_argv


def main() -> int:
    parser = argparse.ArgumentParser(description="StarHub Kit >=80% Statement Coverage Gate")
    parser.add_argument("--min-coverage", type=float, default=80.0)
    args = parser.parse_args()

    exec_lines = collect_executable_lines(TARGET_SCRIPT)
    tracer = trace.Trace(count=True, trace=False)

    with tempfile.TemporaryDirectory(prefix="starhub_cov_") as tmp:
        temp_root = pathlib.Path(tmp)

        def _workload() -> None:
            mod = load_ctl_module()
            exercise_suite(mod, temp_root)

        tracer.runfunc(_workload)

    results = tracer.results()
    hit_lines: set[int] = set()
    target_resolved = str(TARGET_SCRIPT)
    for (filename, lineno), count in results.counts.items():
        if count > 0 and str(pathlib.Path(filename).resolve()) == target_resolved:
            if lineno in exec_lines:
                hit_lines.add(lineno)

    pct = (len(hit_lines) / len(exec_lines) * 100.0) if exec_lines else 100.0
    print(
        f"[INFO] [COVERAGE] scripts/starhub-ctl.py statement coverage: {len(hit_lines)}/{len(exec_lines)} ({pct:.2f}%, threshold >= {args.min_coverage:.1f}%)"
    )
    if pct < args.min_coverage:
        missed = sorted(exec_lines - hit_lines)
        print(f"[FAIL] [COVERAGE] Below {args.min_coverage:.1f}%! Missed lines: {missed[:25]}", file=sys.stderr)
        return 1
    print(f"[PASS] [COVERAGE] OpenSSF Silver >=80% statement coverage gate satisfied ({pct:.2f}%).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
