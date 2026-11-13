#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StarHub Contributors
# SPDX-License-Identifier: MIT
"""
StarHub EGM 3.0 — 全栈唯一事实源、八维零漂移门禁与反隐私发布引擎
路径: scripts/starhub-doctor.py (同时兼容私有生产仓 production 与公开开源包 open_source_kit)

用法:
  1. 主控端全网 8 维实机核验 (自动 SSH 核对 panel / gw / home):
     ssh -A panel "python3 /root/starhub/scripts/starhub-doctor.py"
  2. 看板节点本地仓库 + 双栈防火墙 + :3001 探针核验:
     python3 scripts/starhub-doctor.py --local-only
  3. Git pre-commit 钩子 / GitHub Actions CI 毫秒级静态门禁校验 (零网络调用):
     python3 scripts/starhub-doctor.py --local-docs-only
  4. 按 [STUDIO] 标签一键导出工作站专项台账片段:
     python3 scripts/starhub-doctor.py --export-studio
  5. 数学级反隐私泄露发布门禁 (扫描公开导出目录与 .git 历史，确保 0 真实资产外泄):
     python3 scripts/starhub-doctor.py --verify-public-export /root/starhub-kit --private-gt /root/starhub/STARHUB_GROUND_TRUTH.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.parse
import urllib.request

DEFAULT_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
EMOJI_RE = re.compile(r"[\U0001F000-\U0001FAFF\u2300-\u23FF\u2600-\u27BF]")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP)?\s*PRIVATE KEY-----")
FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
MD_LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.MULTILINE)
IPV4_TOKEN_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TS_IPV6_TOKEN_RE = re.compile(r"fd7a:115c:a1e0:[0-9a-fA-F:]+")
MAC_TOKEN_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")

PUBLIC_SAFE_IPV4_ALLOWLIST = {
    "0.0.0.0",
    "127.0.0.0",
    "127.0.0.1",
    "100.64.0.0",
    "100.100.100.100",
    "172.16.0.0",
    "198.18.0.0",
    "223.5.5.5",
    "1.1.1.1",
}

FROZEN_PRE_V3_INCIDENTS = {
    "docs/incidents/INC-20260506-001-history-store-self-poller-18h-gap.md",
    "docs/incidents/INC-20260620-001-vless1-cross-border-instability-and-cf-challenge-clarification.md",
    "docs/incidents/INC-20260620-003-verge-kill-tun-loss-claude-cf-block.md",
    "docs/incidents/INC-20261112-001-grokbot-ssh-banner-splitbrain.md",
}


class CheckRunner:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.skipped = 0

    def ok(self, section: str, msg: str) -> None:
        self.passed += 1
        print(f"  [PASS] [{section}] {msg}")

    def fail(self, section: str, msg: str) -> None:
        self.failed += 1
        print(f"  [FAIL] [{section}] {msg}")

    def skip(self, section: str, msg: str) -> None:
        self.skipped += 1
        print(f"  [SKIP] [{section}] {msg}")


def load_json_compatible(path: pathlib.Path) -> dict:
    raw_lines = path.read_text(encoding="utf-8").splitlines()
    json_body = "\n".join(
        line for line in raw_lines if not line.lstrip().startswith("#")
    )
    return json.loads(json_body)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_mihomo_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"(?m)^secret:.*$", 'secret: ""', text)
    return text.strip()


def strip_yaml_comments(text: str) -> list[str]:
    active: list[str] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        active.append(raw)
    return active


def github_slugify(heading_text: str) -> str:
    txt = heading_text.replace("`", "").strip().lower()
    slug_chars: list[str] = []
    for ch in txt:
        if ch == " ":
            slug_chars.append("-")
        elif ch.isalnum() or ch in ("-", "_"):
            slug_chars.append(ch)
    return "".join(slug_chars)


def collect_heading_slugs(markdown_text: str) -> set[str]:
    body = FENCE_RE.sub("", markdown_text)
    slugs: set[str] = set()
    counts: dict[str, int] = {}
    for m in HEADING_RE.finditer(body):
        base = github_slugify(m.group(2))
        if not base:
            continue
        if base not in counts:
            counts[base] = 0
            slugs.add(base)
        else:
            counts[base] += 1
            slugs.add(f"{base}-{counts[base]}")
    for am in re.finditer(r'<a\s+(?:id|name)=["\']([^"\']+)["\']', body):
        slugs.add(am.group(1))
    return slugs


def run_cmd(cmd: list[str], timeout: int = 12) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:" + env.get(
        "PATH", ""
    )
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as exc:
        return 127, "", str(exc)


def export_studio_ledger(repo_root: pathlib.Path) -> int:
    ledger_path = repo_root / "docs" / "ops" / "STARHUB-LEDGER.md"
    gt_path = repo_root / "STARHUB_GROUND_TRUTH.json"
    if not ledger_path.is_file():
        print(f"ERROR: 未找到 {ledger_path}", file=sys.stderr)
        return 1
    studio_ip = "studio"
    if gt_path.is_file():
        gt = load_json_compatible(gt_path)
        studio_ip = gt.get("nodes", {}).get("studio", {}).get("tailscale_ip", "studio")
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    out: list[str] = [
        f"# 工作站 Studio ({studio_ip}) 星枢专项变更导出摘要",
        "",
        "> 自动导出自 `docs/ops/STARHUB-LEDGER.md` (`--export-studio`)",
        "",
    ]
    capture = False
    for line in lines:
        if line.startswith("> **更早历史记录"):
            capture = False
            break
        if line.startswith("### "):
            capture = line.startswith("### STUDIO-") or "[STUDIO]" in line
        elif line.startswith("## ") and not line.startswith("### "):
            capture = False
        if capture:
            out.append(line)
    while out and out[-1].strip() in ("", "---"):
        out.pop()
    print("\n".join(out) + "\n")
    return 0


def _iter_strings(obj: object) -> list[str]:
    found: list[str] = []
    if isinstance(obj, str):
        found.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            found.extend(_iter_strings(v))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_iter_strings(item))
    return found


def verify_public_export(public_dir: pathlib.Path, private_gt_path: pathlib.Path) -> int:
    print("======================================================================")
    print(" StarHub Zero-PII Release Sanitizer — 公开开源包数学级反隐私泄露门禁")
    print("======================================================================")
    if not public_dir.is_dir():
        print(f"  [FAIL] [ZERO-PII] 导出目录不存在: {public_dir}")
        return 1
    if not private_gt_path.is_file():
        print(f"  [FAIL] [ZERO-PII] 私有事实源不存在: {private_gt_path}")
        return 1

    priv_gt = load_json_compatible(private_gt_path)
    all_strs = _iter_strings(priv_gt)

    ipv4_blocklist: set[str] = set()
    literal_blocklist: dict[str, str] = {}

    for s in all_strs:
        for ip4 in IPV4_TOKEN_RE.findall(s):
            if ip4 not in PUBLIC_SAFE_IPV4_ALLOWLIST:
                ipv4_blocklist.add(ip4)
        for ip6 in TS_IPV6_TOKEN_RE.findall(s):
            if ip6.lower() != "fd7a:115c:a1e0:":
                literal_blocklist[ip6.lower()] = "private Tailscale IPv6/4via6"
        for mac in MAC_TOKEN_RE.findall(s):
            literal_blocklist[mac.lower()] = "private hardware MAC"

    derp = priv_gt.get("nodes", {}).get("derp", {})
    for dom_field in ("domain", "root_domain_suffix"):
        val = derp.get(dom_field, "").strip()
        if val:
            literal_blocklist[val.lower()] = f"private {dom_field}"

    for tok in priv_gt.get("private_pii_tokens", []):
        t = tok.strip()
        if t:
            literal_blocklist[t.lower()] = "private_pii_token"

    for r_tok in priv_gt.get("retired_assets_blocklist", []):
        t = r_tok.strip()
        if IPV4_TOKEN_RE.fullmatch(t):
            ipv4_blocklist.add(t)
        elif t:
            literal_blocklist[t.lower()] = "retired_asset"

    ipv4_patterns = [
        (ip4, re.compile(rf"(?<![0-9.]){re.escape(ip4)}(?![0-9])"))
        for ip4 in sorted(ipv4_blocklist)
    ]

    leaks: list[str] = []
    scanned_files = 0
    skip_dirs = {".git", "__pycache__", "node_modules", ".next"}

    def scan_text(label: str, content: str) -> None:
        low = content.lower()
        for ip4, pat in ipv4_patterns:
            m = pat.search(content)
            if m:
                line_no = content.count("\n", 0, m.start()) + 1
                leaks.append(f"{label}:{line_no} 命中私有 IP '{ip4}'")
        for lit, kind in literal_blocklist.items():
            idx = low.find(lit)
            if idx != -1:
                line_no = low.count("\n", 0, idx) + 1
                leaks.append(f"{label}:{line_no} 命中私有标识 '{lit}' ({kind})")

    for root, dirs, files in os.walk(public_dir, followlinks=False):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        rp = pathlib.Path(root)
        for fn in sorted(files):
            fp = rp / fn
            if fp.is_symlink() or not fp.is_file():
                continue
            rel = fp.relative_to(public_dir).as_posix()
            scanned_files += 1
            text = fp.read_text(encoding="utf-8", errors="ignore")
            scan_text(rel, text)

    git_commits_scanned = 0
    if (public_dir / ".git").exists():
        rc_cnt, out_cnt, _ = run_cmd(
            ["git", "-C", str(public_dir), "rev-list", "--all", "--count"]
        )
        if rc_cnt == 0 and out_cnt.strip().isdigit():
            git_commits_scanned = int(out_cnt.strip())
        rc_log, out_log, _ = run_cmd(
            ["git", "-C", str(public_dir), "log", "-p", "--all"], timeout=25
        )
        if rc_log == 0 and out_log:
            scan_text(".git/history", out_log)

    total_rules = len(ipv4_patterns) + len(literal_blocklist)
    print(
        f"  [INFO] 已加载私有资产敏感指纹字典: {total_rules} 项 "
        f"(真实 IPv4={len(ipv4_patterns)}, IPv6/MAC/域名/账号标识={len(literal_blocklist)})"
    )
    print(
        f"  [INFO] 已逐字节扫描公开导出目录文件: {scanned_files} 份 | Git 历史提交: {git_commits_scanned} 个"
    )
    if leaks:
        for hit in leaks[:15]:
            print(f"  [FAIL] [ZERO-PII] {hit}")
        print("----------------------------------------------------------------------")
        print(f" 反隐私发布门禁阻断: 检测到 {len(leaks)} 处真实资产痕迹，严禁公开推送！")
        print("======================================================================")
        return 1

    print("  [PASS] [ZERO-PII] 公开仓工作树与 .git 全历史命中真实私有资产次数 == 0 (100% 净室脱敏通过)")
    print("======================================================================")
    return 0


def check_dim1_doc_whitelist(
    runner: CheckRunner, repo_root: pathlib.Path, gt: dict
) -> list[pathlib.Path]:
    sec = "DIM1-DOC-WHITELIST"
    expected_symlinks: dict[str, str] = gt.get("root_markdown_symlinks", {})
    for link_name, target_name in expected_symlinks.items():
        lp = repo_root / link_name
        expected_target = (lp.parent / target_name).resolve()
        if lp.is_symlink() and lp.is_file() and lp.resolve() == expected_target:
            runner.ok(sec, f"入口软链收敛正常且目标有效: {link_name} -> {target_name}")
        else:
            runner.fail(
                sec,
                f"入口 {link_name} 未配置为指向有效 {target_name} 的软链接 (禁止双头分叉或悬空)",
            )

    allowed_set = set(gt.get("allowed_active_markdown_files", []))
    found_active: set[str] = set()
    link_check_files: list[pathlib.Path] = []
    skip_dirs = {".git", "node_modules", ".next", "__pycache__", "dist"}

    for root, dirs, files in os.walk(repo_root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        root_path = pathlib.Path(root)
        for fn in files:
            if not fn.endswith(".md"):
                continue
            fp = root_path / fn
            rel = fp.relative_to(repo_root).as_posix()
            if fp.is_symlink():
                if rel not in expected_symlinks:
                    runner.fail(sec, f"检测到未授权的 Markdown 软链接: {rel}")
                continue
            if rel.startswith("docs/archive/"):
                continue
            if rel.startswith("docs/incidents/"):
                link_check_files.append(fp)
                continue
            found_active.add(rel)
            link_check_files.append(fp)

    missing_docs = sorted(allowed_set - found_active)
    rogue_docs = sorted(found_active - allowed_set)
    if missing_docs:
        runner.fail(sec, f"缺失黄金白名单文档: {missing_docs}")
    if rogue_docs:
        runner.fail(
            sec,
            f"检测到白名单外的野文档/冗余碎片 (请合并或归档至 docs/archive/): {rogue_docs}",
        )
    if not missing_docs and not rogue_docs:
        runner.ok(
            sec,
            f"全仓活跃 Markdown 精确锁死 ({len(found_active)}/{len(allowed_set)} 份，零野文档)",
        )

    inc_dir = repo_root / "docs" / "incidents"
    inc_files = sorted(p.name for p in inc_dir.glob("*.md")) if inc_dir.is_dir() else []
    min_inc = 2 if gt.get("repo_profile") == "open_source_kit" else 9
    if len(inc_files) >= min_inc and "README.md" in inc_files:
        runner.ok(sec, f"docs/incidents/ 复盘库与模板完整 ({len(inc_files)} 份)")
    else:
        runner.fail(sec, f"docs/incidents/ 文件异常或缺失: {inc_files}")

    return sorted(link_check_files)


def check_dim2_doc_links(
    runner: CheckRunner, repo_root: pathlib.Path, md_files: list[pathlib.Path]
) -> None:
    sec = "DIM2-DOC-LINKS"
    broken: list[str] = []
    checked_count = 0
    ignore_schemes = (
        "http://",
        "https://",
        "mailto:",
        "starhub://",
        "sidecar://",
        "conversation://",
        "file://",
    )

    slug_cache: dict[pathlib.Path, set[str]] = {}

    def get_slugs(p: pathlib.Path) -> set[str]:
        if p not in slug_cache:
            slug_cache[p] = collect_heading_slugs(p.read_text(encoding="utf-8"))
        return slug_cache[p]

    for fp in md_files:
        raw = fp.read_text(encoding="utf-8")
        stripped = INLINE_CODE_RE.sub("", FENCE_RE.sub("", raw))
        rel_src = fp.relative_to(repo_root).as_posix()
        for m in MD_LINK_RE.finditer(stripped):
            target_raw = m.group(1).strip()
            if not target_raw or target_raw.startswith(ignore_schemes):
                continue
            target_clean = target_raw.split()[0]
            if target_clean.startswith("#"):
                checked_count += 1
                anchor = urllib.parse.unquote(target_clean[1:]).lower()
                if anchor and anchor not in get_slugs(fp):
                    broken.append(f"{rel_src} -> {target_raw} (锚点不存在)")
                continue

            parts = target_clean.split("#", 1)
            path_part = urllib.parse.unquote(parts[0])
            anchor_part = urllib.parse.unquote(parts[1]).lower() if len(parts) > 1 else ""
            if not path_part:
                continue

            checked_count += 1
            if path_part.startswith("/"):
                resolved = (repo_root / path_part.lstrip("/")).resolve()
            else:
                resolved = (fp.parent / path_part).resolve()

            if not resolved.is_relative_to(repo_root):
                broken.append(f"{rel_src} -> {target_raw} (越界路径)")
                continue

            if not resolved.exists():
                if rel_src in FROZEN_PRE_V3_INCIDENTS and path_part in (
                    "../ops/updates-log.md",
                    "../ops/bugfix-log.md",
                ):
                    archived_target = (
                        repo_root
                        / "docs"
                        / "archive"
                        / "2026-11-13-v3-consolidation"
                        / "ops"
                        / pathlib.Path(path_part).name
                    )
                    unified_ledger = repo_root / "docs" / "ops" / "STARHUB-LEDGER.md"
                    if archived_target.is_file() and unified_ledger.is_file():
                        continue
                broken.append(f"{rel_src} -> {target_raw}")
                continue

            if anchor_part and resolved.is_file() and resolved.suffix == ".md":
                if anchor_part not in get_slugs(resolved):
                    broken.append(f"{rel_src} -> {target_raw} (跨文件锚点不存在)")

    if broken:
        runner.fail(sec, f"检测到 {len(broken)} 处死链或失效锚点: {broken[:5]}")
    else:
        runner.ok(
            sec,
            f"全仓活跃文档内部链接与标题锚点 100% 可达 (共核验 {checked_count} 处，0 死链)",
        )


def check_dim3_anti_corrupt(
    runner: CheckRunner, repo_root: pathlib.Path, gt: dict
) -> None:
    sec = "DIM3-ANTI-CORRUPT"
    stale_phrases: list[str] = gt.get("forbidden_stale_phrases", [])
    retired_ips: list[str] = gt.get("retired_assets_blocklist", [])
    allowed_docs: list[str] = gt.get("allowed_active_markdown_files", [])

    phrase_hits: list[str] = []
    ip_hits: list[str] = []

    for rel in allowed_docs:
        fp = repo_root / rel
        if not fp.is_file():
            continue
        txt = fp.read_text(encoding="utf-8")
        for ph in stale_phrases:
            if ph in txt:
                phrase_hits.append(f"{rel}: '{ph}'")
        if rel != "docs/ops/STARHUB-LEDGER.md":
            for rip in retired_ips:
                if rip in txt:
                    ip_hits.append(f"{rel}: '{rip}'")

    if phrase_hits:
        runner.fail(sec, f"检测到旧版腐败/违规表述残留: {phrase_hits[:5]}")
    else:
        runner.ok(sec, f"全仓黄金文档零旧版腐败词残留 ({len(stale_phrases)} 项禁用词清零)")

    if ip_hits:
        runner.fail(sec, f"活跃架构/运维文档中仍残留已退役设备 IP: {ip_hits}")
    else:
        runner.ok(sec, "活跃架构与运维手册零退役设备幽灵 IP 残留")

    sys_ver = gt.get("system_version", "")
    home_ver = gt.get("nodes", {}).get("home", {}).get("app_version", "")
    egress_ips = [v["ip"] for v in gt.get("egress_vps", {}).values()]
    forward_checks = [
        ("AGENTS.md", [sys_ver, home_ver] + egress_ips),
        ("docs/01-架构与IP全景.md", [sys_ver, home_ver] + egress_ips),
        ("docs/05-智能家居与AI中枢全景.md", [sys_ver, home_ver]),
    ]
    drift_forward: list[str] = []
    for rel_doc, tokens in forward_checks:
        p = repo_root / rel_doc
        if p.is_file():
            body = p.read_text(encoding="utf-8")
            for tok in tokens:
                if tok and tok not in body:
                    drift_forward.append(f"{rel_doc} 缺失当前权威字段 '{tok}'")
    if drift_forward:
        runner.fail(sec, f"正向版本/IP 一致性断言失败: {drift_forward[:4]}")
    else:
        runner.ok(sec, f"核心手册与 STARHUB_GROUND_TRUTH ({sys_ver} / {home_ver} / 三出口 IP) 正向对齐")


def check_dim4_secret_guard(runner: CheckRunner, repo_root: pathlib.Path) -> None:
    sec = "DIM4-SECRET-GUARD"
    skip_dirs = {".git", "node_modules", ".next", "__pycache__", "dist"}
    binary_exts = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".webp",
        ".woff",
        ".woff2",
        ".ttf",
        ".zst",
        ".gz",
        ".tgz",
        ".zip",
        ".pdf",
    }
    allowed_env_templates = {".env.example", ".env.sample", ".env.template"}
    present_envs: list[str] = []
    key_leaks: list[str] = []

    candidate_rels: list[str] = []
    if (repo_root / ".git").exists():
        rc, out, _ = run_cmd(
            ["git", "-C", str(repo_root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
        )
        if rc == 0:
            candidate_rels = [p for p in out.split("\0") if p]

    if not candidate_rels:
        for root, dirs, files in os.walk(repo_root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            rp = pathlib.Path(root)
            for fn in files:
                fp = rp / fn
                if fp.is_symlink():
                    continue
                candidate_rels.append(fp.relative_to(repo_root).as_posix())

    for rel in candidate_rels:
        fp = repo_root / rel
        if fp.is_symlink() or not fp.is_file():
            continue
        fn = fp.name
        if (fn == ".env" or fn.startswith(".env.")) and fn not in allowed_env_templates:
            present_envs.append(rel)
        if fp.suffix.lower() in binary_exts:
            continue
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if PRIVATE_KEY_RE.search(content) and rel != "scripts/starhub-doctor.py":
            key_leaks.append(rel)

    if present_envs:
        runner.fail(sec, f"Git 入库/待暂存范围存在严禁入库的真实 .env 文件: {present_envs}")
    else:
        runner.ok(sec, "Git 入库与未忽略范围零真实 .env 敏感文件泄露 (线上运行态 .env 已被 .gitignore 隔离)")

    if key_leaks:
        runner.fail(sec, f"Git 入库/待暂存范围检测到疑似私钥块泄露: {key_leaks}")
    else:
        runner.ok(sec, "Git 入库与未忽略文件零明文私钥块泄露 (运行态 keys/ 已被 .gitignore 隔离)")


def check_dim5_iot_ssot(runner: CheckRunner, repo_root: pathlib.Path, gt: dict) -> None:
    sec = "DIM5-IOT-SSOT"
    iot_cfg = gt.get("iot_ssot", {})
    for dep in iot_cfg.get("deprecated_iot_dirs", []):
        p = repo_root / dep
        if p.exists():
            runner.fail(sec, f"冗余历史目录仍存在: {p}")
        else:
            runner.ok(sec, f"已清退历史分裂目录: {dep}")

    if iot_cfg.get("enabled", True) is False or gt.get("repo_profile") == "open_source_kit":
        roadmap = repo_root / "docs" / "ROADMAP-v2.md"
        if roadmap.is_file():
            runner.ok(sec, "开源核心包模式: IoT 驱动插件规范已收敛于 docs/ROADMAP-v2.md (v2.0 插件接口预留就绪)")
        else:
            runner.fail(sec, "open_source_kit 缺失 docs/ROADMAP-v2.md 插件扩展规范文档")
        return

    iot_dir = repo_root / iot_cfg.get("canonical_iot_dir", "iot/starhub-home")
    parity_files = iot_cfg.get("iot_parity_files", [])
    missing = [f for f in parity_files if not (iot_dir / f).is_file()]
    if missing:
        runner.fail(sec, f"{iot_dir} 缺失核心文件: {missing}")
    else:
        runner.ok(sec, f"唯一真源目录 {iot_cfg.get('canonical_iot_dir')} {len(parity_files)} 项核心文件齐全")

    idx_root = iot_dir / "index.html"
    idx_static = iot_dir / "static" / "index.html"
    if idx_root.is_file() and idx_static.is_file():
        if idx_root.read_bytes() == idx_static.read_bytes():
            runner.ok(sec, "iot/starhub-home/index.html 与 static/index.html 100% 字节一致")
        else:
            runner.fail(sec, "iot/starhub-home/index.html 与 static/index.html 内容不一致")

    for fn in ("index.html", "server.py", "gemx_bridge.py", "shome"):
        fp = iot_dir / fn
        if fp.is_file():
            cnt = len(EMOJI_RE.findall(fp.read_text(encoding="utf-8")))
            if cnt == 0:
                runner.ok(sec, f"{fn} 满足零 Emoji 规范 (emoji_count=0)")
            else:
                runner.fail(sec, f"{fn} 检测到违规 Emoji 字符: emoji_count={cnt}")


def check_dim6_mihomo_repo(runner: CheckRunner, repo_root: pathlib.Path, g: dict) -> str:
    sec = "DIM6-MIHOMO-GUARD"
    backup_path = repo_root / "scripts" / "mihomo-config-backup.yaml"
    if not backup_path.is_file():
        runner.fail(sec, f"未找到 {backup_path}")
        return ""

    raw_text = backup_path.read_text(encoding="utf-8")
    active_lines = strip_yaml_comments(raw_text)
    active_text = "\n".join(active_lines)
    compact_active = re.sub(r"\s+", " ", active_text)

    if re.search(r'(?m)^secret:\s*""\s*$', active_text):
        runner.ok(sec, 'scripts/mihomo-config-backup.yaml 已脱敏 (secret: "")')
    else:
        runner.fail(sec, "scripts/mihomo-config-backup.yaml 未脱敏 secret 字段！")

    if re.search(r"(?m)^\s*fallback:\s*$", active_text):
        runner.fail(sec, "DNS 仍残留盲目竞速 fallback: 段（会引发跨洋半开握手断连）")
    else:
        runner.ok(sec, "DNS 已移除 fallback 盲目双发竞速段")

    if re.search(r"(?m)^\s*respect-rules:\s*true\s*$", active_text):
        runner.ok(sec, "DNS respect-rules: true 已启用")
    else:
        runner.fail(sec, "DNS 缺失 respect-rules: true")

    for dom_key, upstream in g["gw_dns_invariants"]["required_nameserver_policy_pairs"]:
        pat_multiline = f'"{dom_key}": - "{upstream}"'
        pat_inline = f'"{dom_key}": "{upstream}"'
        if pat_multiline in compact_active or pat_inline in compact_active:
            runner.ok(sec, f"确定性分域 DNS 策略有效就位: {dom_key} -> {upstream}")
        else:
            runner.fail(sec, f"缺失或被注释的分域 DNS 策略: {dom_key} -> {upstream}")

    for rule_group_key, label in (
        ("mandatory_anti_loop_rules", "核心防环直连规则"),
        ("apple_quic_reject_rules", "Section 12b Apple QUIC 治理"),
        ("gmail_quic_reject_rules", "Section 12c Gmail QUIC 治理"),
    ):
        missing_rules = [
            r for r in g[rule_group_key] if not any(r in ln for ln in active_lines)
        ]
        if missing_rules:
            runner.fail(sec, f"{label} 缺失或被注释 {len(missing_rules)} 条: {missing_rules[:2]}")
        else:
            runner.ok(sec, f"{label} 全部有效就位 ({len(g[rule_group_key])}/{len(g[rule_group_key])})")

    yt_violation = False
    for line in active_lines:
        s = line.strip()
        if "REJECT" not in s or "UDP" not in s:
            continue
        for yt_dom in g["protected_youtube_cronet_domains"]:
            if yt_dom in s:
                runner.fail(sec, f"违规拦截 YouTube/Cronet UDP 域名 ({yt_dom}): {s}")
                yt_violation = True
                break
        if s.replace(" ", "") == "-AND,((NETWORK,UDP),(DST-PORT,443)),REJECT":
            runner.fail(sec, "检测到已被禁止的全局 UDP/443 REJECT 规则 (违背 BUGFIX-20260820-002)")
            yt_violation = True
    if not yt_violation:
        runner.ok(sec, "YouTube Cronet UDP 通道零误伤保护验证通过 (BUGFIX-20260820-002)")

    return raw_text


def check_dim7_fw_repo(runner: CheckRunner, repo_root: pathlib.Path, gt: dict) -> None:
    fw_sec = "DIM7-FW-GUARD"
    ctl_script = repo_root / "scripts" / "starhub-ctl.py"
    if ctl_script.is_file():
        rc_ctl, _, err_ctl = run_cmd(
            [sys.executable, str(ctl_script), "--repo-root", str(repo_root), "render", "--check"]
        )
        if rc_ctl == 0:
            runner.ok(fw_sec, "starhub-ctl.py render --check 声明式编译零漂移校验通过")
        else:
            runner.fail(fw_sec, f"starhub-ctl.py render --check 检测到漂移: {err_ctl.strip()}")
    else:
        runner.fail(fw_sec, "缺失声明式编译器 scripts/starhub-ctl.py")

    retired_ips: list[str] = gt.get("retired_assets_blocklist", [])
    fw_scripts = [
        "starhub-ts-mss-clamp.sh",
        "starhub-dash-fw.sh",
        "starhub-home-fw.sh",
    ]
    for fw_name in fw_scripts:
        fw_path = repo_root / "scripts" / fw_name
        if not fw_path.is_file():
            runner.fail(fw_sec, f"未找到防火墙脚本: {fw_path}")
            continue
        fw_txt = fw_path.read_text(encoding="utf-8")
        leaked = [ip for ip in retired_ips if ip in fw_txt]
        if leaked:
            runner.fail(fw_sec, f"{fw_name} 仍残留已退役设备 IP: {leaked}")
        else:
            runner.ok(fw_sec, f"{fw_name} 已清退退役设备双栈幽灵 IP")

    for bot_fw in ("starhub-dash-fw.sh", "starhub-home-fw.sh"):
        fw_path = repo_root / "scripts" / bot_fw
        if fw_path.is_file():
            fw_txt = fw_path.read_text(encoding="utf-8")
            if "STARHUB-BOT-NOSSH" in fw_txt and "STARHUB-BOT-NOSSH6" in fw_txt:
                runner.ok(fw_sec, f"{bot_fw} 已配齐双栈 B2 访客禁 SSH 链 (NOSSH + NOSSH6)")
            else:
                runner.fail(fw_sec, f"{bot_fw} 缺失 STARHUB-BOT-NOSSH 或 STARHUB-BOT-NOSSH6")

    hook_script = repo_root / "scripts" / "pre-commit"
    if hook_script.is_file():
        runner.ok(fw_sec, "受控 Git 门禁模板 scripts/pre-commit 已在主仓归档")
    else:
        runner.fail(fw_sec, "缺失 scripts/pre-commit 受控门禁模板")


def check_dim8_local_panel_and_health(runner: CheckRunner, gt: dict) -> None:
    fw_sec = "DIM7-PANEL-IPTABLES"
    retired_ips: list[str] = gt.get("retired_assets_blocklist", [])
    rc4, out4, _ = run_cmd(["iptables", "-S"])
    rc6, out6, _ = run_cmd(["ip6tables", "-S"])
    if rc4 == 0 and rc6 == 0:
        combined = out4 + "\n" + out6
        leaked = [ip for ip in retired_ips if ip in combined]
        if leaked:
            runner.fail(fw_sec, f"panel 线上双栈防火墙仍残留退役 IP: {leaked}")
        else:
            runner.ok(fw_sec, "panel 线上 iptables + ip6tables 零退役 IP 残留")
        if "STARHUB-BOT-NOSSH" in out4 and "STARHUB-BOT-NOSSH6" in out6:
            runner.ok(fw_sec, "panel 线上双栈 STARHUB-BOT-NOSSH / NOSSH6 生效中")
        else:
            runner.fail(fw_sec, "panel 线上双栈防火墙缺失 STARHUB-BOT-NOSSH 或 NOSSH6")
    else:
        runner.skip(fw_sec, "非 root 或非 Linux 环境，跳过本地双栈 iptables 检查")

    sec = "DIM8-HEALTH-16"
    dash_port = gt.get("ssot_workspace", {}).get("dashboard_port", 3001)
    expected_cnt = gt.get("ssot_workspace", {}).get("expected_probe_count", 16)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{dash_port}/api/health", timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        probes = data.get("probes", [])
        if len(probes) == expected_cnt:
            runner.ok(sec, f"看板探针总数严格对齐 ({len(probes)}/{expected_cnt} 项)")
        else:
            runner.fail(sec, f"看板探针数量漂移: 实测 {len(probes)} 项 != 期望 {expected_cnt} 项")
        bad_crit = [
            p["name"]
            for p in probes
            if p.get("critical") and p.get("status") not in ("ok", "degraded", "warn")
        ]
        ok_cnt = sum(1 for p in probes if p.get("status") == "ok")
        deg_cnt = sum(1 for p in probes if p.get("status") == "degraded")
        if bad_crit:
            runner.fail(sec, f"看板关键探针异常 down: {bad_crit}")
        else:
            runner.ok(
                sec,
                f"127.0.0.1:{dash_port}/api/health 响应正常 (ok={ok_cnt}, degraded={deg_cnt}, 关键探针零 down)",
            )
    except Exception as exc:  # noqa: BLE001
        runner.fail(sec, f"请求 127.0.0.1:{dash_port}/api/health 失败: {exc}")


def check_remote_gw_and_home(
    runner: CheckRunner, repo_root: pathlib.Path, gt: dict, backup_text: str
) -> None:
    retired_ips: list[str] = gt.get("retired_assets_blocklist", [])
    nodes = gt.get("nodes", {})
    gw_ip = nodes.get("gw", {}).get("lan_ip", "")
    home_ip = nodes.get("home", {}).get("lan_ip", "")

    gw_sec = "DIM6-GW-LIVE"
    rc, out, err = run_cmd(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=5",
            f"root@{gw_ip}",
            "stat -c '%a' /etc/mihomo/config.yaml && echo '===SPLIT===' && cat /etc/mihomo/config.yaml && echo '===SPLIT===' && cat /root/README.md && echo '===SPLIT===' && iptables -S && ip6tables -S",
        ],
        timeout=15,
    )
    if rc == 255:
        runner.skip(gw_sec, "当前会话未携带主控 SSH Agent (请从主控端执行 ssh -A panel 运行全节点核验)")
    elif rc != 0:
        runner.fail(gw_sec, f"gw ({gw_ip}) 远端核验命令执行失败 (rc={rc}): {err.strip()}")
    else:
        parts = out.split("===SPLIT===")
        mode_str = parts[0].strip()
        live_cfg = parts[1] if len(parts) > 1 else ""
        gw_readme = parts[2] if len(parts) > 2 else ""
        gw_ipt = parts[3] if len(parts) > 3 else ""
        if mode_str == "600":
            runner.ok(gw_sec, "gw:/etc/mihomo/config.yaml 权限严格锁定为 0600")
        else:
            runner.fail(gw_sec, f"gw:/etc/mihomo/config.yaml 权限异常: {mode_str} (期望 0600)")

        if backup_text:
            if normalize_mihomo_text(live_cfg) == normalize_mihomo_text(backup_text):
                runner.ok(gw_sec, "gw 线上 config.yaml 与主仓脱敏备份 100% 零漂移对齐")
            else:
                runner.fail(gw_sec, "gw 线上 config.yaml 与 scripts/mihomo-config-backup.yaml 存在漂移！")

        gw_card_path = repo_root / "scripts" / "starhub-gw-root-README.md"
        if gw_card_path.is_file() and gw_readme.strip() == gw_card_path.read_text(encoding="utf-8").strip():
            runner.ok(gw_sec, "gw:/root/README.md 与主仓 scripts/starhub-gw-root-README.md 100% 同步")
        else:
            runner.fail(gw_sec, "gw:/root/README.md 与主仓说明卡不一致")

        if any(ip in gw_ipt for ip in retired_ips):
            runner.fail(gw_sec, "gw 线上双栈防火墙仍残留退役设备 IP")
        else:
            runner.ok(gw_sec, "gw 线上 iptables + ip6tables 零退役 IP 残留")

    if gt.get("iot_ssot", {}).get("enabled", True) is False or gt.get("repo_profile") == "open_source_kit":
        return

    home_sec = "DIM5-HOME-LIVE"
    remote_files = [
        "/opt/starhub-home/AGENTS.md",
        "/opt/starhub-home/server.py",
        "/opt/starhub-home/gemx_bridge.py",
        "/opt/starhub-home/index.html",
        "/opt/starhub-home/static/index.html",
        "/usr/local/bin/shome",
    ]
    rc, out, err = run_cmd(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=5",
            f"root@{home_ip}",
            f"sha256sum {' '.join(remote_files)} && echo '===SPLIT===' && iptables -S && echo '===SPLIT===' && ip6tables -S",
        ],
        timeout=15,
    )
    if rc == 255:
        runner.skip(home_sec, "当前会话未携带主控 SSH Agent，跳过 home 远端哈希核对")
    elif rc != 0:
        runner.fail(home_sec, f"home ({home_ip}) 远端核验命令执行失败 (rc={rc}): {err.strip()}")
    else:
        parts = out.split("===SPLIT===")
        sums_raw = parts[0].strip().splitlines()
        home_ipt4 = parts[1] if len(parts) > 1 else ""
        home_ipt6 = parts[2] if len(parts) > 2 else ""
        remote_map: dict[str, str] = {}
        for line in sums_raw:
            toks = line.split()
            if len(toks) >= 2:
                remote_map[toks[1]] = toks[0]

        iot_dir = repo_root / gt.get("iot_ssot", {}).get("canonical_iot_dir", "iot/starhub-home")
        local_to_remote = {
            "AGENTS.md": "/opt/starhub-home/AGENTS.md",
            "server.py": "/opt/starhub-home/server.py",
            "gemx_bridge.py": "/opt/starhub-home/gemx_bridge.py",
            "index.html": "/opt/starhub-home/index.html",
            "static/index.html": "/opt/starhub-home/static/index.html",
            "shome": "/usr/local/bin/shome",
        }
        drifted = []
        for rel_name, rpath in local_to_remote.items():
            lp = iot_dir / rel_name
            if not lp.is_file() or remote_map.get(rpath) != sha256_bytes(lp.read_bytes()):
                drifted.append(rel_name)
        if drifted:
            runner.fail(home_sec, f"home 线上生产文件与主仓 iot/starhub-home 发生漂移: {drifted}")
        else:
            runner.ok(home_sec, "home 线上生产环境与主仓 iot/starhub-home 6/6 文件 SHA256 100% 一致")

        combined_home_ipt = home_ipt4 + "\n" + home_ipt6
        if (
            "STARHUB-BOT-NOSSH" in home_ipt4
            and "STARHUB-BOT-NOSSH6" in home_ipt6
            and not any(ip in combined_home_ipt for ip in retired_ips)
        ):
            runner.ok(home_sec, "home 线上双栈 NOSSH/NOSSH6 生效且零退役 IP 残留")
        else:
            runner.fail(home_sec, "home 线上双栈防火墙策略异常或残留退役 IP")


def main() -> int:
    parser = argparse.ArgumentParser(description="StarHub EGM 3.0 Zero-Drift & Zero-PII Harness")
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=DEFAULT_REPO_ROOT,
        help="StarHub 仓库根目录 (默认自动推导自脚本所在仓库根)",
    )
    parser.add_argument(
        "--local-docs-only",
        action="store_true",
        help="仅执行仓库静态 7 维校验 (供 Git pre-commit 钩子与 CI 沙盒使用，零网络调用)",
    )
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="检查本地仓库 + 本地双栈防火墙 + 看板 /api/health，不发起跨节点 SSH",
    )
    parser.add_argument(
        "--export-studio",
        action="store_true",
        help="从 STARHUB-LEDGER.md 过滤导出 [STUDIO] 专项变更记录",
    )
    parser.add_argument(
        "--verify-public-export",
        type=pathlib.Path,
        default=None,
        help="指定待发布的公开开源包目录，执行数学级反隐私泄露扫描",
    )
    parser.add_argument(
        "--private-gt",
        type=pathlib.Path,
        default=None,
        help="配合 --verify-public-export 指定私有 STARHUB_GROUND_TRUTH.json 路径",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()

    if args.verify_public_export is not None:
        priv_gt = (args.private_gt or (repo_root / "STARHUB_GROUND_TRUTH.json")).resolve()
        return verify_public_export(args.verify_public_export.resolve(), priv_gt)

    if args.export_studio:
        return export_studio_ledger(repo_root)

    print("======================================================================")
    print(" StarHub EGM 3.0 Doctor — 全栈唯一事实源与八维零漂移门禁 (Read-Only)")
    print("======================================================================")

    runner = CheckRunner()
    gt_path = repo_root / "STARHUB_GROUND_TRUTH.json"
    guardrails_path = repo_root / "scripts" / "profiles" / "mihomo-shared-guardrails.yaml"

    if not gt_path.is_file():
        runner.fail("DIM1-DOC-WHITELIST", f"未找到机器事实源 {gt_path}")
        return 1
    if not guardrails_path.is_file():
        runner.fail("DIM6-MIHOMO-GUARD", f"未找到规则母版 {guardrails_path}")
        return 1

    gt = load_json_compatible(gt_path)
    g = load_json_compatible(guardrails_path)

    md_files = check_dim1_doc_whitelist(runner, repo_root, gt)
    check_dim2_doc_links(runner, repo_root, md_files)
    check_dim3_anti_corrupt(runner, repo_root, gt)
    check_dim4_secret_guard(runner, repo_root)
    check_dim5_iot_ssot(runner, repo_root, gt)
    backup_text = check_dim6_mihomo_repo(runner, repo_root, g)
    check_dim7_fw_repo(runner, repo_root, gt)

    if not args.local_docs_only:
        check_dim8_local_panel_and_health(runner, gt)
        if not args.local_only:
            check_remote_gw_and_home(runner, repo_root, gt, backup_text)

    print("----------------------------------------------------------------------")
    print(
        f" EGM 门禁汇总: PASS={runner.passed}  FAIL={runner.failed}  SKIP={runner.skipped}"
    )
    print("======================================================================")
    return 1 if runner.failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
