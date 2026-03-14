#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_SCORES = {
    "low": 8,
    "medium": 20,
    "high": 35,
    "critical": 60,
}

TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".json",
    ".json5",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".swift",
    ".php",
    ".ps1",
    ".env",
    ".lock",
}


@dataclass
class Finding:
    severity: str
    category: str
    rule_id: str
    file: str
    line: int | None
    evidence: str
    message: str


RULES: list[tuple[str, str, str, re.Pattern[str], str]] = [
    (
        "high",
        "code-exec",
        "shell-exec",
        re.compile(r"\b(os\.system|subprocess\.(Popen|run|call|check_output)|child_process\.(exec|spawn))"),
        "Found direct shell or process execution.",
    ),
    (
        "critical",
        "code-exec",
        "download-exec-pipe",
        re.compile(r"(curl|wget)[^\n|]{0,120}\|\s*(bash|sh|zsh)"),
        "Found downloaded code piped directly into a shell.",
    ),
    (
        "high",
        "code-exec",
        "shell-inline",
        re.compile(r"\b(bash|sh|zsh)\s+-c\b"),
        "Found inline shell execution.",
    ),
    (
        "high",
        "secrets",
        "sensitive-paths",
        re.compile(r"(\.ssh|\.gnupg|id_rsa|authorized_keys|keychain|wallet|mnemonic|private[_ -]?key|seed phrase|aws_access_key_id|BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY)"),
        "Found references to sensitive credentials or key material.",
    ),
    (
        "high",
        "persistence",
        "startup-persistence",
        re.compile(r"(LaunchAgents|launchctl\s+(bootstrap|load)|systemctl\s+enable|crontab\b|/etc/cron|\.zshrc|\.bashrc|\.profile)"),
        "Found persistence or shell profile modification patterns.",
    ),
    (
        "high",
        "network",
        "network-exfil",
        re.compile(r"\b(requests\.(post|put)|fetch\(|axios\.(post|put)|curl\s+-[A-Za-z]*[dFX]|wget\s+https?://|urllib\.request|httpx\.(post|put))"),
        "Found active outbound network call patterns.",
    ),
    (
        "critical",
        "network",
        "webhook-exfil",
        re.compile(r"(discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|pastebin|transfer\.sh|ngrok)"),
        "Found suspicious webhook or easy-exfil endpoint references.",
    ),
    (
        "medium",
        "obfuscation",
        "dynamic-eval",
        re.compile(r"\b(eval\(|new Function\(|Function\(|exec\()"),
        "Found dynamic code execution primitives.",
    ),
    (
        "medium",
        "obfuscation",
        "base64-decode",
        re.compile(r"(base64\.b64decode|Buffer\.from\([^)]*base64|atob\()"),
        "Found runtime decoding patterns often used to hide payloads.",
    ),
]

DOC_SUFFIXES = {".md", ".txt"}
DOC_RULE_IDS = {"download-exec-pipe"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Static security scanner for OpenClaw skill directories."
    )
    parser.add_argument("target", help="Path to an unpacked skill directory")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--min-fail-level",
        choices=tuple(SEVERITY_ORDER.keys()),
        default=None,
        help="Exit non-zero when findings meet or exceed this severity",
    )
    return parser.parse_args()


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    if path.name in {"SKILL.md", "HOOK.md", "package.json"}:
        return True
    return False


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", "node_modules", "__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        yield path


def safe_read(path: Path) -> str | None:
    try:
        raw = path.read_text(encoding="utf-8")
        return raw
    except UnicodeDecodeError:
        return None
    except OSError:
        return None


def shorten(text: str, limit: int = 140) -> str:
    squashed = " ".join(text.strip().split())
    return squashed[: limit - 1] + "…" if len(squashed) > limit else squashed


def scan_text_file(root: Path, path: Path, findings: list[Finding]) -> None:
    text = safe_read(path)
    if text is None:
        return

    rel = str(path.relative_to(root))
    allowed_rule_ids: set[str] | None = None
    if path.suffix.lower() in DOC_SUFFIXES:
        allowed_rule_ids = DOC_RULE_IDS
    for severity, category, rule_id, pattern, message in RULES:
        if allowed_rule_ids is not None and rule_id not in allowed_rule_ids:
            continue
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    severity=severity,
                    category=category,
                    rule_id=rule_id,
                    file=rel,
                    line=line,
                    evidence=shorten(match.group(0)),
                    message=message,
                )
            )

    long_base64 = re.search(r"[A-Za-z0-9+/]{180,}={0,2}", text)
    if long_base64 and allowed_rule_ids is None:
        findings.append(
            Finding(
                severity="medium",
                category="obfuscation",
                rule_id="long-base64-blob",
                file=rel,
                line=text.count("\n", 0, long_base64.start()) + 1,
                evidence=shorten(long_base64.group(0), 100),
                message="Found a long base64-like blob that may hide payload content.",
            )
        )

    if path.name == "package.json":
        scan_package_json(rel, text, findings)


def scan_package_json(rel: str, text: str, findings: list[Finding]) -> None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        findings.append(
            Finding(
                severity="medium",
                category="metadata",
                rule_id="package-json-invalid",
                file=rel,
                line=None,
                evidence="package.json",
                message="Invalid package.json; cannot verify lifecycle scripts safely.",
            )
        )
        return

    if not isinstance(payload, dict):
        return

    scripts = payload.get("scripts")
    if isinstance(scripts, dict):
        for key in ("preinstall", "install", "postinstall", "prepare"):
            value = scripts.get(key)
            if isinstance(value, str) and value.strip():
                findings.append(
                    Finding(
                        severity="high",
                        category="install-time",
                        rule_id=f"npm-{key}",
                        file=rel,
                        line=None,
                        evidence=shorten(value),
                        message=f"Found npm lifecycle script '{key}', which may execute during install.",
                    )
                )


def summarize(findings: list[Finding]) -> dict[str, object]:
    counts = {level: 0 for level in SEVERITY_ORDER}
    categories: dict[str, int] = {}
    score = 0
    max_level = "low"

    for finding in findings:
        counts[finding.severity] += 1
        categories[finding.category] = categories.get(finding.category, 0) + 1
        score += SEVERITY_SCORES[finding.severity]
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[max_level]:
            max_level = finding.severity

    if not findings:
        verdict = "low"
        score = 0
    elif counts["critical"] > 0:
        verdict = "critical"
    elif counts["high"] > 0 or score >= 60:
        verdict = "high"
    elif counts["medium"] > 0 or score >= 20:
        verdict = "medium"
    else:
        verdict = "low"

    return {
        "verdict": verdict,
        "score": min(score, 100),
        "maxSeverity": max_level if findings else "none",
        "counts": counts,
        "categories": categories,
    }


def format_text(target: Path, summary: dict[str, object], findings: list[Finding]) -> str:
    lines = [
        f"Target: {target}",
        f"Verdict: {summary['verdict']}",
        f"Score: {summary['score']}",
        f"Counts: critical={summary['counts']['critical']} high={summary['counts']['high']} medium={summary['counts']['medium']} low={summary['counts']['low']}",
    ]
    if not findings:
        lines.append("No rule hits found.")
        return "\n".join(lines)

    lines.append("Findings:")
    ordered = sorted(
        findings,
        key=lambda item: (-SEVERITY_ORDER[item.severity], item.file, item.line or 0, item.rule_id),
    )
    for finding in ordered:
        location = finding.file if finding.line is None else f"{finding.file}:{finding.line}"
        lines.append(
            f"- [{finding.severity}] {finding.category} {location} {finding.rule_id}: {finding.message} Evidence: {finding.evidence}"
        )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    target = Path(os.path.expanduser(args.target)).resolve()
    if not target.exists():
        print(f"Target does not exist: {target}", file=sys.stderr)
        return 2
    if not target.is_dir():
        print(f"Target is not a directory: {target}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for path in iter_files(target):
        if not is_text_file(path):
            continue
        scan_text_file(target, path, findings)

    summary = summarize(findings)
    payload = {
        "target": str(target),
        "summary": summary,
        "findings": [asdict(item) for item in findings],
    }

    if args.format == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(format_text(target, summary, findings))

    if args.min_fail_level:
        threshold = SEVERITY_ORDER[args.min_fail_level]
        hit = any(SEVERITY_ORDER[item.severity] >= threshold for item in findings)
        if hit:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
