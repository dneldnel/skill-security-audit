# Skill Security Audit

Static security auditing for OpenClaw skills before install or update.

This skill helps review third-party or locally developed skills for likely security risks such as:

- malicious shell execution
- downloaded-code execution
- secret or key material access
- data exfiltration
- persistence or startup modification
- obfuscation and hidden payloads
- risky package lifecycle scripts

It is designed as an install-time gate, not as proof that a skill is safe.

## What It Does

`skill-security-audit` scans an unpacked skill directory and produces:

- a verdict: `low`, `medium`, `high`, or `critical`
- a numeric score
- categorized findings
- file paths and line numbers where possible
- evidence snippets for manual review

The scanner is intentionally conservative. It is meant to help you decide whether a skill should be installed, manually reviewed, or rejected.

## Repository Layout

```text
skill-security-audit/
├── README.md
├── SKILL.md
├── references/
│   ├── install-gate.md
│   └── rules.md
└── scripts/
    └── scan_skill.py
```

## Installation

Place this skill where OpenClaw can load it:

- per-agent: `<workspace>/skills/skill-security-audit`
- shared: `~/.openclaw/skills/skill-security-audit`

This skill requires:

- `python3`

## Basic Usage

Scan a local skill directory:

```bash
python3 scripts/scan_skill.py /path/to/skill
```

Get JSON output:

```bash
python3 scripts/scan_skill.py /path/to/skill --format json
```

Exit non-zero when findings are medium or above:

```bash
python3 scripts/scan_skill.py /path/to/skill --min-fail-level medium
```

## Example Output

```text
Target: /tmp/review/my-skill
Verdict: high
Score: 55
Counts: critical=0 high=1 medium=1 low=2
Findings:
- [high] code-exec scripts/install.sh:12 shell-exec: Found direct shell or process execution. Evidence: os.system
```

## Recommended Workflow

Do not install unreviewed third-party skills directly into your live OpenClaw `skills/` directory.

Recommended flow:

1. Download or install the target skill into a temporary directory.
2. Run `scan_skill.py` on the unpacked skill.
3. Review the findings.
4. Only move the skill into the real OpenClaw skills directory after approval.

If you use ClawHub, prefer a wrapper flow that installs to a temporary location first, scans, then promotes the skill into the real target directory only if it passes review.

## Risk Levels

- `low`: weak signal or context-dependent pattern
- `medium`: suspicious enough to require manual review
- `high`: likely dangerous or inconsistent with a normal skill
- `critical`: strong compromise indicators such as secret theft, exfiltration, or install-time execution chains

In practice, the highest-severity finding matters more than the score.

## What It Checks

- shell and process execution
- remote download piped into a shell
- secret and credential access patterns
- persistence and startup modification
- outbound data transfer patterns
- suspicious webhook and exfil endpoints
- dynamic evaluation and runtime decoding
- `package.json` lifecycle scripts such as `preinstall` and `postinstall`

See [references/rules.md](references/rules.md) for the current rule families.

## Limitations

- This is a static scanner.
- It cannot prove a skill is safe.
- It may produce false positives, especially for admin or automation skills.
- It may miss behavior that only appears at runtime or after secondary downloads.

Treat this as a review gate, not as a full sandbox or malware engine.

## Recommended Next Step

For stronger protection, pair this skill with a dedicated installer workflow:

- install to a temp directory
- scan automatically
- require approval for risky findings
- only then copy into `<workspace>/skills` or `~/.openclaw/skills`

The design notes for that flow are in [references/install-gate.md](references/install-gate.md).

## License / Reuse

Adapt freely for your own OpenClaw workflows. If you publish modifications, make the limitations explicit so users do not mistake static scanning for a security guarantee.
