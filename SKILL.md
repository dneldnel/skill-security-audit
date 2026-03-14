---
name: skill-security-audit
description: Audit a OpenClaw skill directory for likely security risks before install or update. Use when reviewing third-party skills, unpacked ClawHub installs, local skill folders, or any skill that may read secrets, execute shell commands, persist on the host, or exfiltrate data.
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡️",
        "requires": { "bins": ["python3"] },
        "install":
          [
            {
              "id": "bundled",
              "kind": "bundled",
              "label": "Bundled with workspace/repo",
            },
          ],
      },
  }
---

# Skill Security Audit

## Purpose

Review a skill directory before it is installed into `<workspace>/skills` or `~/.openclaw/skills`.

This skill is a static auditor. It is good at surfacing suspicious patterns and installation risk. It is not a proof that a skill is safe.

## When to use

- Before installing a third-party skill from ClawHub or git
- Before updating an already-installed skill to a new version
- When a skill contains scripts, package managers, downloads, or network calls
- When you want a risk score plus concrete evidence with file paths

## Core workflow

1. Get the target skill into a temporary local directory first.
2. Run the scanner on that directory.
3. Review the findings, not just the score.
4. Only move/install the skill if the result is acceptable for the user's risk tolerance.

## Quick start

Scan a local unpacked skill directory:

```bash
python3 {baseDir}/scripts/scan_skill.py /path/to/skill
```

JSON output:

```bash
python3 {baseDir}/scripts/scan_skill.py /path/to/skill --format json
```

Fail the workflow on medium-or-higher risk:

```bash
python3 {baseDir}/scripts/scan_skill.py /path/to/skill --min-fail-level medium
```

## Interpretation

- `low`: weak signal or expected tooling pattern; still review
- `medium`: meaningful risk; do not auto-install without approval
- `high`: likely dangerous or inconsistent with a normal skill; block by default
- `critical`: clear host compromise or secret-exfiltration indicators; reject

Prefer the highest-severity finding over the total score if they disagree.

## What this scanner looks for

- Shell execution and downloaded-code execution
- Secret access and sensitive path reads
- Persistence or startup modification
- Network exfiltration and suspicious endpoints
- Obfuscation, long base64 blobs, dynamic eval
- Package manager lifecycle scripts
- Documentation/behavior mismatch hints

Read [references/rules.md](references/rules.md) when you need the exact rule families and limitations.

## Recommended install gate

Do not let normal agents call `clawhub install <name>` directly for unreviewed skills.

Preferred flow:

1. Install/download to a temporary directory
2. Run this scanner
3. Show findings to the user
4. Install into the real skills directory only after approval

Read [references/install-gate.md](references/install-gate.md) for the recommended wrapper flow and "installer agent" design.
