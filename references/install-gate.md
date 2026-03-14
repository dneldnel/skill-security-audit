# Install Gate

## Recommended pattern

Use this auditor as part of a forced install workflow, not as an optional afterthought.

The cleanest pattern is:

1. A dedicated installer agent handles all third-party skill installs
2. That agent always downloads to a temporary directory first
3. It runs `scan_skill.py`
4. It only installs into the real skills directory after approval

## Why this is better than a normal agent

- It centralizes policy
- It avoids direct `clawhub install <name>` into production skills folders
- It creates one audit trail for approvals and rejects

## Wrapper flow

Example flow:

```text
request install
-> resolve source and version
-> install/download to /tmp/openclaw-skill-review/<skill>
-> run scan_skill.py
-> show findings and score
-> require explicit approval for medium/high risk
-> move into <workspace>/skills or ~/.openclaw/skills
-> record source/version/hash/decision
```

## Suggested command pattern

If using `clawhub`, prefer overriding the destination/workdir so the initial download is isolated:

```bash
clawhub install <skill> --dir /tmp/openclaw-skill-review/skills
python3 /path/to/scan_skill.py /tmp/openclaw-skill-review/skills/<skill> --min-fail-level medium
```

Only after review should the files be copied or moved to the real target directory.

## Policy recommendation

- `critical`: reject automatically
- `high`: reject by default; only allow with explicit override
- `medium`: require manual approval
- `low`: allow, but still show findings

## Future hardening

If you later want stronger guarantees, add:

- a hash allowlist for approved skills
- rescans on update
- periodic rescans of installed skills
- dynamic execution in a sandbox with blocked network egress
- an approval log stored alongside skill metadata
