# Rules

This skill is an install-time static auditor for OpenClaw skills.

## Risk families

### 1. Code execution

Examples:

- `os.system(...)`
- `subprocess.Popen(...)`
- `child_process.exec(...)`
- `bash -c`
- `curl ... | bash`
- `wget ... | sh`

Why it matters:

- Skills often run as the same user as OpenClaw.
- Shell execution can pivot into arbitrary host access.

### 2. Secret and identity access

Examples:

- `~/.ssh`
- `~/.gnupg`
- `.env`
- `id_rsa`
- `mnemonic`
- `private key`
- `aws_access_key_id`
- browser cookies / session stores

Why it matters:

- A malicious skill may steal credentials unrelated to its stated purpose.

### 3. Persistence and host modification

Examples:

- `~/Library/LaunchAgents`
- `launchctl bootstrap`
- `systemctl enable`
- `crontab`
- `~/.zshrc`
- `~/.bashrc`

Why it matters:

- A skill should almost never install persistence as part of normal use.

### 4. Network exfiltration

Examples:

- `requests.post(...)`
- `fetch("https://...")`
- Discord webhooks
- Pastebin-like endpoints
- custom upload endpoints

Why it matters:

- Exfiltration is one of the highest-signal malicious behaviors.

### 5. Obfuscation and concealment

Examples:

- `eval(...)`
- `new Function(...)`
- `base64.b64decode(...)` combined with execution
- long base64 or hex blobs
- compressed payload stagers

Why it matters:

- Hidden payloads reduce reviewability and are common in malicious installers.

### 6. Package lifecycle scripts

Examples:

- `preinstall`
- `install`
- `postinstall`
- `prepare`

Why it matters:

- Install-time scripts may execute before the user has reviewed the unpacked files.

## Decision guidance

- `critical`: clear secret theft, persistence, or remote code execution chain
- `high`: strong evidence of dangerous behavior or several medium findings together
- `medium`: suspicious patterns that require manual review
- `low`: weak heuristics, broad APIs, or context-dependent behavior

## Known limits

- Static analysis cannot prove absence of malicious behavior.
- Benign admin or automation skills may legitimately touch shell or network APIs.
- Obfuscated payloads may still evade pattern checks.
- Remote behavior can differ from local source if the package downloads more code later.

Use this skill as a gate, not as an absolute trust oracle.
