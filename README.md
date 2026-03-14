# claw-scan

Security scanner for OpenClaw installations.

**Your current security? `.gitignore` and hope.**

## The problem

- [135,000+ OpenClaw instances](https://www.theregister.com/2026/02/05/openclaw_skills_marketplace_leaky_security/) exposed on the public internet
- [12% of marketplace skills](https://blog.cyberdesserts.com/openclaw-malicious-skills-security/) confirmed malicious (ClawHavoc campaign)
- [7% of skills](https://www.theregister.com/2026/02/05/openclaw_skills_marketplace_leaky_security/) leak credentials in plaintext
- Credentials stored in plaintext JSON and Markdown files
- [CVE-2026-25253](https://www.darkreading.com/application-security/critical-openclaw-vulnerability-ai-agent-risks): one-click RCE via malicious webpage

## Install

```bash
npx claw-scan
```

Or install globally:

```bash
npm install -g claw-scan
claw-scan
```

## What it checks

| Check | Severity | What it catches |
|-------|----------|-----------------|
| Gateway binding | CRITICAL | Exposed to network (0.0.0.0) |
| Gateway auth | CRITICAL | Authentication disabled |
| Plaintext secrets | CRITICAL | API keys, tokens in openclaw.json |
| Malicious skills | CRITICAL | Known ClawHavoc/Atomic Stealer skills |
| File permissions | HIGH | Sensitive files readable by others |
| Exec approvals | HIGH | Arbitrary command execution allowed |
| Workspace isolation | HIGH | Agent can read your whole filesystem |
| Plugin integrity | HIGH | Missing verification hashes |
| Paired devices | HIGH | Unexpected admin-level devices |
| Backup files | HIGH | Old configs with plaintext secrets |
| .env exposure | HIGH | Plaintext secrets in .env |
| Tool deny list | MEDIUM | Sensitive tools not blocked |
| Cron jobs | MEDIUM | Scheduled shell command execution |
| Session logs | MEDIUM | API keys captured in session history |

## Output

```
claw-scan v0.1.0

  ✗ CRITICAL  3 plaintext secret(s) in openclaw.json
    Gateway auth token, Twilio Account SID, Twilio Auth Token in plugin "voice-call"
    Fix: Move secrets to environment variables or use psst: npm i -g psst-cli && psst init --global

  ! HIGH      4 backup file(s) contain secrets
    openclaw.json.bak, openclaw.json.bak.1, openclaw.json.bak.2, openclaw.json.bak.3
    Fix: rm ~/.openclaw/openclaw.json.bak*

  ✓ OK        Gateway bound to loopback (not exposed)
  ✓ OK        Gateway auth: token mode
  ✓ OK        Exec approvals: allowlist mode
  ✓ OK        Workspace isolation: enabled
  ✓ OK        File permissions: 600 on sensitive files

Score: 7/14 passed | 1 critical | 1 high | 0 medium
```

## Options

```
claw-scan                  Scan default ~/.openclaw/
claw-scan --path <dir>     Scan specific OpenClaw directory
claw-scan --json           Output as JSON (for CI/scripts)
claw-scan --fix            Show copy-pasteable fix commands
```

## Exit codes

- `0` — All checks passed
- `1` — High severity findings
- `2` — Critical severity findings

## Fixing findings

claw-scan recommends [psst](https://github.com/Michaelliv/psst) for secrets management:

```bash
# Install psst
npm install -g psst-cli

# Move secrets to encrypted vault
psst init --global
psst set TWILIO_AUTH_TOKEN
psst set OPENAI_API_KEY

# Run commands with injected secrets (agent never sees them)
psst TWILIO_AUTH_TOKEN -- curl -u "$TWILIO_AUTH_TOKEN" https://api.twilio.com

# Protect Claude Code sessions
psst install-hooks
```

## Contributing

Found a malicious skill? Open an issue or PR to add it to `data/malicious-skills.json`.

## License

MIT

---

Built by [Carapace Labs](https://github.com/carapace-labs) — security tools for AI agent deployments.
