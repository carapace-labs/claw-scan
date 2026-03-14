import { readFileSync, statSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

// Patterns that look like API keys/tokens/secrets
const SECRET_PATTERNS = [
  { name: "OpenAI API Key", pattern: /sk-[a-zA-Z0-9]{20,}/ },
  { name: "Anthropic API Key", pattern: /sk-ant-[a-zA-Z0-9-]{20,}/ },
  { name: "Stripe Secret Key", pattern: /sk_(live|test)_[a-zA-Z0-9]{20,}/ },
  { name: "Twilio Account SID", pattern: /AC[a-f0-9]{32}/ },
  { name: "Twilio Auth Token", pattern: /["\'][a-f0-9]{32}["\']/ },
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/ },
  { name: "GitHub Token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/ },
  { name: "Generic API Key", pattern: /["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']/ },
  { name: "Generic Secret", pattern: /["\']?secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']/ },
  { name: "Bearer Token (long)", pattern: /[a-zA-Z0-9_\-]{40,}/ },
];

// Known malicious skills from ClawHavoc campaign and Snyk/Koi research
let MALICIOUS_SKILLS = [];
try {
  const dataPath = new URL("../data/malicious-skills.json", import.meta.url);
  MALICIOUS_SKILLS = JSON.parse(readFileSync(dataPath, "utf8"));
} catch {
  // Blocklist not available, skip that check
}

export function scan(openclawDir) {
  const findings = [];
  const passed = [];

  // 1. Check gateway binding
  checkGatewayBinding(openclawDir, findings, passed);

  // 2. Check gateway auth mode
  checkGatewayAuth(openclawDir, findings, passed);

  // 3. Check for plaintext secrets in config
  checkPlaintextSecrets(openclawDir, findings, passed);

  // 4. Check file permissions
  checkFilePermissions(openclawDir, findings, passed);

  // 5. Check exec approvals mode
  checkExecApprovals(openclawDir, findings, passed);

  // 6. Check workspace isolation
  checkWorkspaceIsolation(openclawDir, findings, passed);

  // 7. Check tool deny list
  checkToolDenyList(openclawDir, findings, passed);

  // 8. Check for malicious skills
  checkMaliciousSkills(openclawDir, findings, passed);

  // 9. Check plugin integrity hashes
  checkPluginIntegrity(openclawDir, findings, passed);

  // 10. Check paired devices
  checkPairedDevices(openclawDir, findings, passed);

  // 11. Check cron jobs
  checkCronJobs(openclawDir, findings, passed);

  // 12. Check backup files with secrets
  checkBackupFiles(openclawDir, findings, passed);

  // 13. Check session logs for leaked secrets
  checkSessionLogs(openclawDir, findings, passed);

  // 14. Check .env file
  checkEnvFile(openclawDir, findings, passed);

  const summary = {
    total: findings.length + passed.length,
    passed: passed.length,
    critical: findings.filter((f) => f.severity === "CRITICAL").length,
    high: findings.filter((f) => f.severity === "HIGH").length,
    medium: findings.filter((f) => f.severity === "MEDIUM").length,
  };

  // Sort: critical first, then high, then medium
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  return { findings, passed, summary };
}

function loadConfig(openclawDir) {
  const configPath = join(openclawDir, "openclaw.json");
  if (!existsSync(configPath)) return null;
  try {
    return JSON.parse(readFileSync(configPath, "utf8"));
  } catch {
    return null;
  }
}

function checkGatewayBinding(dir, findings, passed) {
  const config = loadConfig(dir);
  if (!config?.gateway) return;

  const bind = config.gateway.bind || "loopback";
  if (bind === "wildcard" || bind === "0.0.0.0") {
    findings.push({
      severity: "CRITICAL",
      title: `Gateway bound to ${bind} (exposed to network)`,
      detail: `Port ${config.gateway.port || 18789} is accessible from any interface. 21,000+ OpenClaw instances were found exposed this way.`,
      fix: `Set "bind": "loopback" in ${join(dir, "openclaw.json")}`,
    });
  } else {
    passed.push("Gateway bound to loopback (not exposed)");
  }
}

function checkGatewayAuth(dir, findings, passed) {
  const config = loadConfig(dir);
  if (!config?.gateway?.auth) return;

  const mode = config.gateway.auth.mode;
  if (mode === "none") {
    findings.push({
      severity: "CRITICAL",
      title: "Gateway authentication disabled",
      detail: "Anyone with network access can control your agent.",
      fix: `Set "auth": { "mode": "token" } in ${join(dir, "openclaw.json")}`,
    });
  } else {
    passed.push(`Gateway auth: ${mode} mode`);
  }
}

function checkPlaintextSecrets(dir, findings, passed) {
  const configPath = join(dir, "openclaw.json");
  if (!existsSync(configPath)) return;

  const raw = readFileSync(configPath, "utf8");
  const secretsFound = [];

  // Check for known patterns
  for (const { name, pattern } of SECRET_PATTERNS) {
    // Skip the generic bearer token check on the whole config (too noisy)
    if (name === "Bearer Token (long)") continue;

    if (pattern.test(raw)) {
      secretsFound.push(name);
    }
  }

  // Check plugin configs for inline credentials
  const config = loadConfig(dir);
  if (config?.plugins?.entries) {
    for (const [pluginName, entry] of Object.entries(config.plugins.entries)) {
      const configStr = JSON.stringify(entry.config || {});
      for (const { name, pattern } of SECRET_PATTERNS) {
        if (name === "Bearer Token (long)") continue;
        if (pattern.test(configStr)) {
          secretsFound.push(`${name} in plugin "${pluginName}"`);
        }
      }
    }
  }

  // Check gateway token (always plaintext in config)
  if (config?.gateway?.auth?.token) {
    secretsFound.push("Gateway auth token");
  }

  if (secretsFound.length > 0) {
    findings.push({
      severity: "CRITICAL",
      title: `${secretsFound.length} plaintext secret(s) in openclaw.json`,
      detail: secretsFound.join(", "),
      fix: "Move secrets to environment variables or use psst: npm i -g psst-cli && psst init --global",
    });
  } else {
    passed.push("No plaintext secrets detected in config");
  }
}

function checkFilePermissions(dir, findings, passed) {
  const sensitiveFiles = [
    "openclaw.json",
    "agents/main/agent/auth-profiles.json",
    "identity/device.json",
    "identity/device-auth.json",
    "devices/paired.json",
  ];

  const loose = [];
  for (const rel of sensitiveFiles) {
    const full = join(dir, rel);
    if (!existsSync(full)) continue;
    try {
      const stat = statSync(full);
      const mode = (stat.mode & 0o777).toString(8);
      if (mode !== "600") {
        loose.push(`${rel} (${mode})`);
      }
    } catch {
      // skip
    }
  }

  if (loose.length > 0) {
    findings.push({
      severity: "HIGH",
      title: `${loose.length} sensitive file(s) with loose permissions`,
      detail: loose.join(", "),
      fix: `chmod 600 ${loose.map((f) => join(dir, f.split(" ")[0])).join(" ")}`,
    });
  } else {
    passed.push("File permissions: 600 on sensitive files");
  }
}

function checkExecApprovals(dir, findings, passed) {
  const path = join(dir, "exec-approvals.json");
  if (!existsSync(path)) {
    findings.push({
      severity: "HIGH",
      title: "No exec-approvals.json found",
      detail: "Agent may execute arbitrary commands without approval.",
      fix: `Create ${path} with {"version":1,"defaults":{"security":"allowlist","ask":"on-miss","askFallback":"deny"}}`,
    });
    return;
  }
  try {
    const data = JSON.parse(readFileSync(path, "utf8"));
    if (data.defaults?.security === "allowlist") {
      passed.push("Exec approvals: allowlist mode");
    } else {
      findings.push({
        severity: "HIGH",
        title: `Exec approvals set to "${data.defaults?.security}" (not allowlist)`,
        detail: "Agent can execute commands without explicit approval.",
        fix: `Set "security": "allowlist" in ${path}`,
      });
    }
  } catch {
    findings.push({
      severity: "MEDIUM",
      title: "exec-approvals.json is malformed",
      detail: "Could not parse the file.",
    });
  }
}

function checkWorkspaceIsolation(dir, findings, passed) {
  const config = loadConfig(dir);
  if (!config?.tools?.fs) return;

  if (config.tools.fs.workspaceOnly) {
    passed.push("Workspace isolation: enabled");
  } else {
    findings.push({
      severity: "HIGH",
      title: "Workspace isolation disabled",
      detail: "Agent can read/write files outside its workspace, including ~/.ssh, ~/.aws, etc.",
      fix: `Set "tools": { "fs": { "workspaceOnly": true } } in ${join(dir, "openclaw.json")}`,
    });
  }
}

function checkToolDenyList(dir, findings, passed) {
  const config = loadConfig(dir);
  const deny = config?.tools?.deny || [];
  const recommended = ["gateway", "cron", "sessions_spawn", "sessions_send"];
  const missing = recommended.filter((t) => !deny.includes(t));

  if (missing.length === 0) {
    passed.push("Tool deny list: sensitive tools blocked");
  } else {
    findings.push({
      severity: "MEDIUM",
      title: `${missing.length} sensitive tool(s) not in deny list`,
      detail: `Missing: ${missing.join(", ")}. Agent could modify gateway config or spawn uncontrolled sessions.`,
      fix: `Add ${JSON.stringify(missing)} to "tools.deny" in ${join(dir, "openclaw.json")}`,
    });
  }
}

function checkMaliciousSkills(dir, findings, passed) {
  if (MALICIOUS_SKILLS.length === 0) {
    // No blocklist available
    return;
  }

  const config = loadConfig(dir);
  const installs = config?.plugins?.installs || {};
  const installed = Object.keys(installs);
  const malicious = installed.filter((name) =>
    MALICIOUS_SKILLS.some((m) => name.includes(m.name) || m.name.includes(name))
  );

  if (malicious.length > 0) {
    findings.push({
      severity: "CRITICAL",
      title: `${malicious.length} known malicious skill(s) installed`,
      detail: malicious.join(", "),
      fix: malicious.map((m) => `openclaw plugin uninstall ${m}`).join(" && "),
    });
  } else {
    passed.push("No known malicious skills detected");
  }
}

function checkPluginIntegrity(dir, findings, passed) {
  const config = loadConfig(dir);
  const installs = config?.plugins?.installs || {};
  const noIntegrity = [];

  for (const [name, info] of Object.entries(installs)) {
    if (!info.integrity && !info.shasum) {
      noIntegrity.push(name);
    }
  }

  if (Object.keys(installs).length === 0) return;

  if (noIntegrity.length > 0) {
    findings.push({
      severity: "HIGH",
      title: `${noIntegrity.length} plugin(s) without integrity hash`,
      detail: `${noIntegrity.join(", ")} — cannot verify these haven't been tampered with.`,
      fix: "Reinstall plugins to generate integrity hashes.",
    });
  } else {
    passed.push("Plugin integrity: all hashes present");
  }
}

function checkPairedDevices(dir, findings, passed) {
  const path = join(dir, "devices/paired.json");
  if (!existsSync(path)) return;

  try {
    const data = JSON.parse(readFileSync(path, "utf8"));
    const devices = Object.values(data);
    if (devices.length === 0) {
      passed.push("No paired devices");
      return;
    }

    const adminDevices = devices.filter((d) =>
      d.approvedScopes?.includes("operator.admin")
    );

    if (adminDevices.length > 2) {
      findings.push({
        severity: "HIGH",
        title: `${adminDevices.length} devices with operator.admin scope`,
        detail: "Review paired devices — each is a full-access entry point.",
        fix: `Review ${path} and remove untrusted devices.`,
      });
    } else if (devices.length > 0) {
      passed.push(`${devices.length} paired device(s) (review periodically)`);
    }
  } catch {
    // skip
  }
}

function checkCronJobs(dir, findings, passed) {
  const path = join(dir, "cron/jobs.json");
  if (!existsSync(path)) return;

  try {
    const data = JSON.parse(readFileSync(path, "utf8"));
    const jobs = data.jobs || [];
    if (jobs.length === 0) {
      passed.push("No cron jobs configured");
      return;
    }

    // Flag any jobs that run shell commands
    const shellJobs = jobs.filter((j) => {
      const msg = j.payload?.message || "";
      return msg.includes("bash") || msg.includes("sh ") || msg.includes("python") || msg.includes("node ");
    });

    if (shellJobs.length > 0) {
      findings.push({
        severity: "MEDIUM",
        title: `${shellJobs.length} cron job(s) execute shell commands`,
        detail: shellJobs.map((j) => j.name).join(", "),
        fix: "Review cron jobs — they run with agent permissions.",
      });
    } else {
      passed.push(`${jobs.length} cron job(s) (no shell execution)`);
    }
  } catch {
    // skip
  }
}

function checkBackupFiles(dir, findings, passed) {
  const backups = [];
  try {
    const files = readdirSync(dir);
    for (const f of files) {
      if (f.endsWith(".bak") || f.match(/\.bak\.\d+$/)) {
        const full = join(dir, f);
        const content = readFileSync(full, "utf8");
        // Check if backup contains secrets
        for (const { name, pattern } of SECRET_PATTERNS) {
          if (name === "Bearer Token (long)") continue;
          if (pattern.test(content)) {
            backups.push(f);
            break;
          }
        }
      }
    }
  } catch {
    // skip
  }

  if (backups.length > 0) {
    findings.push({
      severity: "HIGH",
      title: `${backups.length} backup file(s) contain secrets`,
      detail: backups.join(", "),
      fix: `rm ${backups.map((b) => join(dir, b)).join(" ")}`,
    });
  }
}

function checkSessionLogs(dir, findings, passed) {
  const sessionsDir = join(dir, "agents/main/sessions");
  if (!existsSync(sessionsDir)) return;

  try {
    const files = readdirSync(sessionsDir).filter((f) => f.endsWith(".jsonl"));
    let leakyFiles = 0;

    for (const f of files.slice(-5)) {
      // Check only recent sessions
      const content = readFileSync(join(sessionsDir, f), "utf8");
      for (const { name, pattern } of SECRET_PATTERNS) {
        if (name === "Bearer Token (long)" || name === "Generic Secret" || name === "Generic API Key") continue;
        if (pattern.test(content)) {
          leakyFiles++;
          break;
        }
      }
    }

    if (leakyFiles > 0) {
      findings.push({
        severity: "MEDIUM",
        title: `${leakyFiles} recent session log(s) may contain secrets`,
        detail: "Session JSONL files can capture API keys from tool outputs.",
        fix: "Rotate exposed credentials. Consider psst to prevent future leaks.",
      });
    }
  } catch {
    // skip
  }
}

function checkEnvFile(dir, findings, passed) {
  const envPath = join(dir, ".env");
  if (!existsSync(envPath)) return;

  const content = readFileSync(envPath, "utf8");
  const lines = content.split("\n").filter((l) => l.includes("=") && !l.startsWith("#"));

  if (lines.length > 0) {
    findings.push({
      severity: "HIGH",
      title: `${lines.length} secret(s) in .env file`,
      detail: "Plaintext .env in OpenClaw directory.",
      fix: `psst import ${envPath} && rm ${envPath}`,
    });
  }
}
