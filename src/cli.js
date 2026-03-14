#!/usr/bin/env node

import { readFileSync, statSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { scan } from "./scanner.js";

const VERSION = "0.1.0";
const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`
claw-scan v${VERSION} — Security scanner for OpenClaw installations

Usage:
  claw-scan                  Scan default ~/.openclaw/
  claw-scan --path <dir>     Scan specific OpenClaw directory
  claw-scan --json           Output results as JSON
  claw-scan --fix            Show fix commands (copy-pasteable)
  claw-scan --version        Show version

https://github.com/carapace-labs/claw-scan
`);
  process.exit(0);
}

if (args.includes("--version") || args.includes("-v")) {
  console.log(`claw-scan v${VERSION}`);
  process.exit(0);
}

const pathIdx = args.indexOf("--path");
const openclawDir = pathIdx !== -1 ? resolve(args[pathIdx + 1]) : join(homedir(), ".openclaw");
const jsonOutput = args.includes("--json");
const showFix = args.includes("--fix");

if (!existsSync(openclawDir)) {
  console.error(`No OpenClaw directory found at ${openclawDir}`);
  console.error("Is OpenClaw installed? Try: claw-scan --path /path/to/.openclaw");
  process.exit(1);
}

const results = scan(openclawDir);
if (jsonOutput) {
  console.log(JSON.stringify(results, null, 2));
} else {
  printReport(results, showFix);
}

process.exit(results.summary.critical > 0 ? 2 : results.summary.high > 0 ? 1 : 0);

function printReport(results, showFix) {
  const RED = "\x1b[31m";
  const YELLOW = "\x1b[33m";
  const GREEN = "\x1b[32m";
  const DIM = "\x1b[2m";
  const BOLD = "\x1b[1m";
  const RESET = "\x1b[0m";

  console.log(`\n${BOLD}claw-scan v${VERSION}${RESET}\n`);

  for (const finding of results.findings) {
    const color =
      finding.severity === "CRITICAL" ? RED :
      finding.severity === "HIGH" ? YELLOW :
      GREEN;
    const icon =
      finding.severity === "CRITICAL" ? "✗" :
      finding.severity === "HIGH" ? "!" :
      "✓";

    console.log(`  ${color}${icon} ${finding.severity}${RESET}  ${finding.title}`);
    if (finding.detail) {
      console.log(`    ${DIM}${finding.detail}${RESET}`);
    }
    if (showFix && finding.fix) {
      console.log(`    ${GREEN}Fix: ${finding.fix}${RESET}`);
    }
    console.log();
  }

  for (const ok of results.passed) {
    console.log(`  ${GREEN}✓ OK${RESET}      ${ok}`);
  }

  console.log();
  const { total, passed, critical, high, medium } = results.summary;
  const scoreColor = critical > 0 ? RED : high > 0 ? YELLOW : GREEN;
  console.log(
    `${scoreColor}${BOLD}Score: ${passed}/${total} passed${RESET}` +
    (critical ? ` | ${RED}${critical} critical${RESET}` : "") +
    (high ? ` | ${YELLOW}${high} high${RESET}` : "") +
    (medium ? ` | ${medium} medium` : "")
  );
  console.log();
}
