#!/usr/bin/env node
/**
 * Fails when a tracked file references an advertising network, a payment or
 * donation provider, the DNS-over-HTTPS fallback once used to reach the ad
 * network, or a spoofed desktop-Chrome User-Agent.
 *
 * This fork removed the ad network and the supporter licence; this guard keeps
 * them from returning unnoticed. Usage: `node scripts/check-no-ads.cjs [root]`.
 */
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

/** Forbidden references, each with the reason it is forbidden. */
const FORBIDDEN = [
  { pattern: /highperformanceformat|effectivecpmnetwork|effectivegatecpm|adsterra/i, reason: 'advertising network host' },
  { pattern: /paypal/i, reason: 'payment provider' },
  { pattern: /trustwallet|link\.trustwallet\.com|buymeacoffee|ko-fi\.com|patreon\.com|opencollective\.com/i, reason: 'donation provider' },
  { pattern: /\b(?:litecoin|bitcoin|ethereum):[a-z0-9]/i, reason: 'cryptocurrency payment URI' },
  { pattern: /cloudflare-dns\.com\/dns-query|dns\.google\/resolve|dns\.google\/dns-query/i, reason: 'DNS-over-HTTPS fallback used to reach blocked ad hosts' },
  { pattern: /Mozilla\/5\.0 \([^)]*\) AppleWebKit\/[\d.]+ \(KHTML, like Gecko\) Chrome\/\d+/, reason: 'spoofed desktop-Chrome User-Agent' },
];

/**
 * Paths that may mention the forbidden references, with the justification for
 * each. Keep this list short: every entry is a place the guard cannot see.
 */
const ALLOWED = new Map([
  // The guard must spell out what it forbids.
  ['scripts/check-no-ads.cjs', 'defines the forbidden patterns'],
  // Release history is append-only; earlier entries describe removed code.
  ['CHANGELOG.md', 'append-only release history'],
  // A dated record of the upstream 4.1.0 candidate's test evidence; editing
  // it would falsify what was run. It carries a historical-record banner.
  ['Docs/RELEASE_READINESS_4.1.0.md', 'historical upstream test evidence'],
]);

/** Lists tracked text files under `root`, relative to it. */
function trackedFiles(root) {
  const output = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return output.split('\0').filter(Boolean);
}

/** Returns every forbidden reference found under `root`. */
function findViolations(root) {
  const violations = [];
  for (const file of trackedFiles(root)) {
    if (ALLOWED.has(file)) continue;
    // Lockfiles carry third-party packages' own `funding` metadata, which the
    // app never ships or displays.
    if (path.basename(file) === 'package-lock.json') continue;
    const absolute = path.join(root, file);
    let text;
    try {
      if (!fs.statSync(absolute).isFile()) continue;
      const bytes = fs.readFileSync(absolute);
      if (bytes.includes(0)) continue; // binary
      text = bytes.toString('utf8');
    } catch (error) {
      if (error.code === 'ENOENT') continue; // deleted in the working tree
      throw error;
    }
    const lines = text.split('\n');
    lines.forEach((line, index) => {
      for (const { pattern, reason } of FORBIDDEN) {
        if (pattern.test(line)) violations.push(`${file}:${index + 1}: ${reason}`);
      }
    });
  }
  return violations;
}

if (require.main === module) {
  const root = path.resolve(process.argv[2] || path.join(__dirname, '..'));
  const violations = findViolations(root);
  if (violations.length) {
    console.error(`[no-ads] ${violations.length} forbidden advertising, payment or donation reference(s):`);
    for (const violation of violations) console.error(`  ${violation}`);
    process.exit(1);
  }
  console.log(`[no-ads] No advertising, payment, donation, DoH-fallback or spoofed-UA references in tracked files (${ALLOWED.size} justified exclusions).`);
}

module.exports = { FORBIDDEN, findViolations };
