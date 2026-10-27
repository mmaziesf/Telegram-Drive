// Validate actual application configuration without a unit-test framework.
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..', 'app');
// These files are part of the release input, including the untracked Cargo
// configuration that enables FTS5 and the build-time SQLite capability probe.
for (const file of ['.cargo/config.toml', 'app/src-tauri/Cargo.toml', 'app/src-tauri/Cargo.lock', 'app/src-tauri/build.rs', 'app/src-tauri/build/search-support.rs']) {
  if (!fs.statSync(path.resolve(root, '..', file)).isFile()) throw new Error(`Missing release build input: ${file}`);
}
const json = file => JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
const config = json('src-tauri/tauri.conf.json');
// External links are fixed constants or Telegram's fragment.com login link, so the
// Rust-enforced shell scope allows HTTPS on those hosts only. The plugin anchors it as ^...$.
const shellScope = new RegExp(`^(?:${config.plugins?.shell?.open})$`);
const links = fs.readFileSync(path.join(root, 'src/services/projectLinks.ts'), 'utf8');
const linkConstants = [...links.matchAll(/'(https:\/\/[^']+)'/g)].map(([, url]) => url);
if (linkConstants.length < 3) throw new Error('projectLinks.ts link constants were not found.');
const mustOpen = [...linkConstants, 'https://github.com/mmaziesf/Telegram-Drive/issues',
  'https://github.com/mmaziesf/Telegram-Drive/blob/main/PRIVACY.md', 'https://my.telegram.org',
  'https://ffmpeg.org/download.html#build-windows', 'https://fragment.com/', 'https://oauth.fragment.com/x?y=1'];
const mustRefuse = ['http://github.com/mmaziesf/Telegram-Drive', 'https://github.com/someone/else', 'https://github.com.evil.example/',
  'https://telegram.org.evil.example/', 'https://evil.example/?next=https://telegram.org', 'https://fragment.com.evil.example/',
  'https://evilfragment.com/', 'mailto:someone@example.com', 'file:///etc/passwd', 'tel:123', 'https://my.telegram.org@evil.example/'];
const scopeErrors = mustOpen.filter(url => !shellScope.test(url)).map(url => `blocked: ${url}`)
  .concat(mustRefuse.filter(url => shellScope.test(url)).map(url => `allowed: ${url}`));
if (scopeErrors.length) throw new Error(`Shell URL scope is wrong: ${scopeErrors.join('; ')}`);
const csp = config.app?.security?.csp;
if (typeof csp !== 'string') throw new Error('A production WebView CSP is required.');
const directives = new Map(csp.split(';').map(value => value.trim()).filter(Boolean).map(value => {
  const [name, ...sources] = value.split(/\s+/);
  return [name, sources];
}));
const scripts = directives.get('script-src') || [];
if (scripts.length !== 1 || scripts[0] !== "'self'") {
  throw new Error("WebView scripts must come from 'self' only (workers use worker-src).");
}
// Nothing in the app is framed; the removed sponsor iframe was the only user.
for (const [name, expected] of [['object-src', "'none'"], ['frame-src', "'none'"], ['base-uri', "'self'"], ['form-action', "'self'"]]) {
  const sources = directives.get(name);
  if (sources?.length !== 1 || sources[0] !== expected) throw new Error(`Invalid ${name} restriction.`);
}
// Media URLs carry the local stream token in their query string.
if (!/<meta name="referrer" content="no-referrer" \/>/.test(fs.readFileSync(path.join(root, 'index.html'), 'utf8'))) {
  throw new Error('index.html must set <meta name="referrer" content="no-referrer" />.');
}
const mobile = json('src-tauri/capabilities/mobile.json');
const desktop = json('src-tauri/capabilities/default.json');
if (mobile.platforms?.length !== 1 || mobile.platforms[0] !== 'android') {
  throw new Error('Mobile capabilities must remain restricted to Android.');
}
if (desktop.platforms?.length !== 3 || !['linux', 'macOS', 'windows'].every(value => desktop.platforms.includes(value))) {
  throw new Error('Desktop capabilities must remain restricted to desktop platforms.');
}
// This fork publishes no signed releases, so it must not carry an updater that
// could install binaries signed by someone else's key.
if (desktop.permissions?.some(value => typeof value === 'string' && /^(updater|process):/.test(value))) {
  throw new Error('Updater and process-restart permissions must stay removed until the fork has its own signing key.');
}
// The WebView never uses the fs plugin. Granting it would let injected script
// read the Telegram session and settings files under the app data directory.
for (const capability of [mobile, desktop]) {
  if (capability.permissions.some(value => /^fs:/.test(typeof value === 'string' ? value : value?.identifier ?? ''))) {
    throw new Error('WebView file-system permissions must stay removed; file access goes through audited Rust commands.');
  }
}
if (![mobile.identifier, desktop.identifier].every(value => config.app.security.capabilities.includes(value))) {
  throw new Error('The application must declare its platform-specific capabilities.');
}
// Desktop opens links through the shell scope above; only Android uses opener.openUrl,
// and only for fixed project and Telegram policy pages.
const openerUrls = capability => capability.permissions.filter(value => value?.identifier === 'opener:allow-open-url' || value === 'opener:allow-open-url');
if (openerUrls(desktop).length) throw new Error('Desktop must not grant opener:allow-open-url; it opens links through the shell scope.');
const mobileOpener = openerUrls(mobile);
const mobileUrls = (mobileOpener[0]?.allow || []).map(value => value.url);
if (mobileOpener.length !== 1 || !mobileUrls.length || mobileUrls.some(url => /[*?[]/.test(url) || !shellScope.test(url))) {
  throw new Error('Android opener URLs must be an explicit list of exact HTTPS links inside the shell scope.');
}
for (const capability of [mobile, desktop]) {
  if (capability.permissions.some(value => ['opener:default', 'opener:allow-default-urls', 'opener:allow-open-path'].includes(value))) {
    throw new Error('Opener must not grant default URL or generic path permissions.');
  }
}
if (!desktop.permissions.includes('opener:allow-reveal-item-in-dir')) throw new Error('Download reveal permission is required.');
if (config.plugins?.updater || config.bundle?.createUpdaterArtifacts) {
  throw new Error('The updater configuration must stay removed until the fork has its own signing key.');
}
// The published REST contract and the registered routes describe the same API.
const routes = new Set([...fs.readFileSync(path.join(root, 'src-tauri/src/api_routes.rs'), 'utf8')
  .matchAll(/^#\[(get|post|patch|put|delete)\("([^"]+)"\)\]/gm)].map(([, method, route]) => `${method} ${route}`));
const contract = new Set(Object.entries(json('src-tauri/api/openapi-v1.json').paths)
  .flatMap(([route, operations]) => Object.keys(operations).map(method => `${method} ${route}`)));
const drift = [...routes].filter(value => !contract.has(value)).map(value => `undocumented: ${value}`)
  .concat([...contract].filter(value => !routes.has(value)).map(value => `not implemented: ${value}`));
if (!routes.size || drift.length) throw new Error(`REST contract differs from the routes: ${drift.join('; ') || 'no routes found'}`);
console.log('[app-security] WebView CSP, capability, no-updater and REST contract configuration passed.');
