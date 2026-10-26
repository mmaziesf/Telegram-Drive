# Threat model

This page covers the desktop app in this fork (Tauri 2 with a Rust backend and a React front end). It lists what the app protects, who it protects it from, what is in place and where each control lives. It also lists what is not covered.

"PR #N" means a pull request in [mmaziesf/Telegram-Drive](https://github.com/mmaziesf/Telegram-Drive/pulls). A control marked with a PR is in place only once that PR is merged.

## Assets

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Telegram session (MTProto authorization key) | `telegram.session` (SQLite) in each account's data directory | Anyone who holds it can act as the account until the session is revoked |
| Telegram `api_hash` | OS credential manager (`app/src-tauri/src/api_secret.rs`) | Identifies the user's own Telegram application |
| File contents and names | Telegram, the local cache and sync folders | User data |
| Vault passphrase, vault key, recovery bundles | Memory while unlocked; the vault file is encrypted with Argon2id and XChaCha20-Poly1305 ([CRYPTO.md](CRYPTO.md)) | Opens every vault-protected file |
| REST API key, WebDAV capability links, share links | Hash or capability token in local state | Local access to files |
| Proxy password | OS credential manager (`app/src-tauri/src/proxy_secret.rs`) | Network credentials |

## Adversaries and controls

| Adversary | Threat | Control | Where | Status |
| --- | --- | --- | --- | --- |
| Telegram or anyone with access to the account's cloud data | Reads uploaded files | Client-side TDENC2 encryption before upload | `crypto/envelope/`; tests in `tests/crypto_envelope.rs` | In the base; tests in PR #5 |
| Same | Plaintext uploads by default | Vault mode is the default for new uploads; sync pauses with `VAULT_LOCKED` instead of uploading plaintext | `EncryptionSettings::default`; `tests/e2e/encryption-default.spec.ts` | PR #1 |
| Another local user on the same machine | Copies the session file | Session directory 0700, session database and SQLite sidecars 0600, symlinks never followed; older installs tightened when the session is next opened | `session_protection.rs`; native test `telegram_session_files_are_owner_only_and_older_installs_are_tightened` | PR #2 (Unix-like systems only) |
| Malware running as the same user | Copies the session or reads unlocked keys | **Not mitigated.** No desktop app can fully defend against code running with the user's privileges. Encrypting the session at rest would raise the cost; see Known limitations | none | Open (MIL-37) |
| Web pages in a local browser | Use the loopback REST/WebDAV/streaming server | Servers are off by default and bind to `127.0.0.1` only; CORS allows only the app's origins, the development-server port and the `null` origin (see Known limitations); the REST key is stored as a hash and shown once | `server.rs` (listener bind), `local_cors.rs` | In the base |
| Third-party ad network or payment provider | Runs remote content inside the app; sees IP address and timing | Removed: no ad routes, no DoH fallback or spoofed User-Agent, no supporter or payment service, WebView `frame-src 'none'`; a CI guard rejects ad, payment and donation hosts | `native_e2e.rs` (ad routes return 404); `check-app-security.cjs`; `check-no-ads.cjs` | PR #10 |
| Update or distribution channel | Pushes a malicious build | No auto-updater; no published binaries; manual-only release workflow | `tauri.conf.json`, `.github/workflows/release.yml` | PR #9 |
| Vulnerable dependency | Known CVE or RUSTSEC advisory in a shipped crate or npm package | Advisories fixed by version bumps; `cargo deny`, `cargo audit`, npm audit and Dependabot in CI | `deny.toml`, `.cargo/audit.toml`, `.github/workflows/ci.yml` | PR #4, PR #6 |
| Secret committed to the repository | Leaks credentials | gitleaks scans the full history in CI; each allowlisted finding has a reason | `.gitleaksignore`, `ci.yml` | PR #6 |
| Malicious pull request or workflow | Abuses CI tokens | Read-only `GITHUB_TOKEN` by default, actions pinned to commit SHAs, no persisted checkout credentials | `.github/workflows/*.yml`, `scripts/check-workflow-pins.cjs` | PR #6 |
| Crafted encrypted file | Weakens the KDF or exhausts memory | Argon2id parameters and sizes are validated against fixed bounds on parse | `crypto/policy.rs` `validate_argon2_params` | In the base |

## Trust boundaries

1. **App ↔ Telegram.** MTProto via `grammers`, using the user's own `api_id` and `api_hash`. The fork ships no credentials.
2. **App ↔ loopback clients.** REST, WebDAV, streaming and share links on `127.0.0.1`.
3. **App ↔ third parties.** Opt-in crash reporting and the services the user enables, such as remote URL uploads ([PRIVACY.md](../PRIVACY.md)). There is no ad network or payment provider (PR #10).
4. **Source ↔ build.** Users build from source. CI checks the pull request, not the machine that builds the app.

## Known limitations

- **The Telegram session is not encrypted at rest.** Owner-only file permissions (PR #2) stop other local users, but not malware running as the user, a backup tool, or someone who reads the disk directly. The planned design:
  - a session store that implements the `grammers` `Session` trait over an encrypted file;
  - a random key held in the OS credential manager (the `keyring` crate the app already uses);
  - atomic, debounced writes;
  - a one-time migration from the SQLite file, followed by secure removal of it.

  This also needs an explicit account ID, because account isolation currently relies on the session file's on-disk identity (`external_files.rs`). It is tracked in MIL-37 and not yet done.
- **Windows and other non-Unix platforms** rely on the per-user profile ACL for the session. The app sets no extra ACL.
- **No independent audit** of TDENC2 or the vault.
- **Metadata is visible to Telegram**: size, time, account and destination, even for encrypted files.
- **Files uploaded in standard mode** before vault became the default stay unencrypted. There is no in-place migration.
- **The local servers accept `Origin: null`** (`local_cors.rs` `is_allowed_origin`). Sandboxed iframes and `file:` pages on any site send that origin. Requests still need the REST key or a capability token, but the allowance should be reviewed and narrowed if the app does not need it.
- **Platforms not verified by this fork**: the existing workflows build macOS, Windows and Linux. Installers, Android and Google TV builds, and a real Telegram sign-in were not exercised by hand.
- **Licensing**: the original project publishes no license. This fork cannot grant one for the original code (see the README).
