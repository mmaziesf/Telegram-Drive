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
| Malware running as the same user | Copies the session or reads unlocked keys | Partly mitigated. No desktop app can fully defend against code running with the user's privileges. The session file is sealed with XChaCha20-Poly1305 under a key in the OS credential store (or an Argon2id passphrase key), so a copied file alone is not enough; malware that can query the credential store or read process memory still gets the session | `session_store/`; journeys in `session_store/journeys.rs`; `session-unlock.spec.ts` | PR #12 (MIL-37); open until merged |
| Web pages in a local browser | Use the loopback REST/WebDAV/streaming server | Servers are off by default and bind to `127.0.0.1` only; CORS allows only the app's origins, the `null` origin (see below) and, in debug builds only, the development-server port; the REST key is stored as a hash and shown once | `server.rs` (listener bind), `local_cors.rs` | In the base; dev origin debug-only in PR #32 |
| Same, through DNS rebinding | Points a domain at `127.0.0.1` and talks to the servers as its own origin | Every local server refuses a `Host` other than `127.0.0.1:<port>` or `localhost:<port>` with 421, before CORS, auth or routing | `local_cors.rs` `guard_loopback_request`; native test `local_servers_refuse_requests_addressed_to_another_host` | PR #32 |
| Anyone who sees a stream URL | Reuses the stream token from the query string | The token is 16 random bytes, generated once per app run in memory and never stored, so a restart rotates it. It is compared in constant time. Every local-server response and the WebView send `Referrer-Policy: no-referrer`. The log redactor removes `token=` values and long hex runs | `lib.rs` `generate_stream_token`, `server.rs` `StreamTokenData::accepts`, `local_cors.rs`, `index.html`, `app_log.rs`; native tests `local_servers_refuse_requests_addressed_to_another_host`, `the_log_file_is_redacted_bounded_and_named_in_the_startup_failure_report` | PRs #31, #32, #33 |
| Someone who copies a share-unlock cookie | Keeps using a password-protected share | Each unlock is a random value the server tracks with a 30-minute expiry, tied to the share's current password | `share_routes.rs` `ShareUnlockStore` | PR #30 |
| Third-party ad network or payment provider | Runs remote content inside the app; sees IP address and timing | Removed: no ad routes, no DoH fallback or spoofed User-Agent, no supporter or payment service, WebView `frame-src 'none'`; a CI guard rejects ad, payment and donation hosts | `native_e2e.rs` (ad routes return 404); `check-app-security.cjs`; `check-no-ads.cjs` | PR #10 |
| Update or distribution channel | Pushes a malicious build | No auto-updater; no published binaries; manual-only release workflow | `tauri.conf.json`, `.github/workflows/release.yml` | PR #9 |
| Vulnerable dependency | Known CVE or RUSTSEC advisory in a shipped crate or npm package | Advisories fixed by version bumps; `cargo deny`, `cargo audit`, npm audit for the app and Dependabot in CI | `deny.toml`, `.cargo/audit.toml`, `.github/workflows/ci.yml`, `dependency-assurance.yml` (`node-assurance` matrix) | PR #4, PR #6, PR #13 |
| Secret committed to the repository | Leaks credentials | gitleaks scans the full history in CI; each allowlisted finding has a reason | `.gitleaksignore`, `ci.yml` | PR #6 |
| Malicious pull request or workflow | Abuses CI tokens | Read-only `GITHUB_TOKEN` by default, actions pinned to commit SHAs, no persisted checkout credentials | `.github/workflows/*.yml`, `scripts/check-workflow-pins.cjs` | PR #6 |
| Crafted encrypted file | Weakens the KDF or exhausts memory | Argon2id parameters and sizes are validated against fixed bounds on parse | `crypto/policy.rs` `validate_argon2_params` | In the base |

## Trust boundaries

1. **App ↔ Telegram.** MTProto via `grammers`, using the user's own `api_id` and `api_hash`. The fork ships no credentials.
2. **App ↔ loopback clients.** REST, WebDAV, streaming and share links on `127.0.0.1`.
3. **App ↔ third parties.** Opt-in crash reporting and the services the user enables, such as remote URL uploads ([PRIVACY.md](../PRIVACY.md)). There is no ad network or payment provider (PR #10).
4. **Source ↔ build.** Users build from source. CI checks the pull request, not the machine that builds the app.

## Known limitations

- **The Telegram session is not encrypted at rest until PR #12 is merged.** Owner-only file permissions (PR #2) stop other local users, but not malware running as the user, a backup tool, or someone who reads the disk directly. PR #12 seals the session and migrates plaintext files. After it, these limits remain:
  - Android sessions are unchanged and still plaintext.
  - Erasing the old plaintext file is best effort. On SSDs, copy-on-write file systems and in backups, old blocks may survive.
  - Intermediate `serde_json` buffers of the session snapshot are not zeroized.
  - If a write tears before the 77-byte header is complete, a keychain key may be left orphaned.
  - When the credential store is unavailable, the app offers only Retry.
  - Resetting a forgotten passphrase deletes the local session but does not revoke the authorization on Telegram's servers; end it from another device.
  - The macOS Keychain and Windows Credential Manager backends compile but have not been tested on those systems.
- **Windows and other non-Unix platforms** rely on the per-user profile ACL for the session. The app sets no extra ACL.
- **No independent audit** of TDENC2 or the vault.
- **Metadata is visible to Telegram**: size, time, account and destination, even for encrypted files.
- **Files uploaded in standard mode** before vault became the default stay unencrypted. There is no in-place migration.
- **The local servers accept `Origin: null` in release builds** (`local_cors.rs` `is_allowed_origin`). WebKit, which backs the WebView on macOS and Linux, sends `Origin: null` for media requests from the `tauri://` scheme; v1.8.2 added the allowance because playback failed there without it. Sandboxed iframes and `file:` pages on any site send the same origin, so such a page may read CORS responses. Everything behind it is still gated: streams and HLS need the per-run stream token, the REST API needs its key, WebDAV needs its capability token, and password-protected shares need an unlock. Removing the allowance needs a playback check on macOS and Linux first.
- **The stream token travels in URL query strings and HLS playlists**, because `<video>` and HLS segment requests cannot carry custom headers. Anything that can read those URLs on this machine (the WebView itself, a local process that can inspect it, or a screen share of a debug view) can use the token until the app restarts. The servers are loopback-only, responses and the WebView send no referrer, and logs redact the token, so the risk is limited to the local machine. Moving the token out of the URL would need a redesign.
- **Platforms not verified by this fork**: the existing workflows build macOS, Windows and Linux. Installers, Android and Google TV builds, and a real Telegram sign-in were not exercised by hand.
- **Licensing**: the original project publishes no license. This fork cannot grant one for the original code (see the README).
