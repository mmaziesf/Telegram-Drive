# Telegram Drive Privacy Policy

Last updated: October 26, 2026

Telegram Drive is a local-first desktop and Android client. It does not operate a file-storage or Telegram account service and does not sell personal information. This fork shows no advertising, sells nothing and takes no payments or donations.

## Data stored on your device

Application settings, transfer queues, cached thumbnails and previews, local activity flags, and encrypted vault material are stored locally. Cache controls in Settings can remove cached media without deleting files stored in Telegram.

## Data sent to Telegram

Authentication and file operations connect directly to Telegram using credentials supplied by the user. Folders are represented by private Telegram channels. Telegram receives the messages and file bytes necessary to provide those operations, subject to Telegram's own terms and privacy policy.

The Telegram API hash is stored in the desktop operating-system credential manager or Android Keystore, separately from ordinary JSON settings. A legacy plaintext API hash is retained only until secure migration succeeds. The non-secret API ID and Telegram session database remain in the application's local data directory.

## Crash reporting

Crash reporting is disabled by default and requires explicit consent. A report contains only the application version, operating-system platform, error type, timestamp, and sanitized function names. It excludes error messages, file names, paths, file contents, Telegram messages or identifiers, credentials, phone numbers, and user-entered values. Reporting can be disabled at any time in Settings; disabling it also clears queued reports.

## No advertising, payments or donations

This fork contains no advertising network, sponsor placement, supporter licence, checkout or donation link, and it operates no licensing or payment service. The app therefore sends nothing to an advertising or payment provider. The loopback media server serves no ad page or ad loader (`app/src-tauri/tests/native_e2e.rs` asserts both routes return 404), the WebView content policy forbids every frame (`frame-src 'none'`, enforced by `scripts/check-app-security.cjs`), and `scripts/check-no-ads.cjs` fails CI if a known ad-network or payment host reappears in the tracked source.

## Local sharing servers

WebDAV, REST, and password-protected local links are disabled until enabled by the user. They listen on the addresses shown in Settings and use capability tokens, API keys, or passwords. Disabling a server or regenerating its credential revokes that access. Guest or anonymous WebDAV connections receive no token-scoped file access.

## User control

Users can clear caches, disable crash reporting, stop local servers, revoke share links, lock the encryption vault, and remove local settings. Files stored in Telegram remain governed by the user's Telegram account until the user deletes them.

Security reports should not include credentials or private file data. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
