<div align="center">

<img src="Docs/assets/logo.svg" alt="Telegram Drive logo" width="92">

# Unofficial Telegram Drive

### A local-first file workspace powered by your own Telegram account

Organize, transfer, preview, stream, sync, and share the files you keep in Saved Messages and Telegram channels—on Windows, macOS, Linux, Android, and Google TV.

[Build from source](#build-from-source) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

</div>

![Telegram Drive desktop dashboard](Docs/assets/dashboard.webp)

Telegram Drive turns Telegram's familiar file storage into a focused, desktop-style workspace. The app connects directly to Telegram with credentials you provide; it does not run a separate file-storage or relay service. Every application feature is available without payment.

> [!IMPORTANT]
> **Unofficial Telegram Drive is an unofficial third-party client.** It is an independent project and is not affiliated with, endorsed by, or sponsored by Telegram FZ-LLC. It uses the Telegram API under the [Telegram API Terms of Service](https://core.telegram.org/api/terms), which require third-party apps that use "Telegram" in their title to mark themselves as "Unofficial". Files remain subject to Telegram's account, service, and per-file limits. Telegram Drive should not be treated as literally unlimited storage or as the only backup of important data.

## Contents

- [Installation](#installation)
- [First-time setup](#first-time-setup)
- [Features](#features)
- [Screenshots](#screenshots)
- [Folder Sync](#folder-sync-desktop)
- [Encryption](#optional-client-side-encryption-beta-format-frozen)
- [Privacy and security](#privacy-and-security)
- [Android and Google TV](#android-and-google-tv)
- [Documentation](#documentation)
- [Build from source](#build-from-source)

## At a glance

| | |
| --- | --- |
| **Platforms** | Windows, macOS Intel, macOS Apple Silicon, Linux, Android, and Google TV |
| **Storage model** | Saved Messages is the home location; Telegram channels can be presented as folders |
| **Transfers** | Files, folders, drag and drop, remote URLs, durable queues, background operation, and retry controls |
| **Media** | Image preview, PDF viewing, audio playback, video streaming, thumbnails, and archive tools |
| **Desktop integrations** | Folder Sync, local REST API, WebDAV, local share links, tray controls, and native notifications |
| **Privacy** | Local configuration and caches, opt-in crash reporting, loopback-only local servers, and no separate file relay |
| **Languages** | 24 selectable locales plus automatic system-language selection |
| **Price** | Free. This fork shows no ads and has no paid tier, checkout or donation link |

## Installation

This fork publishes no release binaries and has no auto-updater. To run it, [build from source](#build-from-source). Installers published elsewhere, including the original project's releases, are not produced by this repository and do not contain this fork's changes.

The [Linux packaging and rendering guide](Docs/LINUX_PACKAGING.md) covers Arch packaging, diagnostics and AppImage safe mode for local builds.

## First-time setup

Telegram requires third-party clients to use an application API ID and API hash. Telegram Drive does not provide shared credentials.

1. Sign in at [my.telegram.org](https://my.telegram.org) and open **API development tools**.
2. Create a Telegram application and copy its `api_id` and `api_hash`.
3. Build and open the app, then enter those credentials locally.
4. Authenticate with your phone number and login code, or use QR login. If Telegram cloud-password protection is enabled, complete that step as well.
5. Open **Saved Messages** or select/create Telegram channels to use as folders.

> [!WARNING]
> Treat the API hash, Telegram login codes, session data, encryption credentials, REST keys, and WebDAV links as secrets. Do not paste them into issues, logs, screenshots, or support messages.

## How it works

Telegram Drive uses Telegram's MTProto API for authentication and file operations:

- **Saved Messages** appears as the main personal storage location.
- Telegram **channels** created or selected by the app can appear as folders.
- Transfers move directly between the application and Telegram.
- Desktop metadata, settings, queues, sync state, thumbnails, and preview caches stay on the local device.
- Standard uploads are stored in Telegram in their normal form. Optional TDENC2 uploads are encrypted locally before transfer.

The application caps a Telegram object at exactly **2,000,000,000 bytes**. Encrypted files need additional envelope space, so their maximum original plaintext size is slightly lower.

## Features

### File management and organization

- Grid and list views with virtualized rendering for large folders.
- Adjustable file-card sizing from **50% to 200%**.
- Filename search, persistent sorting, multi-select, range selection, and bulk actions.
- Upload, download, rename, copy, move, and delete workflows where Telegram permits them.
- Drag-and-drop uploads and internal drag-and-drop organization.
- Folder creation, rename, deletion, visibility controls, and custom local folder groups.
- Whole-folder uploads with optional ZIP creation before transfer.
- Remote URL uploads with progress, cancellation, retries, redirects, bounded size checks, and resumable ranges when supported by the source server.
- Duplicate-file, empty-folder, media-metadata, and storage-insight tools through the local REST API.

### Reliable transfers and desktop operation

- Durable desktop upload and download queues that recover across window and application restarts.
- Independent upload/download concurrency controls, bandwidth controls, pause, resume, retry, cancel, cooldown, network-waiting, and vault-unlock states.
- Background operation from the system tray while transfers are active.
- Native transfer notifications for completion, failure, pause, and attention-required states, with per-category controls.
- Suspend, resume, network-recovery, and Telegram flood-wait handling.
- Verified downloads written through private temporary files and atomically published to their destination.
- A versioned local desktop file inventory so previously scanned folders appear while Telegram reconciliation continues.

### Viewing, playback, and archives

- Lazy-loaded thumbnails and bounded memory/disk preview caches.
- Desktop HEIC/HEIF still images use bounded JPEG display renditions in previews, gallery/slideshow and offline viewing. macOS tries `/usr/bin/sips` first; other desktops need user-installed FFmpeg 8.1 or newer. External opening and downloads keep the original. See [HEIC preview limits](Docs/HEIC_PREVIEW.md).
- A desktop image viewer with zoom, pan, fit-to-window, actual-size, wheel, double-click, and keyboard navigation controls.
- Built-in PDF viewer and audio player.
- Video playback with seeking, HLS/fMP4 streaming, remuxing/transcoding fallbacks, and cache recovery for supported plaintext media.
- Desktop MP4/M4V/MOV uploads in Media mode attach a locally generated JPEG preview and video dimensions/duration. Windows uses its native media decoder first; macOS/Linux need FFmpeg. If decoding is unavailable, choose File mode. Original video bytes are preserved; immediate streaming requires early MP4 metadata.
- Native Android playback with system media controls, resume, subtitle/audio-track selection, playback speed, and Picture-in-Picture where supported.
- ZIP, RAR, and 7z archive browsing and extraction, including extraction back into Telegram Drive where the platform supports it.
- Offline preview-cache controls for recently viewed standard files.
- Recorded plain previews, thumbnails and ready offline copies from 3.9.x retain external opening after an update. The first open verifies and registers each private cache file; arbitrary files and edited copies remain refused.

Some media depends on operating-system codec support or FFmpeg. Supported protected audio, video, and PDF content can use authenticated local byte-range streaming while the vault is unlocked, without publishing a persistent plaintext copy. See [encrypted-file limitations](#current-encrypted-file-limitations).

### Sharing and local integrations

- Password-protected local download links with optional expiration, listing, and revocation.
- Native Telegram message links for files in public channels.
- An opt-in desktop REST API for programmatic file, folder, bulk, storage, thumbnail, and media operations.
- Opt-in desktop WebDAV access for mounting Telegram Drive in compatible file managers.
- Optional, passphrase-encrypted settings backup through the user's own Telegram Saved Messages. Credentials, API/WebDAV keys, proxy details, and file data are excluded.

> [!NOTE]
> REST, WebDAV, and Telegram Drive share links are served by the running desktop application. They are not hosted public internet links. Keep the app open, do not forward its local ports, and protect every generated password, key, and capability URL.

### Personalization, language, and network controls

- System, light, dark, and default appearance preferences.
- Built-in theme presets and a custom-theme editor.
- Reduced-motion and interface-performance preferences.
- 24 selectable production locales with locale-aware dates, numbers, file sizes, and transfer rates.
- Right-to-left document direction and bidirectional-text protections for Arabic, Persian, and Urdu.
- SOCKS5 and HTTP/HTTPS proxy routing with proxy credentials stored in the operating system's secure credential manager.
- Configurable VPN-oriented timeouts, retries, keep-alive behavior, polling, bandwidth, transfer chunk size, and archive limits.
- Android share-sheet intake, foreground transfers, and native downloaded-file publication.

## Screenshots

Screenshots show representative workflows; small details may change between releases.

### Desktop

| Folder and list management | Video playback |
| --- | --- |
| ![Telegram Drive desktop folder list](Docs/assets/folders.webp) | ![Telegram Drive desktop video player](Docs/assets/video.webp) |

### Android

| Files | Transfer queue |
| --- | --- |
| ![Telegram Drive Android file list](Docs/assets/android-folders.webp) | ![Telegram Drive Android transfer queue](Docs/assets/android-transfers.webp) |

Additional desktop and mobile captures are available in the [`screenshots`](screenshots/) directory.

## Folder Sync (desktop)

Folder Sync is an opt-in, bidirectional mapping between a local directory and one Telegram channel on Windows, macOS, or Linux. It compares three states—the current local tree, the current remote tree, and the last successfully synced tree—before changing either side.

Safety behavior includes:

- Explicit conflicts instead of silent overwrites when local and remote versions both change.
- **Keep Local**, **Keep Remote**, and **Keep Both** conflict choices.
- A greater-than-50% mass-deletion guard.
- Atomic temporary-file downloads and exact transfer-size checks.
- Protection against nested mappings, duplicate remote paths, reserved temporary names, incomplete remote scans, and platform-incompatible filenames.
- Vault-aware queue pauses for encrypted mappings.
- A 50,000 file-bearing-message safety ceiling per mapped channel.

Folder Sync is disabled until enabled in **Settings → Folder Sync**. Read the [Folder Sync guide](SYNC_GUIDE.md) before mapping an important directory, and keep a separate tested backup.

## Optional client-side encryption (beta, format frozen)

See the [frozen format specification](Docs/TDENC2_FORMAT.md) and [recovery drill](Docs/ENCRYPTION_RECOVERY_DRILL.md).

Telegram Drive includes opt-in encrypted transfers using the versioned **TDENC2** envelope. Standard uploads remain the default. Encryption can be selected as a default for future uploads or chosen for an individual upload.

| Mode | Protection | Required to unlock |
| --- | --- | --- |
| **Standard** | Existing plaintext Telegram upload | Nothing |
| **Vault** | Encrypts with a key held in the local encrypted vault | Unlocked vault |
| **File passphrase** | Adds a passphrase slot to the individual file | File passphrase |
| **Vault + file passphrase** | Adds both vault and per-file passphrase access | Any supported valid slot |

The implementation provides streaming XChaCha20-Poly1305 encryption before upload, authenticated streaming downloads, optional protection of the original filename and MIME type, vault auto-lock controls, recovery-bundle export/import, per-file state badges, and encryption-aware transfer queues.

> [!CAUTION]
> **Telegram Drive cannot recover, reset, or reconstruct a lost vault passphrase, file passphrase, encryption key, or unusable recovery bundle.** Protect and test your recovery material and keep an independent backup of important files. Lost credentials or damaged recovery material can make encrypted data permanently unrecoverable.

The encryption design and implementation have **not received an independent security audit**. Use isolated test data first. This frozen-format beta is not a substitute for a tested backup strategy.

### Current encrypted-file limitations

The following operations fail closed for encrypted objects while retaining their normal behavior for standard files:

- In-app encrypted image and archive previews.
- Encrypted thumbnails, HLS/fMP4 remuxing, and transcoding.
- Local plaintext share links and REST/local-server plaintext access.
- WebDAV read, overwrite, rename, move, copy, and delete operations.
- Remote rename of encrypted Telegram media.
- Plaintext-to-encrypted migration, decrypt-in-place migration, rekey/slot-management UI, and full format migration.

TDENC2-protected audio, video, and PDF content can stream in supported in-app viewers while the vault is unlocked. The session-scoped credential is revoked when the vault locks, and the app does not publish a persistent plaintext copy. Download and authenticate other encrypted files before opening them in another application.

## Privacy and security

- The Telegram API ID and application state are stored locally. The API hash is kept separately in the desktop operating-system credential manager or Android Keystore; legacy plaintext values are removed only after secure migration succeeds.
- Telegram session data, settings, transfer state, sync metadata, encryption registry data, and vault material are stored locally in the application's data directories.
- Standard uploads send ordinary file content to Telegram. TDENC2 uploads send ciphertext, although Telegram can still observe transport/account metadata such as ciphertext size, time, account, and destination channel.
- The project does not operate a separate file-relay service.
- The app contains no advertising network or payment service. The local media server serves no ad routes (asserted in `app/src-tauri/tests/native_e2e.rs`), the WebView forbids frames (`frame-src 'none'`), and `scripts/check-no-ads.cjs` fails CI if a known ad-network or payment host returns.
- Crash reporting is disabled by default and requires explicit consent. Reports exclude file names, paths, contents, messages, Telegram identifiers, credentials, phone numbers, and user-entered values.
- The REST API and WebDAV server are disabled by default and bind only to `127.0.0.1`.
- The REST API stores only a hash of its generated key; the plaintext key is shown once.
- WebDAV capability links are shown once and can be revoked by regeneration.
- Proxy credentials use the operating system's secure credential manager.

Read the complete [Privacy Policy](PRIVACY.md), [WebDAV guide](WEBDAV_GUIDE.md), and [REST API reference](REST_API_Documentation.md).

## Languages

Telegram Drive supports a **System** language preference and these 24 selectable locales:

| | | | |
| --- | --- | --- | --- |
| English | Spanish | Russian | Ukrainian |
| Polish | Persian | Urdu | Malay |
| Simplified Chinese | Traditional Chinese | French | Italian |
| Arabic | Brazilian Portuguese | German | Hindi |
| Bengali (Bangladesh) | Indonesian | Filipino (Philippines) | Turkish |
| Thai (Thailand) | Japanese | Korean | Vietnamese |

Locale selection and formatting are production-supported. Authentication, encryption and visible data arrays use canonical translations, and the eleven large locales have zero copied-English findings. Mobile follow-up changes remain local under the owner’s pre-commit hook. Noncritical English copy and full native-language, legal-copy, RTL, long-string, CJK and device review remain outstanding; see [the measured locale review](Docs/LOCALIZATION_BUDGET_REVIEW.md).

## Android and Google TV

This fork publishes no Android package. The Kotlin sources that the Android build overlays (`app/android-overrides/`) are not part of this repository, so an Android build cannot currently be reproduced from it. The Rust and TypeScript Android code paths remain in the tree.

## Local REST API and WebDAV

Both integrations are desktop-only, disabled by default, and loopback-only.

| Integration | Default address | Authentication | Access |
| --- | --- | --- | --- |
| **REST API** | `http://127.0.0.1:8550/api/v1` | `X-API-Key` header | File/folder operations, bulk actions, storage data, thumbnails, and media metadata |
| **WebDAV** | `http://127.0.0.1:8551/dav/<private-token>/` | One-time capability URL | Read-only by default; writes require explicit opt-in |

Do not expose these ports to a LAN or the internet. See the [REST API endpoint reference](REST_API_Documentation.md) and [WebDAV guide](WEBDAV_GUIDE.md) for setup, security behavior, examples, and limitations.

## Documentation

### User documentation

| Document | Purpose |
| --- | --- |
| [Changelog](CHANGELOG.md) | Release notes, compatibility information, and upgrade history |
| [Privacy Policy](PRIVACY.md) | Local data, Telegram data flow, crash reporting, sharing, and the absence of ads and payments |
| [Security Policy](SECURITY.md) | Private vulnerability reporting, redaction guidance, and responsible testing boundaries |
| [Folder Sync guide](SYNC_GUIDE.md) | Sync safety model, limits, conflict resolution, and integration behavior |
| [WebDAV guide](WEBDAV_GUIDE.md) | Setup instructions for macOS, Windows, and Linux clients |
| [REST API reference](REST_API_Documentation.md) | Authentication, endpoints, request examples, and error responses |
| [Linux packaging guide](Docs/LINUX_PACKAGING.md) | Linux formats, Arch installation, rendering safe mode, diagnostics, and release safeguards |
| [Linux/Arch implementation plan](Docs/LINUX_ARCH_IMPLEMENTATION_PLAN.md) | Design decisions, compatibility rules, release gates, acceptance matrix, and rollback |

### Maintainer and release documentation

| Document | Purpose |
| --- | --- |
| [Android and Google TV release runbook](Docs/ANDROID_SIDELOAD_RELEASE.md) | Signing, packaging, acceptance, and sideload-release checks |
| [Desktop code signing](Docs/CODE_SIGNING.md) | macOS notarization and Windows Authenticode settings, and first-signed-release acceptance |

## Build from source

### Prerequisites

- **Node.js:** `20.19.0+` within Node 20, or `22.12.0+`.
- **Rust:** the latest stable toolchain installed with [rustup](https://rustup.rs/).
- **Telegram API credentials:** an `api_id` and `api_hash` created at [my.telegram.org](https://my.telegram.org).
- **Tauri system dependencies:** follow the official [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform.

Common requirements:

- **macOS:** Xcode Command Line Tools (`xcode-select --install`).
- **Windows:** Visual Studio Build Tools with **Desktop development with C++** and the Microsoft Edge WebView2 Runtime.
- **Ubuntu/Debian:**

  ```bash
  sudo apt-get update
  sudo apt-get install -y libwebkit2gtk-4.1-dev build-essential curl wget file \
    libssl-dev libdbus-1-dev libgtk-3-dev libayatana-appindicator3-dev \
    librsvg2-dev libfuse2
  ```

### Install and run

```bash
git clone https://github.com/mmaziesf/Telegram-Drive.git
cd Telegram-Drive/app
npm ci
npm run tauri dev
```

The first run downloads and compiles the Rust dependency graph and may take several minutes. Later builds reuse Cargo's compilation cache.

Create local, unsigned installer bundles with:

```bash
cd app
npm run tauri build
```

On Windows, the build scripts download and validate Microsoft's signed Visual C++ Redistributable before creating the NSIS installer.

### Validation

Behavioral tests are end-to-end journeys; there are no unit suites. Run the relevant checks from `app/` before submitting changes:

```bash
npm run build:verify
npm test
npm run i18n:check
cd src-tauri
cargo fmt --all -- --check
cargo clippy --locked --features native-e2e --lib --all-targets -- -D warnings
cargo test --locked --features native-e2e --test native_e2e
```

`node scripts/run-e2e.cjs` from the repository root runs every host suite. See [TESTING.md](TESTING.md) for what each suite covers and what still needs installed-app or device acceptance.

The application is built with Tauri 2, Rust, React 19, TypeScript, Tailwind CSS 4, TanStack Query/Virtual, SQLite, Tokio, Actix Web, Grammers, PDF.js, HLS.js, and MP4Box.

## Support and community

- Report reproducible, non-sensitive problems through [GitHub Issues](https://github.com/mmaziesf/Telegram-Drive/issues).
- Never include Telegram credentials, session data, recovery codes, encryption keys, private filenames, or file contents in a public report.
- For a sensitive security report, follow the private-disclosure guidance in the [Security Policy](SECURITY.md).

---

<div align="center">

Telegram Drive is not affiliated with Telegram FZ-LLC. Use the application responsibly and in accordance with Telegram's terms and applicable law.

</div>

### TV field navigation

With TV directional navigation, arrows edit a focused native field. After finishing an edit (or closing a native select picker), press Escape to return that field to directional navigation; the next arrow moves focus to another control. Enter resumes editing. A second Escape while already in navigation mode keeps the normal dialog-close behavior. Browser Escape is verified; physical Google TV Back event delivery and remote acceptance remain unrun.
