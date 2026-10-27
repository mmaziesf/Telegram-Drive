# Security Policy

This policy covers the Unofficial Telegram Drive fork at [mmaziesf/Telegram-Drive](https://github.com/mmaziesf/Telegram-Drive). The app handles Telegram sessions, local file access, optional encryption, and loopback REST/WebDAV services. It has no built-in updater, no advertising and no payment service. Please report security issues privately and avoid exposing user data or credentials while investigating them.

## Report a vulnerability privately

Do not open a public GitHub issue for a vulnerability or suspected credential exposure. Use GitHub private vulnerability reporting: open the repository's [Security tab](https://github.com/mmaziesf/Telegram-Drive/security) and choose **Report a vulnerability**, or go directly to the [new advisory form](https://github.com/mmaziesf/Telegram-Drive/security/advisories/new).

Reports about code that is unchanged from the original project may also affect [caamer20/Telegram-Drive](https://github.com/caamer20/Telegram-Drive); this fork does not speak for that project, so contact its maintainer through that repository as well.

Include only the information needed to understand the report:

- The affected commit or branch, platform, and how you built the app.
- The component or workflow involved.
- A concise impact description and reproducible steps using test data.
- Relevant logs or screenshots after removing private information.
- Any safe mitigation you have already confirmed.

Never send Telegram API credentials, login codes, session data, phone numbers, file contents, private filenames or paths, proxy passwords, REST API keys, WebDAV capability links, share-link passwords, vault/file passphrases, recovery bundles, signing keys, or other secrets.

## Supported versions

Only the latest commit on `main` is supported. The fork has no releases and no version branches, so security fixes land on `main` only.

## Response times

> **Owner input needed.** No response times have been committed yet. Until this section is filled in, reports are handled on a best-effort basis.

<!-- OWNER INPUT: acknowledgement time (for example N business days), time to a first assessment, fix or mitigation target by severity, and the coordinated disclosure deadline (for example 90 days). Then tick the SLA criterion in MIL-57. -->

## Encrypted reports

GitHub private vulnerability reporting is the only channel. A draft advisory is visible only to the reporter and the repository maintainers. This fork publishes no PGP key.

<!-- OWNER INPUT: if a PGP key is published, add its fingerprint and URL here and to the Encryption field in Docs/security.txt.template. -->

## Safe harbour

> **Owner input needed.** No safe-harbour commitment has been made yet. Until it is, follow the responsible testing rules below and report privately.

<!-- OWNER INPUT: the maintainer's own safe-harbour wording (what good-faith research will not be pursued, and its limits). It is a legal commitment, so it is not drafted here. -->

## Responsible testing

- Test only with accounts, devices, services, and data you own or have explicit permission to use.
- Use isolated test files for encryption research. The TDENC2 encryption feature is a frozen-format beta and has not received an independent security audit.
- Do not expose Telegram Drive's loopback REST, WebDAV, streaming, or share-link ports to a LAN or the public internet.
- Stop testing if it could access another person's account or data, interrupt a service, or destroy data.

## Public bug reports

Non-sensitive reliability and usability issues can be reported through [GitHub Issues](https://github.com/mmaziesf/Telegram-Drive/issues). Before posting, remove identifiers, private filenames, paths, file contents, credentials, and recovery material.

For the application's data handling and local-server model, read the [Privacy Policy](PRIVACY.md), [REST API reference](REST_API_Documentation.md), and [WebDAV guide](WEBDAV_GUIDE.md).

See [TDENC2 format and review boundaries](Docs/TDENC2_FORMAT.md) and the [recovery drill](Docs/ENCRYPTION_RECOVERY_DRILL.md). Independent cryptographic review remains an owner-commissioned release boundary.

## Releases

This fork publishes no release binaries and ships no auto-updater. Build from source and review the commit you build. Binaries from any other source are not produced by this repository.

## security.txt

[`Docs/security.txt.template`](Docs/security.txt.template) is an RFC 9116 `security.txt` for when the project has a website. It is not published anywhere yet.
