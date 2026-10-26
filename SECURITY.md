# Security Policy

This policy covers the Unofficial Telegram Drive fork at [mmaziesf/Telegram-Drive](https://github.com/mmaziesf/Telegram-Drive). The app handles Telegram sessions, local file access, optional encryption, loopback REST/WebDAV services, and an optional supporter-verification service. It has no built-in updater. Please report security issues privately and avoid exposing user data or credentials while investigating them.

## Report a vulnerability privately

Do not open a public GitHub issue for a vulnerability or suspected credential exposure. Use GitHub private vulnerability reporting: open the repository's [Security tab](https://github.com/mmaziesf/Telegram-Drive/security) and choose **Report a vulnerability**, or go directly to the [new advisory form](https://github.com/mmaziesf/Telegram-Drive/security/advisories/new).

Reports about code that is unchanged from the original project may also affect [caamer20/Telegram-Drive](https://github.com/caamer20/Telegram-Drive); this fork does not speak for that project, so contact its maintainer through that repository as well.

Include only the information needed to understand the report:

- The affected commit or branch, platform, and how you built the app.
- The component or workflow involved.
- A concise impact description and reproducible steps using test data.
- Relevant logs or screenshots after removing private information.
- Any safe mitigation you have already confirmed.

Never send Telegram API credentials, login codes, session data, phone numbers, file contents, private filenames or paths, proxy passwords, REST API keys, WebDAV capability links, share-link passwords, vault/file passphrases, recovery bundles, supporter recovery codes, payment credentials, raw entitlement tokens, device private keys, signing keys, or production service secrets.

## Responsible testing

- Test only with accounts, devices, services, and data you own or have explicit permission to use.
- Use isolated test files for encryption research. The TDENC2 encryption feature is a frozen-format beta and has not received an independent security audit.
- Do not perform live PayPal transactions, entitlement revocations, signing-key changes, production deployments, or production D1 mutations without explicit repository-owner authorization.
- Do not expose Telegram Drive's loopback REST, WebDAV, streaming, or share-link ports to a LAN or the public internet.
- Stop testing if it could access another person's account or data, interrupt a service, or destroy data.

## Public bug reports

Non-sensitive reliability and usability issues can be reported through [GitHub Issues](https://github.com/mmaziesf/Telegram-Drive/issues). Before posting, remove identifiers, private filenames, paths, file contents, credentials, payment information, and recovery material.

For the application's data handling and local-server model, read the [Privacy Policy](PRIVACY.md), [REST API reference](REST_API_Documentation.md), and [WebDAV guide](WEBDAV_GUIDE.md). Maintainers changing the supporter path must also preserve the [$5 lifetime supporter license invariants](SUPPORTER_LICENSE_INVARIANTS.md).

See [TDENC2 format and review boundaries](Docs/TDENC2_FORMAT.md) and the [recovery drill](Docs/ENCRYPTION_RECOVERY_DRILL.md). Independent cryptographic review remains an owner-commissioned release boundary.

## Releases

This fork publishes no release binaries and ships no auto-updater. Build from source and review the commit you build. Binaries from any other source are not produced by this repository.
