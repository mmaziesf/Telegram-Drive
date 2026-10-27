# Repository Agent Instructions

## Behavioral tests are end-to-end only

Use end-to-end regression tests for future work. Do not add or restore unit-test suites, Vitest, Testing Library, inline Rust test modules, or Android JVM unit tests. `npm test` and `test:e2e` in each JavaScript project run the same E2E suite; native journeys run through the dedicated `native_e2e` target. See [TESTING.md](TESTING.md) for commands and coverage boundaries.

Exercise user-visible browser journeys, native child-process/HTTP/storage lifecycles, or Android device journeys. Test through application boundaries; renaming an isolated function test to E2E does not meet this policy. The external Telegram boundary may use controlled fixtures, but describe that limitation and keep required real-device release acceptance.

Preserve account isolation, encrypted-data integrity and recovery, transfer behavior, and release protections when changing test coverage. Add the relevant E2E regression before fixing a behavior bug. Keep type checking, formatting, linting, security/dependency/configuration checks, localization checks, bundle budgets, and platform builds. These static checks are separate from behavioral testing and must not be removed as part of an E2E-only policy.

Run `node scripts/check-test-policy.cjs` before handing off testing changes. Never report skipped, unrun, fixture-only, or unavailable device/platform checks as passed. Passing suites are evidence for the exercised journeys, not a guarantee of perfect software.

## Android publication is binaries only

Android project and source files must remain local and must never be committed to or uploaded to GitHub. This includes Android build configuration, native project files, generated project folders, and Android test projects. Only compiled Android binaries may be uploaded, as assets in the separate Android GitHub release. Signing keys and credentials must always remain private.

Local branch merges are allowed; they do not authorize a push or publication of Android project files. Before any future GitHub push, inspect the complete outgoing commits for Android project files, including changes in shared application files. Do not assume that an existing tracked file or a local merge makes Android source eligible for publication. `node scripts/check-android-publication.cjs` inspects tracked files and every outgoing commit and must pass before a push; it refuses Android project files and any Android-related path that is not listed in `dependency-policy/android-publication-review.json`. Paths listed there as pending are reported on every run and are not approved by the check; only the repository owner moves a path to the permitted list.

## No advertising, payments or donations

This fork carries no advertising network, sponsor placement, supporter licence, checkout, donation link or payment service, and every feature is free. Do not add any of them, and do not add a frame, remote script or loopback route that would serve third-party content. `node scripts/check-no-ads.cjs` fails on known ad-network and payment hosts in tracked files, `scripts/check-app-security.cjs` requires `frame-src 'none'`, and the native E2E suite asserts the retired ad routes return 404.
