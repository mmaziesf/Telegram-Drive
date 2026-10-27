## Problem

<!-- What is wrong or missing, and who is affected. Link the issue. -->

## Change

<!-- What this pull request changes and why this approach. -->

## Evidence

<!-- For each claim, the test, scan output or code reference that backs it. -->

| Check | Result |
| --- | --- |
| `npm run lint`, `tsc --noEmit`, `npm run i18n:check`, `npm run build:verify` | |
| Playwright (`--workers=1`) | |
| `cargo fmt --check`, `cargo clippy ... -D warnings` | |
| `cargo test --features native-e2e --test '*'` | |
| `cargo deny check` / `cargo audit` / gitleaks (if dependencies or secrets are touched) | |

## Not verified

<!-- Platforms, devices or flows you could not test. -->

## Checklist

- [ ] CHANGELOG entry under `[Unreleased]`
- [ ] No credentials, session data or private file data in code, tests, logs or screenshots
- [ ] Any new lint, advisory or secret-scan exception has its reason next to it
- [ ] User-visible strings added to every locale
