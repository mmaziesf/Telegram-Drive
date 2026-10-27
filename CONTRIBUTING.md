# Contributing

Thanks for helping improve this fork. Read the [Security Policy](SECURITY.md) before reporting anything sensitive, and never put credentials, session files or private file data in an issue, pull request or log.

## Scope

- Pull requests go to `main` of [mmaziesf/Telegram-Drive](https://github.com/mmaziesf/Telegram-Drive). Changes for the original project belong in [caamer20/Telegram-Drive](https://github.com/caamer20/Telegram-Drive).
- The original code has no license (see the README notice). Do not add a license file or license headers on behalf of the original author.
- Do not commit Telegram `api_id`/`api_hash` values, signing keys, release binaries or generated installers.

## Development setup

- Node 22 for `app/`; run `npm ci` in `app/`.
- Rust 1.92 or newer (`rust-version` in `app/src-tauri/Cargo.toml`) with `rustfmt` and `clippy`; `cargo-deny` for the dependency check.
- Linux needs the Tauri system packages listed in [Build from source](README.md#build-from-source).

## Checks to run before opening a pull request

From `app/`:

```sh
npm run lint            # added with the CI pipeline (PR #6)
npx tsc --noEmit -p .
npm run i18n:check
npm run build:verify
npx playwright test --workers=1
```

From `app/src-tauri/`:

```sh
cargo fmt --check
cargo clippy --locked --features native-e2e --lib --all-targets -- -D warnings
cargo test --locked --features native-e2e --test '*'
cargo deny check
```

CI runs the same checks plus `cargo audit`, gitleaks and CodeQL. Fix a failure at its cause. If a lint rule, advisory or secret-scan finding has to be allowed, put the reason next to the exception (`deny.toml`, `.cargo/audit.toml`, `.gitleaksignore` or an inline lint comment).

## Which runners check a pull request

- Pull requests run the desktop build on Linux and Windows only. macOS (Apple silicon and Intel) runs on every push to `main`, nightly, and on demand with `gh workflow run desktop-sync-ci.yml --ref BRANCH`. Run it on demand when a change touches macOS-specific code.
- A newer push to a pull request cancels its older runs. Runs on `main` are never cancelled.
- `scripts/check-workflow-pins.cjs` enforces both rules. [TESTING.md](TESTING.md) has the details.

## Code expectations

- Rust: no `unwrap`, `expect` or `panic!` on paths reachable from user input or the network; return errors instead. Never log secrets, session data, file names or paths.
- Integration tests live under `app/src-tauri/tests/` and `app/tests/e2e/`; the test policy (`scripts/check-test-policy.cjs`) rejects `#[test]` inside `src/`.
- Every user-visible string goes through the locale catalogs in all supported languages.
- Keep commits small and focused, with a message that says why.

## Pull requests

- Fill in the pull-request template, including how you tested and what you did not test.
- Add an entry under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- Every claim in a pull request or in documentation must point to a test, a scan result or the code that backs it.
- No force-pushes to shared branches.
