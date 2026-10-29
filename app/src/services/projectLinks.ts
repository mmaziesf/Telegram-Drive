/** Public repository of this fork; source code, issues and policies live here. */
export const FORK_REPOSITORY_URL = 'https://github.com/mmaziesf/Telegram-Drive';

/** Issue tracker for questions and bug reports about this fork. */
export const FORK_ISSUES_URL = `${FORK_REPOSITORY_URL}/issues`;

/** Privacy policy that describes this fork's behaviour. */
export const FORK_PRIVACY_URL = `${FORK_REPOSITORY_URL}/blob/main/PRIVACY.md`;

/** Original project this fork is based on, credited in About. */
export const UPSTREAM_REPOSITORY_URL = 'https://github.com/caamer20/Telegram-Drive';

/** Author of the original project, credited in About. */
export const UPSTREAM_AUTHOR = 'Cameron Amer';

/** Telegram API Terms of Service, linked from the account-risk step of the first-run introduction. */
export const TELEGRAM_API_TERMS_URL = 'https://core.telegram.org/api/terms';

/** Telegram FAQ entry on inactive-account self-destruction, linked from the same step. */
export const TELEGRAM_SELF_DESTRUCT_FAQ_URL = 'https://telegram.org/faq#q-how-does-account-self-destruction-work';

/** Strips the scheme so a URL reads as a short label, e.g. "github.com/owner/repo". */
export function displayUrl(url: string): string {
  return url.replace(/^https?:\/\//, '');
}
