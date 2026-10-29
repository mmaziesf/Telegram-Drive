import { expect, test } from '@playwright/test';
import { desktopFixture, nativeCalls } from './desktop-fixture';

test('a keychain-protected session opens without asking for a passphrase', async ({ page }) => {
  await desktopFixture(page);
  await page.goto('/');
  await expect(page.getByText('Holiday folder photo.jpg', { exact: true })).toBeVisible();
  // React's development StrictMode runs the startup effect twice.
  expect((await nativeCalls(page, 'cmd_session_storage_status')).length).toBeGreaterThan(0);
  expect(await nativeCalls(page, 'cmd_unlock_session')).toHaveLength(0);
});

test('a passphrase-protected session is unlocked before it connects', async ({ page }) => {
  await desktopFixture(page, { sessionProtection: 'passphrase-locked' });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Unlock your Telegram session' })).toBeVisible();
  expect(await nativeCalls(page, 'cmd_connect')).toHaveLength(0);
  const passphrase = page.getByLabel('Passphrase', { exact: true });
  await passphrase.fill('not the right passphrase');
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'The passphrase is incorrect.' })).toBeVisible();
  expect(await nativeCalls(page, 'cmd_connect')).toHaveLength(0);
  await passphrase.fill('fixture session passphrase');
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
  await expect(page.getByText('Holiday folder photo.jpg', { exact: true })).toBeVisible();
  expect((await nativeCalls(page, 'cmd_connect')).length).toBeGreaterThan(0);
  const stored = await page.evaluate(() => (window as any).__desktopTest.stores['config.json']);
  expect(stored.api_id).toBe('12345');
});

test('without a credential store a new passphrase must be long enough and confirmed', async ({ page }) => {
  await desktopFixture(page, { sessionProtection: 'passphrase-setup', signedOut: true });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Protect your Telegram session' })).toBeVisible();
  await page.getByLabel('Passphrase', { exact: true }).fill('too short');
  await page.getByLabel('Confirm passphrase', { exact: true }).fill('too short');
  await page.getByRole('button', { name: 'Protect session', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Use at least 12 characters.' })).toBeVisible();
  await page.getByLabel('Passphrase', { exact: true }).fill('a long enough passphrase');
  await page.getByLabel('Confirm passphrase', { exact: true }).fill('a different passphrase');
  await page.getByRole('button', { name: 'Protect session', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'The passphrases do not match.' })).toBeVisible();
  expect(await nativeCalls(page, 'cmd_unlock_session')).toHaveLength(0);
  await page.getByLabel('Confirm passphrase', { exact: true }).fill('a long enough passphrase');
  await page.getByRole('button', { name: 'Protect session', exact: true }).click();
  await expect(page.getByLabel('API ID', { exact: true })).toBeVisible();
  expect(await nativeCalls(page, 'cmd_unlock_session')).toEqual([{ command: 'cmd_unlock_session', args: { passphrase: 'a long enough passphrase' } }]);
});

test('an unreachable credential store keeps the saved session and offers a retry', async ({ page }) => {
  await desktopFixture(page, { sessionProtection: 'keychain-unavailable' });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'System credential store unavailable' })).toBeVisible();
  const stored = await page.evaluate(() => (window as any).__desktopTest.stores['config.json']);
  expect(stored.api_id).toBe('12345');
  await page.evaluate(() => { (window as any).__desktopTest.keychainUnavailable = false; });
  await page.getByRole('button', { name: 'Try again', exact: true }).click();
  await expect(page.getByText('Holiday folder photo.jpg', { exact: true })).toBeVisible();
});

test('a forgotten passphrase deletes only the local session after confirmation', async ({ page }) => {
  await desktopFixture(page, { sessionProtection: 'passphrase-locked' });
  await page.goto('/');
  await page.getByRole('button', { name: 'Forgot your passphrase?', exact: true }).click();
  await expect(page.getByText(/stays listed in Telegram's active sessions/)).toBeVisible();
  expect(await nativeCalls(page, 'cmd_logout')).toHaveLength(0);
  await page.getByRole('button', { name: 'Delete session', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Protect your Telegram session' })).toBeVisible();
  expect(await nativeCalls(page, 'cmd_logout')).toHaveLength(1);
});

test('an unreachable credential store offers to remove the session and protect the next one with a passphrase', async ({ page }) => {
  await desktopFixture(page, { sessionProtection: 'keychain-unavailable' });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'System credential store unavailable' })).toBeVisible();
  await page.getByRole('button', { name: 'Remove saved session and sign in again', exact: true }).click();
  await expect(page.getByText(/you will choose a passphrase to protect the new session/)).toBeVisible();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(await nativeCalls(page, 'cmd_logout')).toHaveLength(0);
  await page.getByRole('button', { name: 'Remove saved session and sign in again', exact: true }).click();
  await page.getByRole('button', { name: 'Delete session', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Protect your Telegram session' })).toBeVisible();
  expect(await nativeCalls(page, 'cmd_logout')).toHaveLength(1);
  await page.getByLabel('Passphrase', { exact: true }).fill('a long enough passphrase');
  await page.getByLabel('Confirm passphrase', { exact: true }).fill('a long enough passphrase');
  await page.getByRole('button', { name: 'Protect session', exact: true }).click();
  await expect(page.getByText('Holiday folder photo.jpg', { exact: true })).toBeVisible();
  expect(await nativeCalls(page, 'cmd_unlock_session')).toEqual([{ command: 'cmd_unlock_session', args: { passphrase: 'a long enough passphrase' } }]);
});

test('a failed removal on the credential store screen is reported and keeps the session', async ({ page }) => {
  await desktopFixture(page, { sessionProtection: 'keychain-unavailable' });
  await page.goto('/');
  await page.evaluate(() => { (window as any).__desktopTest.logoutFails = true; });
  await page.getByRole('button', { name: 'Remove saved session and sign in again', exact: true }).click();
  await page.getByRole('button', { name: 'Delete session', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'The operation could not be completed.' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'System credential store unavailable' })).toBeVisible();
  await expect(page.getByText('Private native diagnostic')).toHaveCount(0);
});
