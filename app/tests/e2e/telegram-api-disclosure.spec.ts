import { expect, test } from '@playwright/test';
import { desktopFixture, nativeCalls, openSettings } from './desktop-fixture';

const notice = 'This unofficial app uses the Telegram API. It is not affiliated with, endorsed by or sponsored by Telegram.';

test('the sign-in screen discloses that the app is an unofficial Telegram API client', async ({ page }) => {
  await desktopFixture(page, { signedOut: true });
  await page.goto('/');
  await expect(page.getByTestId('telegram-api-notice')).toHaveText(notice);
});

test('the first-run introduction discloses the Telegram API and the notice leaves with it', async ({ page }) => {
  await desktopFixture(page, { settings: { driveTourSeen: false } });
  await page.goto('/');
  const tour = page.getByRole('dialog');
  await expect(tour.getByTestId('telegram-api-notice')).toHaveText(notice);
  await tour.getByRole('button', { name: 'Skip drive introduction', exact: true }).click();
  await expect(page.getByTestId('telegram-api-notice')).toHaveCount(0);
});

test('About discloses that the app is an unofficial Telegram API client', async ({ page }) => {
  await desktopFixture(page);
  await page.goto('/');
  await openSettings(page);
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: 'About', exact: true }).click();
  await expect(dialog.getByTestId('telegram-api-notice')).toHaveText(notice);
});

test('About links to this fork and credits the original project', async ({ page }) => {
  await desktopFixture(page);
  await page.goto('/');
  await openSettings(page);
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: 'About', exact: true }).click();
  const attribution = dialog.getByTestId('project-attribution');
  await expect(attribution).toContainText('Based on the original Telegram Drive by Cameron Amer:');
  await attribution.getByRole('button', { name: 'github.com/mmaziesf/Telegram-Drive', exact: true }).click();
  await attribution.getByRole('button', { name: 'github.com/caamer20/Telegram-Drive', exact: true }).click();
  await expect.poll(async () => (await nativeCalls(page, 'plugin:shell|open')).map(call => call.args.path)).toEqual([
    'https://github.com/mmaziesf/Telegram-Drive',
    'https://github.com/caamer20/Telegram-Drive',
  ]);
});

test('the first-run introduction warns about Telegram account risks and links the terms and self-destruct FAQ', async ({ page }) => {
  await desktopFixture(page, { settings: { driveTourSeen: false } });
  await page.goto('/');
  const tour = page.getByRole('dialog');
  for (let step = 0; step < 3; step += 1) {
    await tour.getByRole('button', { name: 'Next', exact: true }).click();
  }
  await expect(tour.getByRole('heading', { name: 'Protect your Telegram account', exact: true })).toBeVisible();
  await expect(tour).toContainText('under observation');
  await expect(tour).toContainText('no storage guarantee or SLA');
  await expect(tour).toContainText('keep your own backups');
  await tour.getByRole('button', { name: 'Telegram API Terms of Service', exact: true }).click();
  await tour.getByRole('button', { name: 'How account self-destruction works', exact: true }).click();
  await expect.poll(async () => (await nativeCalls(page, 'plugin:shell|open')).map(call => call.args.path)).toEqual([
    'https://core.telegram.org/api/terms',
    'https://telegram.org/faq#q-how-does-account-self-destruction-work',
  ]);
  await tour.getByRole('button', { name: 'Finish', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Protect your Telegram account', exact: true })).toHaveCount(0);
});
