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
