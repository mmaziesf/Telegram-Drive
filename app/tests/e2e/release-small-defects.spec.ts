import { expect, test } from '@playwright/test';
import { desktopFixture, nativeCalls, openSettings } from './desktop-fixture';

test('sign-in offers no donation, purchase or sponsor content', async ({ page }) => {
  await desktopFixture(page, { signedOut: true });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'QR-first secure sign in', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /donat|support|licen/i })).toHaveCount(0);
  await expect(page.locator('iframe')).toHaveCount(0);
});

test('the signed-in workspace and settings offer no purchase or sponsor content', async ({ page }) => {
  await desktopFixture(page);
  await page.goto('/');
  await expect(page.getByText('Holiday folder photo.jpg', { exact: true })).toBeVisible();
  await expect(page.locator('iframe')).toHaveCount(0);
  await expect(page.getByText(/sponsored|ad-free|\$5/i)).toHaveCount(0);
  await openSettings(page);
  await expect(page.getByRole('button', { name: /licen[cs]e|supporter/i })).toHaveCount(0);
  expect(await nativeCalls(page, 'plugin:shell|open')).toHaveLength(0);
});

test('storage insights show when their retained inventory is partial', async ({ page }) => {
  await desktopFixture(page);
  await page.goto('/');
  await expect(page.getByText('Holiday folder photo.jpg', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Large files', exact: true }).click();
  await expect(page.getByText('1200 indexed results · partial inventory', { exact: true })).toBeVisible();
});
