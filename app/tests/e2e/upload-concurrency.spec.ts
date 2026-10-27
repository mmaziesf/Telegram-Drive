import { expect, test } from '@playwright/test';
import { desktopFixture, nativeCalls, openSettings } from './desktop-fixture';

const lastLimits = async (page: Parameters<typeof nativeCalls>[0]) =>
  (await nativeCalls(page, 'cmd_transfer_set_limits')).at(-1)?.args;

test('A new install uploads two files at a time and can raise that to four at most', async ({ page }) => {
  await desktopFixture(page);
  await page.goto('/');
  await expect.poll(async () => (await lastLimits(page))?.maxUploads).toBe(2);
  await openSettings(page);
  const stepper = page.getByRole('dialog').getByRole('group', { name: 'Concurrent Uploads' });
  await expect(stepper).toContainText('2');
  const increase = stepper.getByRole('button', { name: 'Increase Concurrent Uploads' });
  await increase.click();
  await increase.click();
  await expect(stepper).toContainText('4');
  await expect(increase).toBeDisabled();
  await expect.poll(async () => (await lastLimits(page))?.maxUploads).toBe(4);
});

test('An upload limit saved by an older version above four is lowered to four', async ({ page }) => {
  await desktopFixture(page, { settings: { maxConcurrentUploads: 10, maxConcurrentDownloads: 8 } });
  await page.goto('/');
  await expect.poll(async () => lastLimits(page)).toEqual({ maxUploads: 4, maxDownloads: 8 });
  await openSettings(page);
  const stepper = page.getByRole('dialog').getByRole('group', { name: 'Concurrent Uploads' });
  await expect(stepper).toContainText('4');
  await expect(stepper.getByRole('button', { name: 'Increase Concurrent Uploads' })).toBeDisabled();
});
