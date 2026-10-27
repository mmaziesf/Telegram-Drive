import { expect, test } from '@playwright/test';
import { desktopFixture, nativeCalls } from './desktop-fixture';

// Sessions an earlier sign-out could not end, as the backend offers them: never the current one.
const staleSessions = [
  { id: '-9007199254740993', device: 'Pixel 8 Android 15', app: 'Telegram Drive 4.0.0', lastActive: 1_790_000_000 },
  { id: '4242', device: 'Desktop Windows 11', app: 'Telegram Drive 4.1.0', lastActive: 1_790_500_000 },
];

test('without stale sessions nothing is offered', async ({ page }) => {
  await desktopFixture(page);
  await page.goto('/');
  await expect(page.getByText('Holiday folder photo.jpg', { exact: true })).toBeVisible();
  expect((await nativeCalls(page, 'cmd_stale_sessions')).length).toBeGreaterThan(0);
  await expect(page.getByRole('dialog', { name: 'Sessions still signed in' })).toHaveCount(0);
});

test('stale sessions start unselected and end only after an explicit confirmation', async ({ page }) => {
  await desktopFixture(page, { staleSessions });
  await page.goto('/');
  const dialog = page.getByRole('dialog', { name: 'Sessions still signed in' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText('Pixel 8 Android 15', { exact: true })).toBeVisible();
  await expect(dialog.getByText(/Telegram Drive 4\.0\.0 · Last active /)).toBeVisible();
  const boxes = dialog.getByRole('checkbox');
  await expect(boxes).toHaveCount(2);
  for (const box of await boxes.all()) await expect(box).not.toBeChecked();
  const endSelected = dialog.getByRole('button', { name: 'End selected sessions', exact: true });
  await expect(endSelected).toBeDisabled();

  await dialog.getByRole('checkbox', { name: /Pixel 8 Android 15/ }).check();
  await endSelected.click();
  // The confirmation step lists only the chosen session and ends nothing yet.
  await expect(dialog.getByText('These sessions will be signed out of Telegram. This cannot be undone.')).toBeVisible();
  await expect(dialog.getByText('Pixel 8 Android 15', { exact: true })).toBeVisible();
  await expect(dialog.getByText('Desktop Windows 11', { exact: true })).toHaveCount(0);
  expect(await nativeCalls(page, 'cmd_end_stale_sessions')).toHaveLength(0);

  await dialog.getByRole('button', { name: 'End sessions', exact: true }).click();
  // The full-precision id is sent unchanged, and the other session stays offered and unselected.
  const calls = await nativeCalls(page, 'cmd_end_stale_sessions');
  expect(calls.map(call => call.args.ids)).toEqual([['-9007199254740993']]);
  await expect(dialog.getByText('Pixel 8 Android 15', { exact: true })).toHaveCount(0);
  await expect(dialog.getByRole('checkbox', { name: /Desktop Windows 11/ })).not.toBeChecked();
  expect(await nativeCalls(page, 'cmd_dismiss_stale_sessions')).toHaveLength(0);
});

test('backing out of the confirmation ends nothing', async ({ page }) => {
  await desktopFixture(page, { staleSessions });
  await page.goto('/');
  const dialog = page.getByRole('dialog', { name: 'Sessions still signed in' });
  await dialog.getByRole('checkbox', { name: /Desktop Windows 11/ }).check();
  await dialog.getByRole('button', { name: 'End selected sessions', exact: true }).click();
  await dialog.getByRole('button', { name: 'Back', exact: true }).click();
  await expect(dialog.getByRole('checkbox')).toHaveCount(2);
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  expect(await nativeCalls(page, 'cmd_end_stale_sessions')).toHaveLength(0);
  // Closing is "decide later": the pending list is kept for the next sign-in.
  expect(await nativeCalls(page, 'cmd_dismiss_stale_sessions')).toHaveLength(0);
});

test('a session Telegram refuses to end stays offered with an explanation', async ({ page }) => {
  await desktopFixture(page, { staleSessions, staleSessionFailures: ['4242'] });
  await page.goto('/');
  const dialog = page.getByRole('dialog', { name: 'Sessions still signed in' });
  await expect(dialog.getByRole('checkbox')).toHaveCount(2);
  for (const box of await dialog.getByRole('checkbox').all()) await box.check();
  await dialog.getByRole('button', { name: 'End selected sessions', exact: true }).click();
  await dialog.getByRole('button', { name: 'End sessions', exact: true }).click();
  await expect(dialog.getByRole('alert')).toHaveText("Some sessions could not be ended. Try again, or end them in Telegram's settings.");
  await expect(dialog.getByRole('checkbox')).toHaveCount(1);
  await expect(dialog.getByRole('checkbox', { name: /Desktop Windows 11/ })).not.toBeChecked();
});

test('keeping the sessions clears the pending list without ending any', async ({ page }) => {
  await desktopFixture(page, { staleSessions });
  await page.goto('/');
  const dialog = page.getByRole('dialog', { name: 'Sessions still signed in' });
  await dialog.getByRole('button', { name: 'Keep these sessions', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(await nativeCalls(page, 'cmd_dismiss_stale_sessions')).toHaveLength(1);
  expect(await nativeCalls(page, 'cmd_end_stale_sessions')).toHaveLength(0);
});
