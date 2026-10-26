import { expect, test, type Page } from '@playwright/test';
import { desktopFixture } from './desktop-fixture';

// First-run encryption setup and the default-on upload protection policy.
// Native cryptography is a controlled boundary covered by native E2E.
const storedSettings = (page: Page) => page.evaluate(() => JSON.parse(localStorage.getItem('desktop-e2e-stores')!)['settings.json'].settings);

test('a new install asks to set up encryption and turns protected uploads on', async ({ page }) => {
  await desktopFixture(page, { encryptionReady: true, vaultState: 'none', settings: { encryptionSetupSeen: false } });
  await page.goto('/');
  const dialog = page.getByRole('dialog', { name: 'Encrypt your uploads' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText('Files you already uploaded stay readable.', { exact: false })).toBeVisible();
  await dialog.getByRole('button', { name: 'Turn on encryption (recommended)' }).click();

  const vaultDialog = dialog;
  await expect(vaultDialog.getByRole('button', { name: 'Create Vault', exact: true })).toBeVisible();
  await expect(vaultDialog.getByRole('button', { name: 'Finish', exact: true })).toBeDisabled();
  await vaultDialog.getByPlaceholder('Vault passphrase (min 8 characters)').fill('correct horse battery');
  await vaultDialog.getByPlaceholder('Confirm passphrase').fill('correct horse battery');
  await vaultDialog.getByRole('checkbox').check();
  await vaultDialog.getByRole('button', { name: 'Create Vault', exact: true }).click();
  await vaultDialog.getByRole('button', { name: 'Finish', exact: true }).click();

  await expect(dialog).toHaveCount(0);
  await expect.poll(() => storedSettings(page)).toMatchObject({ encryptionDefaultMode: 'vault', encryptionProtectMetadata: true, encryptionSetupSeen: true });
});

test('opting out of encryption requires a visible warning confirmation', async ({ page }) => {
  await desktopFixture(page, { encryptionReady: true, vaultState: 'none', settings: { encryptionSetupSeen: false } });
  await page.goto('/');
  const dialog = page.getByRole('dialog', { name: 'Encrypt your uploads' });
  await dialog.getByRole('button', { name: 'Keep uploads unencrypted' }).click();
  const warning = page.getByRole('dialog', { name: 'Upload without encryption?' });
  await expect(warning.getByRole('alert')).toContainText('Telegram, and anyone who gets into your Telegram account, can read them.');
  await warning.getByRole('button', { name: 'Keep unencrypted', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect.poll(() => storedSettings(page)).toMatchObject({ encryptionDefaultMode: 'standard', encryptionSetupSeen: true });
});

test('existing users on plaintext uploads are offered the setup, and Not now defers it for the session', async ({ page }) => {
  await desktopFixture(page, { encryptionReady: true, vaultState: 'none', settings: { encryptionSetupSeen: false, encryptionDefaultMode: 'standard' } });
  await page.goto('/');
  const dialog = page.getByRole('dialog', { name: 'Encrypt your uploads' });
  await dialog.getByRole('button', { name: 'Not now', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  const settings = await storedSettings(page);
  expect(settings.encryptionSetupSeen).toBe(false);
  expect(settings.encryptionDefaultMode).toBe('standard');
});

test('users who already protect uploads with a vault are not prompted', async ({ page }) => {
  await desktopFixture(page, { encryptionReady: true, vaultState: 'locked', settings: { encryptionSetupSeen: false, encryptionDefaultMode: 'vault' } });
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Upload', exact: true })).toBeVisible();
  await expect(page.getByRole('dialog', { name: 'Encrypt your uploads' })).toHaveCount(0);
});

test('the upload choice recommends protection and warns before a plaintext upload', async ({ page }) => {
  await desktopFixture(page, { encryptionReady: true, vaultState: 'unlocked', pickedUploadPaths: ['/fixtures/Holiday.mp4'] });
  await page.goto('/');
  await page.getByRole('button', { name: 'Upload', exact: true }).click();
  const dialog = page.getByRole('dialog');
  const choices = dialog.getByRole('button', { name: /^Store/ });
  await expect(choices.first()).toHaveAccessibleName(/^Store & protect Recommended/);
  await expect(dialog.getByRole('button', { name: /^Store Upload normally/ })).toContainText('Not encrypted: Telegram can read this file.');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
});
