import { useCallback, useRef, useState } from 'react';
import { AlertTriangle, LockKeyhole, ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useSettings } from '../../context/SettingsContext';
import { useEncryption } from '../../hooks/useEncryption';
import { useModalFocus } from '../../hooks/useModalFocus';
import { EncryptionSettingsSection } from './EncryptionSettingsSection';

type Step = 'intro' | 'vault' | 'confirm_plain';

/**
 * First-run dialog that makes encrypted uploads the default. It walks the
 * user through creating or unlocking a vault; keeping plaintext uploads
 * requires an explicit confirmation of the risk. Answering either way
 * records `encryptionSetupSeen`, while `onDefer` closes the dialog without
 * changing settings so it is offered again later.
 */
export function EncryptionSetupPrompt({ onDefer }: { onDefer: () => void }) {
    const { t } = useTranslation();
    const { settings, updateSettings } = useSettings();
    const encryption = useEncryption();
    const [step, setStep] = useState<Step>('intro');
    const panelRef = useRef<HTMLDivElement>(null);
    const defer = useCallback(() => onDefer(), [onDefer]);
    useModalFocus(panelRef, defer, true);

    const vaultUnlocked = encryption.vaultStatus?.is_unlocked === true;
    const finishProtected = () => {
        updateSettings({
            encryptionDefaultMode: settings.encryptionDefaultMode === 'standard' ? 'vault' : settings.encryptionDefaultMode,
            encryptionProtectMetadata: true,
            encryptionSetupSeen: true,
        });
    };
    const keepPlain = () => {
        updateSettings({ encryptionDefaultMode: 'standard', encryptionSetupSeen: true });
    };
    const startProtected = async () => {
        await encryption.refreshVaultStatus();
        setStep('vault');
    };

    return (
        <div className="fixed inset-0 z-[300] flex items-center justify-center bg-app-overlay p-4 backdrop-blur-sm" role="presentation">
            <div
                ref={panelRef}
                role="dialog"
                aria-modal="true"
                aria-labelledby="encryption-setup-title"
                tabIndex={-1}
                className="quiet-raised max-h-[calc(100vh-2rem)] w-[min(520px,calc(100vw-2rem))] overflow-y-auto p-6"
            >
                {step === 'intro' && <>
                    <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl bg-app-accent/10 text-app-accent">
                        <LockKeyhole className="h-5 w-5" aria-hidden="true" />
                    </div>
                    <h2 id="encryption-setup-title" className="text-lg font-semibold text-app-text">{t('encryption_setup.title')}</h2>
                    <p className="mt-2 text-sm leading-6 text-app-text-secondary">{t('encryption_setup.body')}</p>
                    <div className="mt-4 flex gap-3 rounded-lg border border-app-border-subtle bg-app-surface-sunken/30 p-3 text-xs leading-5 text-app-text-secondary">
                        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-app-success" aria-hidden="true" />
                        <span>{t('encryption_setup.existing_files')}</span>
                    </div>
                    <div className="mt-6 flex flex-wrap justify-end gap-3">
                        <button type="button" onClick={defer} className="quiet-control px-4 py-2.5 text-sm font-medium text-app-text-secondary hover:text-app-text">{t('encryption_setup.later')}</button>
                        <button type="button" onClick={() => setStep('confirm_plain')} className="quiet-control px-4 py-2.5 text-sm font-medium text-app-text-secondary hover:text-app-text">{t('encryption_setup.keep_plain')}</button>
                        <button type="button" onClick={() => void startProtected()} className="quiet-control bg-app-accent px-4 py-2.5 text-sm font-medium text-app-accent-contrast hover:bg-app-accent-hover">{t('encryption_setup.enable')}</button>
                    </div>
                </>}
                {step === 'vault' && <>
                    <h2 id="encryption-setup-title" className="text-lg font-semibold text-app-text">{t('encryption_setup.title')}</h2>
                    <p className="mt-1 mb-5 text-sm text-app-text-secondary">{t('settings.encryption_disclaimer_body')}</p>
                    <EncryptionSettingsSection vaultOnly />
                    <div className="sticky bottom-0 mt-5 flex flex-wrap justify-end gap-2 border-t border-app-border-subtle bg-app-surface pt-4">
                        <button type="button" onClick={() => setStep('intro')} className="quiet-control min-h-11 px-4 text-sm font-medium text-app-text-secondary hover:text-app-text">{t('encryption_setup.back')}</button>
                        <button type="button" disabled={!vaultUnlocked} onClick={finishProtected} className="min-h-11 rounded-lg bg-app-accent px-4 text-sm font-semibold text-app-accent-contrast disabled:opacity-40">{t('encryption_setup.finish')}</button>
                    </div>
                </>}
                {step === 'confirm_plain' && <>
                    <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl bg-app-warning/10 text-app-warning">
                        <AlertTriangle className="h-5 w-5" aria-hidden="true" />
                    </div>
                    <h2 id="encryption-setup-title" className="text-lg font-semibold text-app-text">{t('encryption_setup.plain_warning_title')}</h2>
                    <p role="alert" className="mt-2 text-sm leading-6 text-app-text-secondary">{t('encryption_setup.plain_warning_body')}</p>
                    <div className="mt-6 flex flex-wrap justify-end gap-3">
                        <button type="button" onClick={() => setStep('intro')} className="quiet-control px-4 py-2.5 text-sm font-medium text-app-text-secondary hover:text-app-text">{t('encryption_setup.back')}</button>
                        <button type="button" onClick={keepPlain} className="quiet-control border border-app-danger/40 px-4 py-2.5 text-sm font-medium text-app-text hover:bg-app-danger/10">{t('encryption_setup.confirm_plain')}</button>
                    </div>
                </>}
            </div>
        </div>
    );
}
