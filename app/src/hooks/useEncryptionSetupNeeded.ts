import { useEffect, useState } from 'react';
import { useSettings } from '../context/SettingsContext';
import { useEncryption } from './useEncryption';

/**
 * Whether the first-run encryption setup should be offered on this device.
 * It is shown once the drive tour is done, when encryption is available and
 * uploads are not already protected by an existing vault.
 */
export function useEncryptionSetupNeeded(): boolean {
    const { settings, isLoaded } = useSettings();
    const encryption = useEncryption();
    // Once offered, the prompt stays up until it is answered, even after the
    // vault it creates makes uploads protected.
    const [engaged, setEngaged] = useState(false);
    const pending = isLoaded && settings.driveTourSeen && !settings.encryptionSetupSeen;
    const vault = encryption.vaultStatus;
    const needed = pending
        && encryption.capabilityState === 'ready'
        && encryption.capabilities?.upload_enabled === true
        && vault !== null
        && !(vault.exists && settings.encryptionDefaultMode !== 'standard');
    useEffect(() => {
        if (needed) setEngaged(true);
    }, [needed]);
    return pending && (needed || engaged);
}
