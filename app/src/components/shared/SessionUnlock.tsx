import { useState, type FormEvent } from "react";
import { invoke } from "@tauri-apps/api/core";
import { KeyRound, Lock, ShieldAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import {
  MIN_SESSION_PASSPHRASE_CHARS,
  sessionErrorCode,
  unlockSession,
  type SessionLock,
} from "../../services/sessionStorage";

interface SessionUnlockProps {
  lock: SessionLock;
  /** Called after the lock is resolved or the saved session was removed. */
  onResolved: () => void;
}

/**
 * Shown before the saved Telegram session can open: either the passphrase
 * that encrypts it must be entered (or chosen, for a new session), or the
 * system credential store that holds its key cannot be reached.
 */
export function SessionUnlock({ lock, onResolved }: SessionUnlockProps) {
  const { t } = useTranslation();
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmRemoval, setConfirmRemoval] = useState(false);
  const setup = lock.kind === "passphrase" && lock.setup;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (setup && passphrase.length < MIN_SESSION_PASSPHRASE_CHARS) {
      setError(t("session_lock.too_short", { min: MIN_SESSION_PASSPHRASE_CHARS }));
      return;
    }
    if (setup && passphrase !== confirmation) {
      setError(t("session_lock.mismatch"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await unlockSession(passphrase);
      setPassphrase("");
      setConfirmation("");
      onResolved();
    } catch (failure) {
      const code = sessionErrorCode(failure);
      setError(
        code === "SESSION_PASSPHRASE_INCORRECT"
          ? t("session_lock.incorrect")
          : code === "SESSION_PASSPHRASE_TOO_SHORT"
            ? t("session_lock.too_short", { min: MIN_SESSION_PASSPHRASE_CHARS })
            : t("session_lock.failed"),
      );
    } finally {
      setBusy(false);
    }
  };

  const removeSession = async () => {
    setBusy(true);
    setError(null);
    try {
      // Without the passphrase the session cannot be decrypted, so sign-out
      // only deletes the local copy and its key.
      await invoke("cmd_logout");
      onResolved();
    } catch {
      setError(t("session_lock.failed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-gradient flex h-full w-full items-center justify-center overflow-y-auto p-4 text-app-text sm:p-6">
      <div className="auth-glass my-auto w-full max-w-[26rem] space-y-5 rounded-overlay p-5 sm:p-6">
        <div className="text-center">
          <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-container bg-app-selected">
            {lock.kind === "keychain-unavailable"
              ? <ShieldAlert className="h-6 w-6 text-app-danger" aria-hidden="true" />
              : <KeyRound className="h-6 w-6 text-app-accent" aria-hidden="true" />}
          </div>
          <h1 className="text-app-title font-semibold text-app-text">
            {lock.kind === "keychain-unavailable"
              ? t("session_lock.keychain_title")
              : setup ? t("session_lock.title_setup") : t("session_lock.title_enter")}
          </h1>
          <p className="mt-2 text-metadata text-app-text-secondary">
            {lock.kind === "keychain-unavailable"
              ? t("session_lock.keychain_detail")
              : setup
                ? t("session_lock.detail_setup", { min: MIN_SESSION_PASSPHRASE_CHARS })
                : t("session_lock.detail_enter")}
          </p>
        </div>

        {lock.kind === "keychain-unavailable" ? (
          <button type="button" onClick={onResolved} className="quiet-control auth-primary-action">
            {t("session_lock.retry")}
          </button>
        ) : (
          <form onSubmit={event => void submit(event)} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="session-passphrase" className="auth-label">{t("session_lock.passphrase")}</label>
              <div className="relative">
                <Lock className="auth-input-icon" aria-hidden="true" />
                <input
                  id="session-passphrase"
                  type="password"
                  autoComplete={setup ? "new-password" : "current-password"}
                  value={passphrase}
                  onChange={event => setPassphrase(event.target.value)}
                  className="auth-input"
                  autoFocus
                />
              </div>
            </div>
            {setup && (
              <div className="space-y-2">
                <label htmlFor="session-passphrase-confirm" className="auth-label">{t("session_lock.confirm")}</label>
                <div className="relative">
                  <Lock className="auth-input-icon" aria-hidden="true" />
                  <input
                    id="session-passphrase-confirm"
                    type="password"
                    autoComplete="new-password"
                    value={confirmation}
                    onChange={event => setConfirmation(event.target.value)}
                    className="auth-input"
                  />
                </div>
              </div>
            )}
            {error && <p role="alert" className="text-center text-metadata text-app-danger">{error}</p>}
            <button type="submit" disabled={busy || !passphrase} className="quiet-control auth-primary-action disabled:opacity-45">
              {busy ? t("session_lock.working") : setup ? t("session_lock.submit_setup") : t("session_lock.submit_enter")}
            </button>
          </form>
        )}

        {lock.kind === "passphrase" && !setup && (
          confirmRemoval ? (
            <div className="space-y-3 rounded-control border border-app-danger/30 p-3">
              <p className="text-metadata text-app-text-secondary">{t("session_lock.remove_detail")}</p>
              <div className="flex gap-2">
                <button type="button" disabled={busy} onClick={() => void removeSession()} className="quiet-control auth-secondary-action w-full text-app-danger">
                  {t("session_lock.remove_confirm")}
                </button>
                <button type="button" disabled={busy} onClick={() => setConfirmRemoval(false)} className="quiet-control auth-secondary-action w-full">
                  {t("common.cancel")}
                </button>
              </div>
            </div>
          ) : (
            <button type="button" onClick={() => setConfirmRemoval(true)} className="quiet-control auth-secondary-action w-full">
              {t("session_lock.forgot")}
            </button>
          )
        )}
      </div>
    </div>
  );
}
