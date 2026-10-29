import { invoke } from "@tauri-apps/api/core";
import { type } from "@tauri-apps/plugin-os";

/** How the saved Telegram session is protected at rest (desktop only). */
export interface SessionStorageStatus {
  /** `keychain` keeps the key in the system credential store; `passphrase` derives it. */
  protection: "keychain" | "passphrase";
  /** A passphrase must be entered before the session can open. */
  locked: boolean;
  /** No session exists yet, so the passphrase must be chosen rather than entered. */
  setup: boolean;
}

/** A session that cannot open until the user acts. */
export type SessionLock =
  | { kind: "passphrase"; setup: boolean }
  | { kind: "keychain-unavailable" };

/** Shortest passphrase the backend accepts (`MIN_PASSPHRASE_CHARS`). */
export const MIN_SESSION_PASSPHRASE_CHARS = 12;

function isDesktop(): boolean {
  try {
    const os = type();
    return os !== "android" && os !== "ios";
  } catch {
    // Outside Tauri (browser previews) there is no session store to unlock.
    return false;
  }
}

/** The error code prefix the backend puts before `:` in a session error. */
export function sessionErrorCode(error: unknown): string | null {
  const match = /^(SESSION_[A-Z_]+):/.exec(String(error));
  return match ? match[1] : null;
}

/**
 * The action needed before the saved session can open, or `null` when it can
 * open now. Mobile builds keep their session in app-private storage and do not
 * register the command, so they never report a lock.
 */
export async function readSessionLock(): Promise<SessionLock | null> {
  if (!isDesktop()) return null;
  const status = await invoke<SessionStorageStatus>("cmd_session_storage_status");
  return status.locked ? { kind: "passphrase", setup: status.setup } : null;
}

/** Map a failed session open to the screen that resolves it, if any. */
export function lockFromSessionError(error: unknown): SessionLock | null {
  switch (sessionErrorCode(error)) {
    case "SESSION_PASSPHRASE_SETUP":
      return { kind: "passphrase", setup: true };
    case "SESSION_LOCKED":
      return { kind: "passphrase", setup: false };
    case "SESSION_KEYCHAIN_UNAVAILABLE":
      return { kind: "keychain-unavailable" };
    default:
      return null;
  }
}

/** Enter the passphrase, or choose it for a new session. */
export function unlockSession(passphrase: string): Promise<void> {
  return invoke("cmd_unlock_session", { passphrase });
}
