import { useTranslation } from 'react-i18next';
import { useCallback, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { ShieldAlert, X } from 'lucide-react';
import { useModalFocus } from '../../../hooks/useModalFocus';
import i18n from '../../../i18n';

/** A session an earlier sign-out could not end, as the backend offers it. */
export interface StaleSession {
    id: string;
    device: string;
    app: string;
    /** Unix seconds. */
    lastActive: number;
}

interface EndOutcome {
    ended: string[];
    failed: string[];
}

interface StaleSessionsDialogProps {
    sessions: StaleSession[];
    /** Hides the dialog; any session left unconfirmed is offered again next sign-in. */
    onClose: () => void;
}

function lastActive(seconds: number): string {
    const date = new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(seconds * 1000));
    return i18n.t('stale_sessions.last_active', { date });
}

function SessionLabel({ session }: { session: StaleSession }) {
    return (
        <span className="min-w-0">
            <span className="block truncate text-sm font-medium text-app-text">{session.device || i18n.t('stale_sessions.unknown_device')}</span>
            <span className="block truncate text-xs text-app-text-secondary">{session.app || i18n.t('stale_sessions.unknown_app')} · {lastActive(session.lastActive)}</span>
        </span>
    );
}

/**
 * Lists sessions a sign-out left signed in. Nothing is selected to begin
 * with and nothing ends until the user picks sessions and confirms them; the
 * backend re-checks every id, so the current session can never be ended.
 */
export function StaleSessionsDialog({ sessions, onClose }: StaleSessionsDialogProps) {
    useTranslation();
    const [remaining, setRemaining] = useState(sessions);
    const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set());
    const [confirming, setConfirming] = useState(false);
    const [busy, setBusy] = useState(false);
    const [failed, setFailed] = useState(false);
    const panelRef = useRef<HTMLDivElement>(null);
    const close = useCallback(onClose, [onClose]);
    useModalFocus(panelRef, close);

    const toggle = (id: string) => setSelected(current => {
        const next = new Set(current);
        if (next.has(id)) next.delete(id); else next.add(id);
        return next;
    });

    const keep = async () => {
        setBusy(true);
        try {
            await invoke('cmd_dismiss_stale_sessions');
            onClose();
        } catch {
            setFailed(true);
        } finally {
            setBusy(false);
        }
    };

    const end = async () => {
        setBusy(true);
        setFailed(false);
        try {
            const outcome = await invoke<EndOutcome>('cmd_end_stale_sessions', { ids: [...selected] });
            const ended = new Set(outcome.ended);
            const left = remaining.filter(session => !ended.has(session.id));
            if (left.length === 0) {
                onClose();
                return;
            }
            setRemaining(left);
            setFailed(outcome.failed.length > 0);
        } catch {
            setFailed(true);
        } finally {
            setSelected(new Set());
            setConfirming(false);
            setBusy(false);
        }
    };

    const chosen = remaining.filter(session => selected.has(session.id));

    return (
        <div className="fixed inset-0 z-[210] flex items-center justify-center bg-app-overlay p-4 backdrop-blur-sm">
            <div ref={panelRef} role="dialog" aria-modal="true" aria-labelledby="stale-sessions-title" tabIndex={-1} className="quiet-raised w-[min(480px,calc(100vw-2rem))] overflow-hidden">
                <header className="flex items-center justify-between border-b border-app-border-subtle px-5 py-4">
                    <h2 id="stale-sessions-title" className="flex items-center gap-2 text-base font-semibold text-app-text"><ShieldAlert className="h-4 w-4 text-app-accent" />{i18n.t('stale_sessions.title')}</h2>
                    <button type="button" onClick={onClose} className="quiet-control p-2 text-app-text-secondary hover:text-app-text" aria-label={i18n.t('common.close')}><X className="h-4 w-4" /></button>
                </header>
                <div className="space-y-3 p-5">
                    <p className="text-sm leading-6 text-app-text-secondary">{i18n.t(confirming ? 'stale_sessions.confirm' : 'stale_sessions.intro')}</p>
                    {failed && <p role="alert" className="text-sm text-app-danger">{i18n.t('stale_sessions.failed')}</p>}
                    <ul className="max-h-72 space-y-2 overflow-y-auto">
                        {(confirming ? chosen : remaining).map(session => (
                            <li key={session.id}>
                                {confirming ? (
                                    <div className="flex gap-3 rounded-lg border border-app-border-subtle p-3"><SessionLabel session={session} /></div>
                                ) : (
                                    <label className="flex cursor-pointer items-center gap-3 rounded-lg border border-app-border-subtle p-3 hover:bg-app-surface-sunken/40">
                                        <input type="checkbox" checked={selected.has(session.id)} onChange={() => toggle(session.id)} disabled={busy} className="h-4 w-4 shrink-0 accent-app-accent" />
                                        <SessionLabel session={session} />
                                    </label>
                                )}
                            </li>
                        ))}
                    </ul>
                </div>
                <footer className="flex justify-end gap-3 border-t border-app-border-subtle px-5 py-4">
                    {confirming ? (
                        <>
                            <button type="button" onClick={() => setConfirming(false)} disabled={busy} className="quiet-control px-4 py-2.5 text-sm font-medium text-app-text-secondary hover:text-app-text">{i18n.t('stale_sessions.back')}</button>
                            <button type="button" onClick={() => void end()} disabled={busy} className="quiet-control bg-app-danger/10 px-4 py-2.5 text-sm font-medium text-app-danger hover:bg-app-danger/16 disabled:opacity-50">{i18n.t('stale_sessions.confirm_end')}</button>
                        </>
                    ) : (
                        <>
                            <button type="button" onClick={() => void keep()} disabled={busy} className="quiet-control px-4 py-2.5 text-sm font-medium text-app-text-secondary hover:text-app-text">{i18n.t('stale_sessions.keep')}</button>
                            <button type="button" onClick={() => setConfirming(true)} disabled={busy || chosen.length === 0} className="quiet-control bg-app-accent px-4 py-2.5 text-sm font-medium text-app-accent-contrast hover:bg-app-accent-hover disabled:opacity-50">{i18n.t('stale_sessions.end_selected')}</button>
                        </>
                    )}
                </footer>
            </div>
        </div>
    );
}
