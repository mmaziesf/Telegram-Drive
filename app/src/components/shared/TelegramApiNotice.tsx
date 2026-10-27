import { useTranslation } from 'react-i18next';

interface TelegramApiNoticeProps {
  /** Layout and typography classes for the surrounding screen. */
  className?: string;
}

/**
 * States that the app is an unofficial client built on the Telegram API and
 * is not affiliated with Telegram, as the Telegram API Terms of Service
 * require. Shown on the sign-in screen, the first-run introduction and About.
 */
export function TelegramApiNotice({ className = '' }: TelegramApiNoticeProps) {
  const { t } = useTranslation();
  return (
    <p data-testid="telegram-api-notice" className={className}>
      {t('common.telegram_api_notice')}
    </p>
  );
}
