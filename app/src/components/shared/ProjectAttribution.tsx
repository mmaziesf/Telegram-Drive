import { Github } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { FORK_REPOSITORY_URL, UPSTREAM_AUTHOR, UPSTREAM_REPOSITORY_URL, displayUrl } from '../../services/projectLinks';

interface ProjectAttributionProps {
  /** Opens an external URL with the platform's opener. */
  onOpen: (url: string) => void;
  /** Typography classes for the surrounding screen. */
  className?: string;
}

/**
 * Links to this fork's source and credits the original project and its
 * author. Shown in About on desktop and mobile.
 */
export function ProjectAttribution({ onOpen, className = '' }: ProjectAttributionProps) {
  const { t } = useTranslation();
  return (
    <div data-testid="project-attribution" className={`space-y-2 text-center ${className}`}>
      <button
        type="button"
        onClick={() => onOpen(FORK_REPOSITORY_URL)}
        className="mx-auto flex cursor-pointer items-center justify-center gap-1.5 text-telegram-primary transition-colors hover:text-telegram-primary/80"
      >
        <Github className="h-3.5 w-3.5" aria-hidden="true" />
        {displayUrl(FORK_REPOSITORY_URL)}
      </button>
      <p className="text-telegram-subtext">
        {t('settings.upstream_credit', { author: UPSTREAM_AUTHOR })}{' '}
        <button
          type="button"
          onClick={() => onOpen(UPSTREAM_REPOSITORY_URL)}
          className="cursor-pointer text-telegram-primary underline-offset-2 hover:underline"
        >
          {displayUrl(UPSTREAM_REPOSITORY_URL)}
        </button>
      </p>
    </div>
  );
}
