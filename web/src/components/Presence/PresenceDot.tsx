// src/components/Presence/PresenceDot.tsx
//
// Presence indicator — Arctic Signal design.
// Small colored dot positioned absolutely over an avatar.

import type { PresenceStatus } from "../../types/models";
import { useI18n } from "../../i18n";

interface PresenceDotProps {
  status: PresenceStatus;
  className?: string;
}

const COLORS: Record<PresenceStatus, string> = {
  online: "bg-secure",
  away: "bg-warning",
  dnd: "bg-destructive",
  offline: "bg-offline",
};

export function PresenceDot({ status, className = "" }: PresenceDotProps): JSX.Element {
  const i18n = useI18n();
  const statusKey = {
    online: "presence.online",
    away: "presence.away",
    dnd: "presence.dnd",
    offline: "presence.offline",
  } as const;

  return (
    <span
      role="img"
      aria-label={i18n.t("presence.label", { status: i18n.t(statusKey[status]) })}
      className={`absolute -bottom-0.5 -right-0.5 inline-block h-2.5 w-2.5 rounded-full border-2 border-cobalt ${COLORS[status]} ${className}`}
    />
  );
}

export default PresenceDot;
