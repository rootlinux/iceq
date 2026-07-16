// src/components/Presence/PresenceDot.tsx
//
// A small colored dot indicating a peer's presence state.
//
//   online  → green
//   away    → yellow
//   dnd     → red
//   offline → grey
//
// Sized at 2.5×2.5 to be a small accent on top of an avatar;
// absolutely positioned so callers can drop it into a
// relative-positioned container.

import type { PresenceStatus } from "../../types/models";
import { useI18n } from "../../i18n";

interface PresenceDotProps {
  status: PresenceStatus;
  className?: string;
}

const COLORS: Record<PresenceStatus, string> = {
  online: "bg-presence-online",
  away: "bg-presence-away",
  dnd: "bg-presence-dnd",
  offline: "bg-presence-offline",
};

export function PresenceDot({ status, className = "" }: PresenceDotProps): JSX.Element {
  const i18n = useI18n();
  const statusKey = { online: "presence.online", away: "presence.away", dnd: "presence.dnd", offline: "presence.offline" } as const;
  return (
    <span
      aria-label={i18n.t("presence.label", { status: i18n.t(statusKey[status]) })}
      className={`absolute -bottom-0.5 -right-0.5 inline-block h-2.5 w-2.5 rounded-full border-2 border-surface-2 ${COLORS[status]} ${className}`}
    />
  );
}

export default PresenceDot;
