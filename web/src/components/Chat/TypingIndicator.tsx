// src/components/Chat/TypingIndicator.tsx
//
// "Alice is typing…" indicator — Arctic Signal design.

import { useChatStore } from "../../store/chatStore";
import { useContactStore } from "../../store/contactStore";
import { useAuthStore } from "../../store/authStore";
import { useI18n } from "../../i18n";

interface TypingIndicatorProps {
  conversationId: string;
}

export function TypingIndicator({ conversationId }: TypingIndicatorProps): JSX.Element | null {
  const i18n = useI18n();
  const selfUin = useAuthStore((s) => s.uin);
  const typing = useChatStore((s) => s.typing[conversationId]);
  const contacts = useContactStore((s) => s.contacts);

  if (!typing || typing.size === 0) return null;

  const others = Array.from(typing).filter((u) => u !== selfUin);
  if (others.length === 0) return null;

  const names = others.map((u) => {
    const c = contacts.find((c) => c.uin === u);
    return c?.nickname ?? c?.username ?? `#${u}`;
  });

  return (
    <div className="flex items-center gap-2 px-4 py-1.5 text-xs text-mist">
      <span className="flex gap-0.5">
        <span className="inline-block h-1 w-1 animate-pulse rounded-full bg-signal" style={{ animationDelay: "0ms" }} />
        <span className="inline-block h-1 w-1 animate-pulse rounded-full bg-signal" style={{ animationDelay: "150ms" }} />
        <span className="inline-block h-1 w-1 animate-pulse rounded-full bg-signal" style={{ animationDelay: "300ms" }} />
      </span>
      <span>
        {names.join(", ")} {others.length === 1 ? i18n.t("chat.typingOne") : i18n.t("chat.typingMany")}
      </span>
    </div>
  );
}

export default TypingIndicator;
