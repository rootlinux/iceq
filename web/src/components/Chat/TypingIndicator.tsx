// src/components/Chat/TypingIndicator.tsx
//
// "Alice is typing…" line. The chat-store keeps a
// per-conversation Set<uin> of currently-typing peers; we
// render the union of their usernames. Self-typing is
// filtered out so the user doesn't see their own indicator.

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
    <div className="px-4 py-1 text-xs italic text-text-2">
      {names.join(", ")} {others.length === 1 ? i18n.t("chat.typingOne") : i18n.t("chat.typingMany")}
    </div>
  );
}

export default TypingIndicator;
