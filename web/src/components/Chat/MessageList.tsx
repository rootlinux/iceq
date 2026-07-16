// src/components/Chat/MessageList.tsx
//
// The list of decrypted messages in a conversation. Messages
// are ordered oldest -> newest in the store and bottom-aligned
// in the chat pane, matching a normal chat timeline.

import { useLayoutEffect, useRef } from "react";
import { useChatStore } from "../../store/chatStore";
import { MessageItem } from "./MessageItem";
import type { Message } from "../../types/models";
import { useI18n } from "../../i18n";

interface MessageListProps {
  conversationId: string;
}

export function MessageList({ conversationId }: MessageListProps): JSX.Element {
  const i18n = useI18n();
  const messages = useChatStore((s) => s.messagesByConversation[conversationId] ?? []);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useLayoutEffect(() => {
    bottomRef.current?.scrollIntoView({ block: "end" });
  }, [conversationId, messages.length]);

  return (
    <div className="relative flex min-h-0 flex-1 flex-col overflow-y-auto px-4 py-3">
      {messages.length === 0 ? (
        <div className="mt-auto pb-8 text-center text-sm text-text-2">
        {i18n.t("chat.empty")}
        </div>
      ) : (
        <ul role="list" className="mt-auto space-y-2">
          {messages.map((m) => (
            <li key={m.id}>
              <MessageItem message={m} />
            </li>
          ))}
        </ul>
      )}
      <div ref={bottomRef} aria-hidden="true" />
    </div>
  );
}

export default MessageList;

export type { Message };
