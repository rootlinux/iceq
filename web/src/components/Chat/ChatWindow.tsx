// src/components/Chat/ChatWindow.tsx
//
// The chat area for a single conversation. Owns three things:
//
//   1. MessageList — the scrollable list of decrypted
//      messages. Auto-scrolls to the bottom on new
//      messages unless the user has scrolled up.
//   2. TypingIndicator — appears above the input when the
//      peer is typing.
//   3. MessageInput — the textarea + send button.
//
// History is fetched on mount via the messages API and
// re-decrypted with the local Signal session.

import { useEffect, useState } from "react";
import { MessageList } from "./MessageList";
import { MessageInput } from "./MessageInput";
import { TypingIndicator } from "./TypingIndicator";
import { historyDM } from "../../api/messages";
import { decryptMessage } from "../../lib/signal";
import { processDirectControlMessage } from "../../lib/groupCrypto";
import { getGroupMembersWithEpoch } from "../../api/groups";
import { useChatStore, conversationIdForPair } from "../../store/chatStore";
import { useAuthStore } from "../../store/authStore";
import { usePresence } from "../../hooks/usePresence";
import { PresenceDot } from "../Presence/PresenceDot";
import { useChatShell } from "../Layout/MainLayout";
import { cryptoRandomId } from "../../hooks/useWebSocket";
import type { Message } from "../../types/models";
import type { Envelope, ReadPayload } from "../../types/envelope";
import { permitsPrivacySignal } from "../../lib/privacySettings";
import { useI18n } from "../../i18n";

interface ChatWindowProps {
  peerUin: number;
  peerUsername: string;
}

export function ChatWindow({ peerUin, peerUsername }: ChatWindowProps): JSX.Element {
  const i18n = useI18n();
  const { send } = useChatShell();
  const selfUin = useAuthStore((s) => s.uin);
  const convId = selfUin !== null ? conversationIdForPair(selfUin, peerUin) : "";
  const setMessages = useChatStore((s) => s.setMessages);
  const markConversationRead = useChatStore((s) => s.markConversationRead);
  const markRead = useChatStore((s) => s.markRead);
  const messages = useChatStore((s) => s.messagesByConversation[convId] ?? []);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const presence = usePresence(peerUin);

  // Fetch + decrypt history on mount / peer change.
  useEffect(() => {
    if (!convId) return;
    markConversationRead(convId);
  }, [convId, markConversationRead]);

  useEffect(() => {
    if (!convId) return;
	const sendReceipts = permitsPrivacySignal("readReceipts");
    const unreadIncoming = messages.filter((message) =>
      !message.is_outgoing && message.state !== "read",
    );
    if (unreadIncoming.length === 0) return;
    markConversationRead(convId);
    unreadIncoming.forEach((message) => {
      markRead(message.id, message.conversation_id);
	  if (!sendReceipts) return;
      send({
        type: "read",
        id: cryptoRandomId(),
        ts: Date.now(),
        payload: {
          conversation_id: message.conversation_id,
          reader_uin: selfUin ?? message.receiver_uin,
          sender_uin: message.sender_uin,
          message_id: message.id,
          created_at: message.created_at,
          is_group: message.conversation_id.startsWith("group:"),
          ...(message.conversation_id.startsWith("group:")
            ? { group_id: message.conversation_id.slice("group:".length) }
            : {}),
        } satisfies ReadPayload,
      } satisfies Envelope<ReadPayload>);
    });
  }, [convId, markConversationRead, markRead, messages, selfUin, send]);

  useEffect(() => {
    if (selfUin === null) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const resp = await historyDM(convId, 50);
        const decoder = new TextDecoder();
        const out: Message[] = [];
        for (const row of resp.messages) {
          if (!row.ciphertext || !row.msg_type) continue;
          if (row.msg_type === "plaintext" || row.msg_type === "group_ciphertext") continue;
          try {
            const plain = await decryptMessage(row.sender_uin, row.ciphertext, row.msg_type);
            if(await processDirectControlMessage(row.sender_uin,plain,async(groupId)=>{const roster=await getGroupMembersWithEpoch(groupId);return {epoch:roster.crypto_epoch,members:roster.members.map(member=>member.uin)};}))continue;
            out.push({
              id: row.id,
              conversation_id: row.conversation_id,
              sender_uin: row.sender_uin,
              receiver_uin: row.receiver_uin,
              plaintext: decoder.decode(plain),
              content_type: row.content_type,
              ...(row.file_url ? { file_url: row.file_url } : {}),
              created_at: row.created_at,
              state: "delivered",
              is_outgoing: row.sender_uin === selfUin,
            });
          } catch {
            // Skip rows we can't decrypt (likely from a
            // prior wiped session). The server keeps the
            // ciphertext but the local Signal state is
            // gone; a re-key will recover on the next
            // outgoing message.
          }
        }
        if (cancelled) return;
        setMessages(convId, out);
      } catch (e) {
        if (cancelled) return;
        setError((e as Error).message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [peerUin, selfUin, convId, setMessages]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex h-12 items-center gap-3 border-b border-border px-4">
        <div className="relative h-7 w-7">
          <div className="flex h-full w-full items-center justify-center rounded-full bg-border text-xs font-medium">
            {peerUsername.slice(0, 1).toUpperCase()}
          </div>
          <PresenceDot status={presence.status} />
        </div>
        <div>
          <div className="text-sm font-medium text-text">{peerUsername}</div>
          <div className="text-xs text-text-2">#{peerUin}</div>
        </div>
      </header>

      <div className="min-h-0 flex flex-1 flex-col">
        {loading ? (
          <div className="h-full overflow-y-auto p-4 text-sm text-text-2">{i18n.t("chat.loadingHistory")}</div>
        ) : error ? (
          <div role="alert" className="h-full overflow-y-auto p-4 text-sm">
            {i18n.t("chat.historyError")} {error}
          </div>
        ) : (
          <MessageList conversationId={convId} />
        )}
      </div>

      <TypingIndicator conversationId={convId} />
      <MessageInput peerUin={peerUin} />
    </div>
  );
}

export default ChatWindow;
