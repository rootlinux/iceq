// src/components/Chat/ChatWindow.tsx
//
// Active transmission — direct-message conversation with Encrypted Aurora design.
// Atmospheric but restrained background depth, secure-channel header,
// floating conversation header, polished message rhythm.
//
// Owns: MessageList, TypingIndicator, MessageInput, safety-number modal.

import { useEffect, useState } from "react";
import { MessageList } from "./MessageList";
import { MessageInput } from "./MessageInput";
import { TypingIndicator } from "./TypingIndicator";
import { SafetyNumberVerifyModal } from "./SafetyNumberVerifyModal";
import { historyDM } from "../../api/messages";
import { decryptMessage } from "../../lib/signal";
import { getActiveCryptoNamespace } from "../../lib/indexeddb";
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
  const { send, connected } = useChatShell();
  const selfUin = useAuthStore((s) => s.uin);
  const convId = selfUin !== null ? conversationIdForPair(selfUin, peerUin) : "";
  const setMessages = useChatStore((s) => s.setMessages);
  const markConversationRead = useChatStore((s) => s.markConversationRead);
  const markRead = useChatStore((s) => s.markRead);
  const messages = useChatStore((s) => s.messagesByConversation[convId] ?? []);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSafetyModal, setShowSafetyModal] = useState(false);
  const presence = usePresence(peerUin);

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
    const operationNamespace = getActiveCryptoNamespace();
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
            const plain = await decryptMessage(row.sender_uin, row.ciphertext, row.msg_type,operationNamespace);
            if(await processDirectControlMessage(operationNamespace,row.sender_uin,plain,async(groupId)=>{const roster=await getGroupMembersWithEpoch(groupId);return {epoch:roster.crypto_epoch,members:roster.members.map(member=>member.uin)};}))continue;
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
            // Skip rows we can't decrypt.
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
    return () => { cancelled = true; };
  }, [peerUin, selfUin, convId, setMessages]);

  const avatarInitial = peerUsername.slice(0, 1).toUpperCase();

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* ── Floating conversation header ────────────────────────────── */}
      <header
        className="secure-channel flex h-14 shrink-0 items-center gap-3 px-5"
        data-connected={connected ? "true" : "false"}
        data-reconnecting={!connected ? "true" : undefined}
        style={{
          background: "rgba(10, 16, 36, 0.6)",
          backdropFilter: "blur(8px)",
          WebkitBackdropFilter: "blur(8px)",
        }}
      >
        {/* Avatar with presence */}
        <div className="relative shrink-0">
          <div
            className="iceq-avatar iceq-avatar--md"
            style={{
              background: "linear-gradient(135deg, rgba(139,108,255,0.3), rgba(89,216,255,0.15))",
              color: "#F3F7FF",
            }}
          >
            {avatarInitial}
          </div>
          <PresenceDot status={presence.status} />
        </div>

        {/* Peer identity */}
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-semibold text-frozen">
            {peerUsername}
          </div>
          <div className="text-mono text-[10px] text-mist-dim">
            #{peerUin}
            {presence.status === "online" && (
              <span className="ml-1.5 text-secure-mint">●</span>
            )}
          </div>
        </div>

        {/* Safety verification */}
        <button
          type="button"
          className="iceq-btn-ghost shrink-0 text-xs"
          onClick={() => setShowSafetyModal(true)}
        >
          {i18n.t("security.verifySafetyNumber")}
        </button>
      </header>

      {/* ── Message area — atmospheric depth ────────────────────────── */}
      <div className="min-h-0 flex flex-1 flex-col">
        {loading ? (
          <div className="flex h-full items-center justify-center gap-2 text-sm text-mist">
            <span className="iceq-spinner" />
            {i18n.t("chat.loadingHistory")}
          </div>
        ) : error ? (
          <div role="alert" className="flex h-full items-center justify-center p-4 text-center">
            <div className="iceq-alert-error">
              {i18n.t("chat.historyError")} {error}
            </div>
          </div>
        ) : (
          <MessageList conversationId={convId} />
        )}
      </div>

      <TypingIndicator conversationId={convId} />
      <MessageInput peerUin={peerUin} />

      {/* ── Safety number modal ────────────────────────────────────── */}
      {showSafetyModal && selfUin !== null && (
        <SafetyNumberVerifyModal
          selfUin={selfUin}
          peerUin={peerUin}
          peerLabel={peerUsername}
          onClose={() => setShowSafetyModal(false)}
        />
      )}
    </div>
  );
}

export default ChatWindow;
