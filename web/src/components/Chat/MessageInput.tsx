// src/components/Chat/MessageInput.tsx
//
// The text input + send button. On send:
//
//   1. DM: signal.encryptMessage(recipientUin, plaintext)
//   2. Group: send a group_msg frame for group:<group_id>
//   3. Optimistic UI: addMessage with state="sending"
//
// Typing indicator: a 500ms debounced "typing" frame on
// each keystroke. The server treats typing frames as
// transient; the chat-store's per-conversation typing
// window auto-clears after 5s.

import { useCallback, useRef, useState } from "react";
import { useChatStore, conversationIdForPair } from "../../store/chatStore";
import { useAuthStore } from "../../store/authStore";
import { useChatShell } from "../Layout/MainLayout";
import { encryptMessage, SignalError } from "../../lib/signal";
import { grantFileAccess, revokeFileAccess, uploadEncryptedFile } from "../../api/files";
import { cryptoRandomId } from "../../hooks/useWebSocket";
import type { Message } from "../../types/models";
import type { GroupMessagePayload, MessagePayload } from "../../types/envelope";
import type { Envelope } from "../../types/envelope";

interface MessageInputProps {
  peerUin?: number;
  groupId?: string;
}

const TYPING_DEBOUNCE_MS = 500;

export function MessageInput({ peerUin, groupId }: MessageInputProps): JSX.Element {
  const { send } = useChatShell();
  const selfUin = useAuthStore((s) => s.uin);
  const addMessage = useChatStore((s) => s.addMessage);
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [attaching, setAttaching] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const typingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastTypingSentRef = useRef(0);

  const onChange = useCallback(
    (value: string) => {
      setText(value);
      // Debounce the typing frame so we don't spam the
      // server on every keystroke. The server also rate-
      // limits; this is just a client courtesy.
      if (typingTimerRef.current) clearTimeout(typingTimerRef.current);
      typingTimerRef.current = setTimeout(() => {
        const now = Date.now();
        if (now - lastTypingSentRef.current < TYPING_DEBOUNCE_MS) return;
        lastTypingSentRef.current = now;
        if (selfUin === null) return;
        if (peerUin === undefined && groupId === undefined) return;
        const convId = groupId !== undefined ? `group:${groupId}` : conversationIdForPair(selfUin, peerUin as number);
        send({
          type: "typing",
          id: cryptoRandomId(),
          ts: Date.now(),
          payload: {
            conversation_id: convId,
            sender_uin: selfUin,
            is_group: groupId !== undefined,
            ...(groupId !== undefined ? { group_id: groupId } : {}),
          },
        });
      }, TYPING_DEBOUNCE_MS);
    },
    [groupId, peerUin, selfUin, send],
  );

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>): void => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void onSend();
    }
  };

  const onSend = async (): Promise<void> => {
    const trimmed = text.trim();
    if (!trimmed || sending) return;
    if (selfUin === null) return;
    if (peerUin === undefined && groupId === undefined) return;
    setSending(true);
    const clientId = cryptoRandomId();
    const isGroup = groupId !== undefined;
    const convId = isGroup ? `group:${groupId}` : conversationIdForPair(selfUin, peerUin as number);
    // ---- Optimistic UI: add a "sending" row ----
    const optimistic: Message = {
      id: clientId,
      conversation_id: convId,
      sender_uin: selfUin,
      receiver_uin: isGroup ? 0 : peerUin as number,
      plaintext: trimmed,
      content_type: "text",
      created_at: new Date().toISOString(),
      state: "sending",
      is_outgoing: true,
    };
    addMessage(convId, optimistic);
    setText("");

    try {
      if (isGroup) {
        const payload: GroupMessagePayload = {
          conversation_id: `group:${groupId}`,
          group_id: groupId,
          sender_uin: selfUin,
          content: trimmed,
          content_type: "text",
          client_id: clientId,
        };
        const frame: Envelope<typeof payload> = {
          type: "group_msg",
          id: clientId,
          ts: Date.now(),
          payload,
        };
        send(frame);
        return;
      }

      const encoder = new TextEncoder();
      const sealed = await encryptMessage(peerUin as number, encoder.encode(trimmed));
      const payload: MessagePayload = {
        conversation_id: convId,
        sender_uin: selfUin,
        to_uin: peerUin as number,
        receiver_uin: peerUin as number,
        content: "",
        content_type: "text",
        client_id: clientId,
        ciphertext: sealed.ciphertext,
        msg_type: sealed.msgType,
      };
      const frame: Envelope<typeof payload> = {
        type: "message",
        id: cryptoRandomId(),
        ts: Date.now(),
        payload,
      };
      send(frame);
      // The server's first ack (state=delivered) will move
      // the optimistic message from "sending" to "delivered"
      // via the dispatch path in useWebSocket.
    } catch (e) {
      const reason = e instanceof SignalError ? e.message : (e as Error).message;
      if (__DEV__) console.error("[send] encrypt failed:", reason);
      // Mark the optimistic row as failed. The chat-store
      // doesn't have a `markFailed` action, so we replace
      // via setMessages.
      useChatStore.setState((s) => {
        const list = s.messagesByConversation[convId];
        if (!list) return s;
        const next = list.map((m) => (m.id === clientId ? { ...m, state: "failed" as const } : m));
        return {
          messagesByConversation: {
            ...s.messagesByConversation,
            [convId]: next,
          },
        };
      });
    } finally {
      setSending(false);
    }
  };

  const handleAttachment = async (file: File): Promise<void> => {
    if (attaching || sending) return;
    if (selfUin === null || peerUin === undefined || groupId !== undefined) return;
    setAttaching(true);
    const clientId = cryptoRandomId();
    const convId = conversationIdForPair(selfUin, peerUin as number);
	let uploadedObjectKey: string | null = null;
	let granted = false;

    try {
      const uploaded = await uploadEncryptedFile(file, file.name);
	  uploadedObjectKey = uploaded.object_key;
	  await grantFileAccess(uploaded.object_key, peerUin as number);
	  granted = true;
      const attachment = {
        object_key: uploaded.object_key,
        manifest: uploaded.manifest,
        name: uploaded.manifest.name ?? file.name,
        mime_type: uploaded.manifest.mime_type,
        size: uploaded.manifest.size,
      };
      const optimistic: Message = {
        id: clientId,
        conversation_id: convId,
        sender_uin: selfUin,
        receiver_uin: peerUin as number,
        plaintext: "",
        content_type: "file",
        file_object_key: uploaded.object_key,
        attachment,
        created_at: new Date().toISOString(),
        state: "sending",
        is_outgoing: true,
      };
      addMessage(convId, optimistic);

      const attachmentEnvelope = {
        kind: "iceq.attachment.v1",
        object_key: uploaded.object_key,
        manifest: uploaded.manifest,
      };
      const attachmentPlaintext = JSON.stringify(attachmentEnvelope);
      const encoder = new TextEncoder();
      const sealed = await encryptMessage(peerUin as number, encoder.encode(attachmentPlaintext));
      const payload: MessagePayload = {
        conversation_id: convId,
        sender_uin: selfUin,
        to_uin: peerUin as number,
        receiver_uin: peerUin as number,
        content: "",
        content_type: "file",
        client_id: clientId,
        ciphertext: sealed.ciphertext,
        msg_type: sealed.msgType,
      };
      if (!send({
        type: "message",
        id: cryptoRandomId(),
        ts: Date.now(),
        payload,
      } satisfies Envelope<typeof payload>)) {
		throw new Error("message transport is unavailable");
	  }
    } catch (e) {
	  if (granted && uploadedObjectKey !== null) {
		await revokeFileAccess(uploadedObjectKey, peerUin as number).catch(() => undefined);
	  }
      const reason = e instanceof SignalError ? e.message : (e as Error).message;
      if (__DEV__) console.error("[send] attachment failed:", reason);
      useChatStore.setState((s) => {
        const list = s.messagesByConversation[convId];
        if (!list) return s;
        const next = list.map((m) => (m.id === clientId ? { ...m, state: "failed" as const } : m));
        return {
          messagesByConversation: {
            ...s.messagesByConversation,
            [convId]: next,
          },
        };
      });
    } finally {
      setAttaching(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  return (
    <div className="border-t border-border p-3">
      <div className="flex items-end gap-2">
        <input
          ref={fileInputRef}
          type="file"
          className="sr-only"
          disabled={sending || attaching || groupId !== undefined}
          onChange={(e) => {
            const file = e.currentTarget.files?.[0];
            if (file) void handleAttachment(file);
          }}
        />
        <button
          type="button"
          className="iceq-btn-secondary shrink-0"
          onClick={() => fileInputRef.current?.click()}
          disabled={sending || attaching || groupId !== undefined}
          title={groupId !== undefined ? "Files are available in direct messages" : "Attach file"}
          aria-label="Attach file"
        >
          {attaching ? "..." : "+"}
        </button>
        <textarea
          rows={1}
          value={text}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Type a message…"
          className="iceq-input max-h-32 resize-y"
          disabled={sending}
        />
        <button
          type="button"
          className="iceq-btn-primary"
          onClick={() => void onSend()}
          disabled={sending || text.trim().length === 0}
        >
          Send
        </button>
      </div>
    </div>
  );
}

export default MessageInput;

declare const __DEV__: boolean;
