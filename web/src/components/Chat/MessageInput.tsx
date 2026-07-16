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
import { attachmentGrantLifecycle } from "../../lib/attachmentGrantLifecycle";
import { cryptoRandomId } from "../../hooks/useWebSocket";
import type { Message } from "../../types/models";
import type { GroupMessagePayload, MessagePayload } from "../../types/envelope";
import type { Envelope } from "../../types/envelope";
import { getGroupMembersWithEpoch, putSenderKeyDistribution } from "../../api/groups";
import { ensureGroupSender, sealGroupContent, encodeGroupCiphertext, GROUP_CONTENT_KIND } from "../../lib/groupCrypto";
import { loadDisappearingSeconds, permitsPrivacySignal } from "../../lib/privacySettings";
import { useI18n } from "../../i18n";

interface MessageInputProps {
  peerUin?: number;
  groupId?: string;
}

const TYPING_DEBOUNCE_MS = 500;

export function MessageInput({ peerUin, groupId }: MessageInputProps): JSX.Element {
  const i18n = useI18n();
  const { send } = useChatShell();
  const selfUin = useAuthStore((s) => s.uin);
  const addMessage = useChatStore((s) => s.addMessage);
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [attaching, setAttaching] = useState(false);
  const [securityError, setSecurityError] = useState<string | null>(null);
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
		if (!permitsPrivacySignal("typing")) return;
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
    setSecurityError(null);
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
        const roster = await getGroupMembersWithEpoch(groupId);
        const sender = await ensureGroupSender(groupId, roster.crypto_epoch, selfUin, roster.members.map((m) => m.uin), async (uin, plaintext, distribution) => {
          const sealedDistribution = await encryptMessage(uin, plaintext);
          await putSenderKeyDistribution(groupId,{recipient_uin:uin,epoch:roster.crypto_epoch,distribution_id:distribution.distribution_id,ciphertext:sealedDistribution.ciphertext,msg_type:sealedDistribution.msgType});
          const directPayload: MessagePayload = { conversation_id: conversationIdForPair(selfUin,uin), sender_uin:selfUin, to_uin:uin, receiver_uin:uin, content:"", content_type:"text", client_id:cryptoRandomId(), ciphertext:sealedDistribution.ciphertext, msg_type:sealedDistribution.msgType };
          if (!send({type:"message",id:cryptoRandomId(),ts:Date.now(),payload:directPayload})) throw new Error("sender-key distribution transport is unavailable");
        });
        const sealed = await sealGroupContent(sender,{kind:GROUP_CONTENT_KIND,content_type:"text",text:trimmed});
        const payload: GroupMessagePayload = {
          conversation_id: `group:${groupId}`,
          group_id: groupId,
          sender_uin: selfUin,
          content: "",
          content_type: "text",
          client_id: clientId,
          ciphertext: encodeGroupCiphertext(sealed),
          msg_type: "group_ciphertext",
          crypto_version: 1,
          crypto_epoch: roster.crypto_epoch,
          expires_in_seconds: loadDisappearingSeconds(),
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
        expires_in_seconds: loadDisappearingSeconds(),
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
      setSecurityError(reason);
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
    if (selfUin === null || (peerUin === undefined && groupId === undefined)) return;
    setAttaching(true);
    setSecurityError(null);
    const clientId = cryptoRandomId();
    const convId = groupId!==undefined?`group:${groupId}`:conversationIdForPair(selfUin, peerUin as number);
    let groupGrantCleanup: { objectKey:string; recipients:number[] }|null=null;
    try {
      const uploaded = await uploadEncryptedFile(file, file.name);
      if(groupId!==undefined){
        const roster=await getGroupMembersWithEpoch(groupId); const recipients=roster.members.map(m=>m.uin).filter(u=>u!==selfUin);
        groupGrantCleanup={objectKey:uploaded.object_key,recipients:[]};
        for(const recipient of recipients){await grantFileAccess(uploaded.object_key,recipient);groupGrantCleanup.recipients.push(recipient);}
        const sender=await ensureGroupSender(groupId,roster.crypto_epoch,selfUin,roster.members.map(m=>m.uin),async(uin,plaintext,distribution)=>{const sealedDistribution=await encryptMessage(uin,plaintext);await putSenderKeyDistribution(groupId,{recipient_uin:uin,epoch:roster.crypto_epoch,distribution_id:distribution.distribution_id,ciphertext:sealedDistribution.ciphertext,msg_type:sealedDistribution.msgType});const directPayload:MessagePayload={conversation_id:conversationIdForPair(selfUin,uin),sender_uin:selfUin,to_uin:uin,receiver_uin:uin,content:"",content_type:"text",client_id:cryptoRandomId(),ciphertext:sealedDistribution.ciphertext,msg_type:sealedDistribution.msgType};if(!send({type:"message",id:cryptoRandomId(),ts:Date.now(),payload:directPayload}))throw new Error("sender-key distribution transport is unavailable");});
        const attachment={kind:"iceq.attachment.v1",object_key:uploaded.object_key,manifest:uploaded.manifest};
        const sealed=await sealGroupContent(sender,{kind:GROUP_CONTENT_KIND,content_type:"file",attachment});
        addMessage(convId,{id:clientId,conversation_id:convId,sender_uin:selfUin,receiver_uin:0,plaintext:"",content_type:"file",file_object_key:uploaded.object_key,attachment:{object_key:uploaded.object_key,manifest:uploaded.manifest,name:uploaded.manifest.name??file.name,mime_type:uploaded.manifest.mime_type,size:uploaded.manifest.size},created_at:new Date().toISOString(),state:"sending",is_outgoing:true});
        const payload:GroupMessagePayload={conversation_id:convId,group_id:groupId,sender_uin:selfUin,content:"",content_type:"file",client_id:clientId,ciphertext:encodeGroupCiphertext(sealed),msg_type:"group_ciphertext",crypto_version:1,crypto_epoch:roster.crypto_epoch,expires_in_seconds:loadDisappearingSeconds()};
        if(!send({type:"group_msg",id:cryptoRandomId(),ts:Date.now(),payload})) throw new Error("message transport is unavailable");
        groupGrantCleanup=null;
        return;
      }
      await attachmentGrantLifecycle.prepare(clientId, uploaded.object_key, peerUin as number);
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
        expires_in_seconds: loadDisappearingSeconds(),
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
      if(groupGrantCleanup) await Promise.allSettled(groupGrantCleanup.recipients.map(u=>revokeFileAccess(groupGrantCleanup!.objectKey,u)));
      await attachmentGrantLifecycle.fail(clientId).catch(() => undefined);
      const reason = e instanceof SignalError ? e.message : (e as Error).message;
      setSecurityError(reason);
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
      {securityError && <div role="alert" className="mb-2 text-sm text-red-400">{i18n.t("chat.sendBlocked")} {securityError}</div>}
      <div className="flex items-end gap-2">
        <input
          ref={fileInputRef}
          type="file"
          className="sr-only"
          disabled={sending || attaching}
          onChange={(e) => {
            const file = e.currentTarget.files?.[0];
            if (file) void handleAttachment(file);
          }}
        />
        <button
          type="button"
          className="iceq-btn-secondary shrink-0"
          onClick={() => fileInputRef.current?.click()}
          disabled={sending || attaching}
          title={i18n.t("chat.attachEncrypted")}
          aria-label={i18n.t("chat.attachFile")}
        >
          {attaching ? "..." : "+"}
        </button>
        <textarea
          rows={1}
          value={text}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder={i18n.t("chat.messagePlaceholder")}
          className="iceq-input max-h-32 resize-y"
          disabled={sending}
        />
        <button
          type="button"
          className="iceq-btn-primary"
          onClick={() => void onSend()}
          disabled={sending || text.trim().length === 0}
        >
          {i18n.t("common.send")}
        </button>
      </div>
    </div>
  );
}

export default MessageInput;

declare const __DEV__: boolean;
