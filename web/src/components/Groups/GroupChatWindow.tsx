import { useEffect, useState } from "react";
import { historyGroup } from "../../api/messages";
import { getGroupMembersWithEpoch, getSenderKeyDistributions } from "../../api/groups";
import type { GroupWire, SenderKeyInboxItem } from "../../api/groups";
import { MessageInput } from "../Chat/MessageInput";
import { MessageList } from "../Chat/MessageList";
import { useChatStore } from "../../store/chatStore";
import { useAuthStore } from "../../store/authStore";
import type { Message } from "../../types/models";
import { decodeGroupCiphertext, hydrateSenderKeyInbox, openGroupContent } from "../../lib/groupCrypto";
import { useGroupStore } from "../../store/groupStore";
import { decryptMessage } from "../../lib/signal";
import { pruneObsoleteGroupEpochs } from "../../lib/groupCryptoStore";
import { GroupDetail } from "./GroupDetail";
import { useI18n } from "../../i18n";
import { getActiveCryptoNamespace } from "../../lib/indexeddb";

interface GroupChatWindowProps {
  group: GroupWire;
}
const inFlightHistoryLoads = new Map<string, Promise<Message[]>>();

function loadEncryptedGroupHistory(groupId: string, selfUin: number, conversationId: string, securityWarning: string): Promise<Message[]> {
  const key = `${groupId}:${selfUin}`;
  const existing = inFlightHistoryLoads.get(key);
  if (existing) return existing;
  const operation = (async () => {
    const operationNamespace=getActiveCryptoNamespace();const roster = await getGroupMembersWithEpoch(groupId);
    const memberUins = roster.members.map((member) => member.uin);
    await pruneObsoleteGroupEpochs(operationNamespace,groupId, roster.crypto_epoch);
    useGroupStore.getState().setMembers(groupId, roster.members);
    useGroupStore.setState((state) => ({ groups: state.groups.map((item) => item.group_id === groupId ? { ...item, crypto_epoch: roster.crypto_epoch } : item) }));
    const distributions:SenderKeyInboxItem[]=[];for(let page=0;page<128;page++){const inbox=await getSenderKeyDistributions(groupId,page);if(inbox.epoch!==roster.crypto_epoch)throw new Error("sender-key inbox epoch changed during hydration");distributions.push(...inbox.distributions);if(inbox.distributions.length<8)break;if(page===127)throw new Error("sender-key inbox page limit exceeded");}
    await hydrateSenderKeyInbox(operationNamespace,groupId, roster.crypto_epoch, memberUins, async () => distributions, (a,b,c)=>decryptMessage(a,b,c,operationNamespace));
    const resp = await historyGroup(groupId, 50);
    const out: Message[] = [];
    for (const row of resp.messages) {
      try {
        if (row.msg_type !== "group_ciphertext") throw new Error("legacy insecure group row");
        if(!Number.isSafeInteger(row.crypto_epoch)||!row.crypto_epoch||row.crypto_epoch<1)throw new Error("group history epoch is missing");
        const content = await openGroupContent(operationNamespace,decodeGroupCiphertext(row.ciphertext), roster.crypto_epoch, memberUins, true, Date.now(), {group_id:groupId,sender_uin:row.sender_uin,epoch:row.crypto_epoch});
        out.push({ id: row.id, conversation_id: conversationId, sender_uin: row.sender_uin, receiver_uin: 0, plaintext: content.content_type === "file" ? JSON.stringify(content.attachment ?? null) : (content.text ?? ""), content_type: content.content_type, created_at: row.created_at, state: "delivered", is_outgoing: row.sender_uin === selfUin });
      } catch {
        out.push({ id: row.id, conversation_id: conversationId, sender_uin: row.sender_uin, receiver_uin: 0, plaintext: securityWarning, content_type: "text", created_at: row.created_at, state: "failed", is_outgoing: row.sender_uin === selfUin });
      }
    }
    return out;
  })();
  inFlightHistoryLoads.set(key, operation);
  void operation.finally(() => { if (inFlightHistoryLoads.get(key) === operation) inFlightHistoryLoads.delete(key); }).catch(() => undefined);
  return operation;
}

export function GroupChatWindow({ group }: GroupChatWindowProps): JSX.Element {
  const i18n = useI18n();
  const selfUin = useAuthStore((s) => s.uin);
  const setMessages = useChatStore((s) => s.setMessages);
  const markConversationRead = useChatStore((s) => s.markConversationRead);
  const conversationId = `group:${group.group_id}`;
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    markConversationRead(conversationId);
  }, [conversationId, markConversationRead]);

  useEffect(() => {
    if (selfUin === null) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const out=await loadEncryptedGroupHistory(group.group_id,selfUin,conversationId,i18n.t("chat.historySecurityWarning"));
        if (cancelled) return;
        setMessages(conversationId, out);
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
  }, [conversationId, group.group_id, selfUin, setMessages]);

  return (
    <div className="flex h-full min-h-0">
      <section className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 items-center gap-3 border-b border-border px-4">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-border text-xs font-medium">
            {group.name.slice(0, 1).toUpperCase()}
          </div>
          <div className="min-w-0">
            <div className="truncate text-sm font-medium text-text">{group.name}</div>
            <div className="text-xs text-text-2">
              {i18n.t(group.member_count === 1 ? "groups.memberCount" : "groups.memberCountPlural", { count: group.member_count })}
            </div>
          </div>
        </header>

        <div className="min-h-0 flex flex-1 flex-col">
          {loading ? (
            <div className="h-full overflow-y-auto p-4 text-sm text-text-2">{i18n.t("chat.loadingHistory")}</div>
          ) : error ? (
            <div role="alert" className="h-full overflow-y-auto p-4 text-sm">
              {i18n.t("chat.groupHistoryError")} {error}
            </div>
          ) : (
            <MessageList conversationId={`group:${group.group_id}`} />
          )}
        </div>

        <MessageInput groupId={group.group_id} />
      </section>

      <GroupDetail group={group} />
    </div>
  );
}

export default GroupChatWindow;
