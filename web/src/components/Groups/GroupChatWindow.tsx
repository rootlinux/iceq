import { useEffect, useState } from "react";
import { historyGroup } from "../../api/messages";
import type { GroupWire } from "../../api/groups";
import { MessageInput } from "../Chat/MessageInput";
import { MessageList } from "../Chat/MessageList";
import { useChatStore } from "../../store/chatStore";
import { useAuthStore } from "../../store/authStore";
import type { Message } from "../../types/models";
import { decodeGroupCiphertext, openGroupContent } from "../../lib/groupCrypto";
import { useGroupStore } from "../../store/groupStore";
import { GroupDetail } from "./GroupDetail";

interface GroupChatWindowProps {
  group: GroupWire;
}

export function GroupChatWindow({ group }: GroupChatWindowProps): JSX.Element {
  const selfUin = useAuthStore((s) => s.uin);
  const setMessages = useChatStore((s) => s.setMessages);
  const markConversationRead = useChatStore((s) => s.markConversationRead);
  const conversationId = `group:${group.group_id}`;
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const members = useGroupStore((s) => s.members[group.group_id] ?? []);
  const currentEpoch = useGroupStore((s) => s.groups.find((item) => item.group_id === group.group_id)?.crypto_epoch ?? group.crypto_epoch);

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
        const resp = await historyGroup(group.group_id, 50);
        const out: Message[] = [];
        for (const row of resp.messages) {
          try {
            if(row.msg_type!=="group_ciphertext")throw new Error("legacy insecure group row");
            const content=await openGroupContent(decodeGroupCiphertext(row.ciphertext),currentEpoch,members.map(m=>m.uin),true);
            const plaintext=content.content_type==="file"?JSON.stringify(content.attachment??null):(content.text??"");
            out.push({
              id: row.id,
              conversation_id: conversationId,
              sender_uin: row.sender_uin,
              receiver_uin: 0,
              plaintext,
              content_type: row.content_type,
              ...(row.file_url ? { file_url: row.file_url } : {}),
              created_at: row.created_at,
              state: "delivered",
              is_outgoing: row.sender_uin === selfUin,
            });
          } catch {
            out.push({id:row.id,conversation_id:conversationId,sender_uin:row.sender_uin,receiver_uin:0,plaintext:"Security warning: this historical group message could not be verified or decrypted.",content_type:"text",created_at:row.created_at,state:"failed",is_outgoing:row.sender_uin===selfUin});
          }
        }
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
  }, [conversationId, group.group_id, currentEpoch, members, selfUin, setMessages]);

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
              {group.member_count} member{group.member_count === 1 ? "" : "s"}
            </div>
          </div>
        </header>

        <div className="min-h-0 flex flex-1 flex-col">
          {loading ? (
            <div className="h-full overflow-y-auto p-4 text-sm text-text-2">Loading history...</div>
          ) : error ? (
            <div role="alert" className="h-full overflow-y-auto p-4 text-sm">
              Could not load group history: {error}
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
