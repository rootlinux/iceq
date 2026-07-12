// src/components/Contacts/ContactItem.tsx
//
// A single contact row. Shows avatar, name, presence dot,
// and (optionally) the last message preview if the chat
// store knows about this conversation.

import { useContactStore } from "../../store/contactStore";
import { useChatStore } from "../../store/chatStore";
import { PresenceDot } from "../Presence/PresenceDot";
import { conversationIdForPair, type Contact } from "../../types/models";
import { useAuthStore } from "../../store/authStore";

interface ContactItemProps {
  contact: Contact;
  onClick?: () => void;
}

export function ContactItem({ contact, onClick }: ContactItemProps): JSX.Element {
  const presence = useContactStore((s) => s.presence[contact.uin]);
  const selfUin = useAuthStore((s) => s.uin);
  const setActiveConversation = useChatStore((s) => s.setActiveConversation);
  const convId = selfUin !== null ? conversationIdForPair(selfUin, contact.uin) : "";
  const preview = useChatStore((s) => {
    const list = s.messagesByConversation[convId];
    if (!list || list.length === 0) return null;
    const last = list[list.length - 1];
    return last ? last.plaintext : null;
  });
  const unreadCount = useChatStore((s) => s.unreadCounts[convId] ?? 0);

  const status = presence?.status ?? contact.last_known_status ?? "offline";
  const initial = (contact.nickname ?? contact.username).slice(0, 1).toUpperCase();

  return (
    <button
      type="button"
      onClick={() => {
        if (selfUin !== null) {
          setActiveConversation(contact.uin, contact.nickname ?? contact.username, selfUin);
        }
        onClick?.();
      }}
      className="flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-surface focus:bg-surface focus:outline-none"
    >
      <div className="relative h-9 w-9 shrink-0 rounded-full bg-surface">
        <div className="flex h-full w-full items-center justify-center rounded-full bg-border text-sm font-medium text-text">
          {initial}
        </div>
        <PresenceDot status={status} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <div className="min-w-0 flex-1 truncate text-sm font-medium text-text">
            {contact.nickname ?? contact.username}
          </div>
          {unreadCount > 0 && (
            <span className="inline-flex min-w-5 items-center justify-center rounded-full bg-accent px-1.5 py-0.5 text-[10px] font-semibold leading-none text-bg">
              {unreadCount}
            </span>
          )}
        </div>
        {preview && (
          <div className="truncate text-xs text-text-2">{preview}</div>
        )}
      </div>
    </button>
  );
}

export default ContactItem;
