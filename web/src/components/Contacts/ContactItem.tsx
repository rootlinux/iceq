// src/components/Contacts/ContactItem.tsx
//
// Single contact row — Arctic Signal design.
// Avatar + name + presence dot + last message preview + unread badge.

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
      className="flex w-full items-center gap-3 px-3 py-2.5 text-left transition-all hover:bg-cobalt-hover/30 focus:bg-cobalt-hover/30 focus:outline-none rounded-lg mx-1.5 my-0.5"
    >
      <div className="relative shrink-0">
        <div
          className="iceq-avatar iceq-avatar--md"
          style={{
            background: status === "online"
              ? "linear-gradient(135deg, rgba(76,225,161,0.2), rgba(89,216,255,0.1))"
              : "linear-gradient(135deg, rgba(139,108,255,0.15), rgba(26,42,80,0.4))",
            color: status === "online" ? "#4CE1A1" : "#9EADCB",
          }}
        >
          {initial}
        </div>
        <PresenceDot status={status} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <div className="min-w-0 flex-1 truncate text-sm font-medium text-frozen">
            {contact.nickname ?? contact.username}
          </div>
          {unreadCount > 0 && (
            <span className="iceq-badge--count">
              {unreadCount > 99 ? "99+" : unreadCount}
            </span>
          )}
        </div>
        {preview && (
          <div className="truncate text-xs text-mist">{preview}</div>
        )}
      </div>
    </button>
  );
}

export default ContactItem;
