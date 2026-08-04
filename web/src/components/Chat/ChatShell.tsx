// src/components/Chat/ChatShell.tsx
//
// Conversation area picker — Encrypted Aurora.
// Ice Bloom Q identity when no conversation is selected.

import { ChatWindow } from "./ChatWindow";
import { useChatStore } from "../../store/chatStore";
import { useI18n } from "../../i18n";
import { GroupChatWindow } from "../Groups/GroupChatWindow";
import { IceQMark } from "../Brand/IceQMark";

export function ChatShell(): JSX.Element {
  const i18n = useI18n();
  const active = useChatStore((s) => s.activeConversation);

  if (!active) {
    return (
      <div className="flex h-full items-center justify-center p-8">
        <div className="iceq-empty">
          <div className="iceq-empty-icon" style={{ background: "transparent" }}>
            <IceQMark size="lg" />
          </div>
          <div className="iceq-empty-title font-display">
            {i18n.t("chat.welcome")}
          </div>
          <p className="iceq-empty-text mt-1 max-w-xs">
            {i18n.t("chat.selectContact")}
          </p>
          {/* Secure channel motif below empty state */}
          <div className="mt-6 w-40 secure-channel" data-secure="true" />
        </div>
      </div>
    );
  }

  if (active.kind === "group") {
    return <GroupChatWindow group={active.group} />;
  }

  return <ChatWindow peerUin={active.peerUin} peerUsername={active.peerUsername} />;
}

export default ChatShell;
