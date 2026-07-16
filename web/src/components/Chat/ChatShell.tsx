// src/components/Chat/ChatShell.tsx
//
// Top-level "what to render in the chat area" picker.
// Renders the active conversation if one is selected,
// otherwise a placeholder inviting the user to pick a
// contact from the sidebar.
//
// Selection state is held in this component (not a global
// store) because it's a UI-only concern. A real app
// persists the active conversation id in the URL (e.g.
// /app/dm/:uin) — that's a future step.

import { ChatWindow } from "./ChatWindow";
import { useChatStore } from "../../store/chatStore";
import { useI18n } from "../../i18n";
import { GroupChatWindow } from "../Groups/GroupChatWindow";

export function ChatShell(): JSX.Element {
  const i18n = useI18n();
  const active = useChatStore((s) => s.activeConversation);

  if (!active) {
    return (
      <div className="flex h-full items-center justify-center p-8 text-center text-text-2">
        <div>
          <div className="mb-2 text-lg text-text">{i18n.t("chat.welcome")}</div>
          <div className="text-sm">{i18n.t("chat.selectContact")}</div>
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
