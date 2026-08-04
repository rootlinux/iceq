// src/components/Layout/Sidebar.tsx
//
// Navigation drawer — overlay panel launched from the identity rail.
// Organised into tabs: Chats (recent conversations), Contacts, Groups.
// Settings and sign-out live in the footer.
//
// Selecting a conversation, contact or group closes the drawer.

import { useCallback, useRef, useState } from "react";
import { useAuthStore } from "../../store/authStore";
import { ContactList } from "../Contacts/ContactList";
import { GroupList } from "../Groups/GroupList";
import { SecuritySettings } from "../Settings/SecuritySettings";
import { useDialogFocus } from "../../hooks/useDialogFocus";
import { useChatStore, conversationIdForPair } from "../../store/chatStore";
import { useContactStore } from "../../store/contactStore";
import { useGroupStore } from "../../store/groupStore";
import { IceQWordmark } from "../Brand/IceQWordmark";
import { useI18n } from "../../i18n";

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

type Tab = "chats" | "contacts" | "groups";

export function Sidebar({ open, onClose }: SidebarProps): JSX.Element {
  const username = useAuthStore((s) => s.username);
  const uin = useAuthStore((s) => s.uin);
  const logout = useAuthStore((s) => s.logout);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [tab, setTab] = useState<Tab>("chats");
  const i18n = useI18n();
  const settingsTriggerRef = useRef<HTMLButtonElement>(null);
  const closeSettings = useCallback(() => setSettingsOpen(false), []);
  const settingsDialogRef = useDialogFocus(settingsOpen, closeSettings, settingsTriggerRef);

  // ── Recent conversations (from chat store) ──────────────────────────
  const contacts = useContactStore((s) => s.contacts);
  const allMessages = useChatStore((s) => s.messagesByConversation);
  const groups = useGroupStore((s) => s.groups);
  const selfUin = uin;

  // Build a list of conversations that have messages
  const recentConvs = (() => {
    if (!selfUin) return [];
    const entries = Object.entries(allMessages)
      .filter(([, msgs]) => msgs.length > 0)
      .sort((a, b) => {
        const aLast = a[1][a[1].length - 1];
        const bLast = b[1][b[1].length - 1];
        if (!aLast || !bLast) return 0;
        return new Date(bLast.created_at).getTime() - new Date(aLast.created_at).getTime();
      })
      .slice(0, 15);
    return entries.map(([convId, msgs]) => {
      // Determine peer from conversation ID
      const lastMsg = msgs[msgs.length - 1];
      const unread = useChatStore.getState().unreadCounts[convId] ?? 0;
      let name = convId;
      let peerUin: number | null = null;
      let isGroup = false;

      if (convId.startsWith("group:")) {
        isGroup = true;
        const groupId = convId.slice("group:".length);
        name = groupId;
        // Try to find group name
        const g = groups.find((grp) => grp.group_id === groupId);
        if (g) name = g.name;
      } else {
        // DM: conversationIdForPair(selfUin, peerUin)
        for (const c of contacts) {
          const cid = conversationIdForPair(selfUin, c.uin);
          if (cid === convId) { name = c.nickname ?? c.username; peerUin = c.uin; break; }
        }
      }

      return { convId, name, peerUin, isGroup, lastMsg, unread };
    });
  })();

  const handleSelectDM = (peerUin: number, peerName: string): void => {
    if (selfUin) {
      useChatStore.getState().setActiveConversation(peerUin, peerName, selfUin);
    }
    onClose();
  };

  const handleSelectGroup = (groupId: string): void => {
    const g = groups.find((grp) => grp.group_id === groupId);
    if (g) {
      useChatStore.getState().setActiveGroupConversation(g);
    }
    onClose();
  };

  const handleSignOut = (): void => {
    void logout().catch((error) => {
      console.error("[IceQ cleanup] logout local cleanup failed", error);
    });
  };

  const tabLabel: Record<Tab, string> = {
    chats: i18n.t("nav.chats"),
    contacts: i18n.t("nav.contacts"),
    groups: i18n.t("nav.groups"),
  };

  return (
    <div className="flex h-full flex-col" style={{ pointerEvents: open ? "auto" : "none" }}>
      {/* ── Header: user identity ──────────────────────────────────── */}
      <div className="secure-channel border-b border-ice-border p-4" data-connected="true">
        <IceQWordmark variant="horizontal" size="sm" monochrome className="text-frozen" />
        <div className="mt-0.5 flex items-baseline gap-1.5 truncate text-xs">
          <span className="text-mist">{username ?? ""}</span>
          {uin !== null && (
            <span className="text-mono text-[11px] text-mist-dim">#{uin}</span>
          )}
        </div>
      </div>

      {/* ── Tabs ───────────────────────────────────────────────────── */}
      <div className="iceq-tabs m-3" role="tablist">
        {(["chats", "contacts", "groups"] as Tab[]).map((key) => (
          <button
            key={key}
            type="button"
            role="tab"
            className="iceq-tab"
            aria-selected={tab === key}
            onClick={() => setTab(key)}
          >
            {tabLabel[key]}
          </button>
        ))}
      </div>

      {/* ── Tab panels ─────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        {/* Chats tab — recent conversations */}
        {tab === "chats" && (
          <div className="divide-y divide-ice-border">
            {recentConvs.length === 0 ? (
              <div className="iceq-empty py-6">
                <p className="iceq-empty-text px-4">
                  {i18n.t("chat.selectContact")}
                </p>
              </div>
            ) : (
              <ul role="list">
                {recentConvs.map((conv) => (
                  <li key={conv.convId}>
                    <button
                      type="button"
                      className="iceq-conversation-row"
                      onClick={() => {
                        if (conv.isGroup) {
                          handleSelectGroup(conv.convId.slice("group:".length));
                        } else if (conv.peerUin) {
                          handleSelectDM(conv.peerUin, conv.name);
                        }
                      }}
                    >
                      <div className="iceq-avatar iceq-avatar--md flex-shrink-0">
                        {conv.name.slice(0, 1).toUpperCase()}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <div className="truncate text-sm font-medium text-frozen">
                            {conv.name}
                          </div>
                          {conv.unread > 0 && (
                            <span className="iceq-badge--count">
                              {conv.unread > 99 ? "99+" : conv.unread}
                            </span>
                          )}
                        </div>
                        {conv.lastMsg && (
                          <div className="truncate text-xs text-mist">
                            {conv.lastMsg.plaintext || (conv.lastMsg.content_type === "file" ? i18n.t("chat.fileAttachment") : "")}
                          </div>
                        )}
                      </div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {/* Contacts tab */}
        {tab === "contacts" && (
          <ContactList onContactSelected={onClose} />
        )}

        {/* Groups tab */}
        {tab === "groups" && (
          <GroupList />
        )}
      </div>

      {/* ── Footer: settings + sign out ────────────────────────────── */}
      <div className="border-t border-ice-border p-3 space-y-2">
        <button
          type="button"
          ref={settingsTriggerRef}
          className="iceq-btn-secondary w-full"
          onClick={() => setSettingsOpen(true)}
          aria-expanded={settingsOpen}
          aria-controls="drawer-settings-modal"
        >
          {i18n.t("nav.settings")}
        </button>
        <button
          type="button"
          className="iceq-btn-ghost w-full"
          onClick={handleSignOut}
        >
          {i18n.t("nav.signOut")}
        </button>
      </div>

      {/* ── Settings modal ─────────────────────────────────────────── */}
      {settingsOpen && (
        <div
          className="iceq-modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="drawer-settings-title"
          onClick={closeSettings}
        >
          <div
            id="drawer-settings-modal"
            ref={settingsDialogRef}
            className="iceq-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <h2 id="drawer-settings-title" className="text-lg font-semibold text-frozen">
                  {i18n.t("nav.settings")}
                </h2>
                <p className="mt-1 text-sm text-mist">
                  {i18n.t("settings.description")}
                </p>
              </div>
              <button
                type="button"
                className="iceq-btn-icon"
                aria-label={i18n.t("settings.close")}
                onClick={closeSettings}
              >
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                  <line x1="4" y1="4" x2="14" y2="14" /><line x1="14" y1="4" x2="4" y2="14" />
                </svg>
              </button>
            </div>
            <SecuritySettings />
          </div>
        </div>
      )}
    </div>
  );
}

export default Sidebar;
