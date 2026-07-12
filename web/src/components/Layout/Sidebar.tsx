// src/components/Layout/Sidebar.tsx
//
// Sidebar — the contact list + the user's identity at the
// top. The chat area is rendered next to it; see MainLayout.
//
// Mobile (<768px): the sidebar is hidden by default and
// slides in from the left when the user opens it. The
// hamburger button lives in MainLayout's top bar.

import { useState } from "react";
import { useAuthStore } from "../../store/authStore";
import { ContactList } from "../Contacts/ContactList";
import { GroupList } from "../Groups/GroupList";
import { SecuritySettings } from "../Settings/SecuritySettings";

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

export function Sidebar({ open, onClose }: SidebarProps): JSX.Element {
  const username = useAuthStore((s) => s.username);
  const uin = useAuthStore((s) => s.uin);
  const logout = useAuthStore((s) => s.logout);
  const [settingsOpen, setSettingsOpen] = useState(false);

  return (
    <aside
      data-open={open ? "true" : "false"}
      className="fixed inset-y-0 left-0 z-30 w-sidebar border-r border-border bg-surface-2 md:static md:translate-x-0"
    >
      <div className="flex h-full flex-col">
        <div className="border-b border-border p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-lg font-semibold text-text">IceQ</div>
              <div className="text-xs text-text-2">
                {username ?? ""}{" "}
                {uin !== null && <span className="text-text-2">· #{uin}</span>}
              </div>
            </div>
            <button
              type="button"
              aria-label="Close menu"
              className="md:hidden iceq-btn-secondary"
              onClick={onClose}
            >
              ✕
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          <ContactList onContactSelected={onClose} />
          <GroupList />
        </div>

        <div className="border-t border-border p-3">
          <button
            type="button"
            className="iceq-btn-secondary w-full"
            onClick={() => setSettingsOpen(true)}
            aria-expanded={settingsOpen}
            aria-controls="sidebar-settings-modal"
          >
            Settings
          </button>
          <button
            type="button"
            className="iceq-btn-secondary mt-2 w-full"
            onClick={() => void logout()}
          >
            Sign out
          </button>
        </div>
      </div>

      {settingsOpen && (
        <div
          className="iceq-modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="sidebar-settings-title"
          onClick={() => setSettingsOpen(false)}
        >
          <div
            id="sidebar-settings-modal"
            className="iceq-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <h2 id="sidebar-settings-title" className="text-lg font-semibold text-text">
                  Settings
                </h2>
                <p className="mt-1 text-sm text-text-2">
                  Review your device security and panic-wipe preferences.
                </p>
              </div>
              <button
                type="button"
                className="iceq-btn-secondary"
                aria-label="Close settings"
                onClick={() => setSettingsOpen(false)}
              >
                ✕
              </button>
            </div>
            <SecuritySettings />
          </div>
        </div>
      )}
    </aside>
  );
}

export default Sidebar;
