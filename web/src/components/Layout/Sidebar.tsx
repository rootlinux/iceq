// src/components/Layout/Sidebar.tsx
//
// Sidebar — the contact list + the user's identity at the
// top. The chat area is rendered next to it; see MainLayout.
//
// Mobile (<768px): the sidebar is hidden by default and
// slides in from the left when the user opens it. The
// hamburger button lives in MainLayout's top bar.

import { useCallback, useEffect, useRef, useState } from "react";
import { useAuthStore } from "../../store/authStore";
import { ContactList } from "../Contacts/ContactList";
import { GroupList } from "../Groups/GroupList";
import { SecuritySettings } from "../Settings/SecuritySettings";
import { useDialogFocus } from "../../hooks/useDialogFocus";
import { useI18n } from "../../i18n";

interface SidebarProps {
  open: boolean;
  hiddenFromNavigation: boolean;
  onClose: () => void;
}

export function Sidebar({ open, hiddenFromNavigation, onClose }: SidebarProps): JSX.Element {
  const username = useAuthStore((s) => s.username);
  const uin = useAuthStore((s) => s.uin);
  const logout = useAuthStore((s) => s.logout);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const i18n = useI18n();
  const sidebarRef = useRef<HTMLElement>(null);
  const settingsTriggerRef = useRef<HTMLButtonElement>(null);
  const closeSettings = useCallback(() => setSettingsOpen(false), []);
  const settingsDialogRef = useDialogFocus(settingsOpen, closeSettings, settingsTriggerRef);

  useEffect(() => {
    if (hiddenFromNavigation) sidebarRef.current?.setAttribute("inert", "");
    else sidebarRef.current?.removeAttribute("inert");
  }, [hiddenFromNavigation]);

  return (
    <aside
      ref={sidebarRef}
      data-open={open ? "true" : "false"}
      aria-hidden={hiddenFromNavigation ? "true" : undefined}
      className={
        "fixed inset-y-0 left-0 z-30 w-sidebar border-r border-border bg-surface-2 transition-transform md:static md:translate-x-0 " +
        (open ? "translate-x-0" : "-translate-x-full")
      }
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
              aria-label={i18n.t("nav.closeMenu")}
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
            ref={settingsTriggerRef}
            className="iceq-btn-secondary w-full"
            onClick={() => setSettingsOpen(true)}
            aria-expanded={settingsOpen}
            aria-controls="sidebar-settings-modal"
          >
            {i18n.t("nav.settings")}
          </button>
          <button
            type="button"
            className="iceq-btn-secondary mt-2 w-full"
            onClick={() => void logout().catch((error) => {
              console.error("[IceQ cleanup] logout local cleanup failed", error);
            })}
          >
            {i18n.t("nav.signOut")}
          </button>
        </div>
      </div>

      {settingsOpen && (
        <div
          className="iceq-modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="sidebar-settings-title"
          onClick={closeSettings}
        >
          <div
            id="sidebar-settings-modal"
            ref={settingsDialogRef}
            className="iceq-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <h2 id="sidebar-settings-title" className="text-lg font-semibold text-text">
                  {i18n.t("nav.settings")}
                </h2>
                <p className="mt-1 text-sm text-text-2">
                  {i18n.t("settings.description")}
                </p>
              </div>
              <button
                type="button"
                className="iceq-btn-secondary"
                aria-label={i18n.t("settings.close")}
                onClick={closeSettings}
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
