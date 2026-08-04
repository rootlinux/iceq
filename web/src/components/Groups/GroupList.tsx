// src/components/Groups/GroupList.tsx
//
// Group list in the sidebar — Arctic Signal design.

import { useCallback, useEffect, useRef, useState } from "react";
import { useGroupStore } from "../../store/groupStore";
import { useChatStore } from "../../store/chatStore";
import { useDialogFocus } from "../../hooks/useDialogFocus";
import { useI18n } from "../../i18n";

export function GroupList(): JSX.Element {
  const i18n = useI18n();
  const groups = useGroupStore((s) => s.groups);
  const loading = useGroupStore((s) => s.loading);
  const error = useGroupStore((s) => s.error);
  const loadGroups = useGroupStore((s) => s.loadGroups);
  const createGroup = useGroupStore((s) => s.createGroup);
  const setActiveGroupConversation = useChatStore((s) => s.setActiveGroupConversation);
  const [creating, setCreating] = useState(false);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [localError, setLocalError] = useState<string | null>(null);
  const openerRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const closeDialog = useCallback(() => setOpen(false), []);
  const dialogRef = useDialogFocus(open, closeDialog, openerRef, inputRef);

  useEffect(() => {
    loadGroups().catch(() => {
      // Store already captures the error state.
    });
  }, [loadGroups]);

  async function onCreate(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    const trimmed = name.trim();
    if (trimmed.length < 3 || trimmed.length > 50) {
      setLocalError(i18n.t("groups.nameInvalid"));
      return;
    }
    setCreating(true);
    setLocalError(null);
    try {
      await createGroup(trimmed);
      setName("");
      setOpen(false);
    } catch (err) {
      setLocalError((err as Error).message);
    } finally { setCreating(false); }
  }

  return (
    <section aria-label={i18n.t("groups.title")} className="border-t border-ice-border">
      <div className="p-3">
        <button
          type="button"
          ref={openerRef}
          className="iceq-btn-secondary w-full"
          onClick={() => setOpen(true)}
        >
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="mr-2">
            <line x1="8" y1="2" x2="8" y2="14"/><line x1="2" y1="8" x2="14" y2="8"/>
          </svg>
          {i18n.t("groups.create")}
        </button>
      </div>

      <h2 className="iceq-section-header">{i18n.t("groups.title")}</h2>

      {loading && groups.length === 0 && (
        <div className="px-3 pb-3 text-sm text-mist">{i18n.t("groups.loading")}</div>
      )}

      {!loading && groups.length === 0 && (
        <div className="px-3 pb-3 text-sm text-mist">{i18n.t("groups.empty")}</div>
      )}

      {groups.length > 0 && (
        <ul role="list" className="divide-y divide-ice-border">
          {groups.map((group) => (
            <li key={group.group_id}>
              <button
                type="button"
                className="flex w-full items-center gap-3 px-3 py-2.5 text-left hover:bg-cobalt-hover/30 focus:bg-cobalt-hover/30 focus:outline-none transition-colors"
                onClick={() => setActiveGroupConversation(group)}
              >
                <div className="iceq-avatar iceq-avatar--sm">
                  {group.name.slice(0, 1).toUpperCase()}
                </div>
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-frozen">{group.name}</div>
                  <div className="text-xs text-mist">
                    {i18n.t(group.member_count === 1 ? "groups.memberCount" : "groups.memberCountPlural", { count: group.member_count })}
                  </div>
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}

      {(error || localError) && (
        <div role="alert" className="px-3 py-3 text-xs text-destructive">{localError ?? error}</div>
      )}

      {/* ── Create group modal ────────────────────────────────────── */}
      {open && (
        <div
          className="iceq-modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="create-group-title"
          onClick={closeDialog}
        >
          <div className="iceq-modal" ref={dialogRef} onClick={(e) => e.stopPropagation()}>
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <h2 id="create-group-title" className="text-lg font-semibold text-frozen">
                  {i18n.t("groups.create")}
                </h2>
                <p className="mt-1 text-sm text-mist">{i18n.t("groups.createHelp")}</p>
              </div>
              <button
                type="button"
                className="iceq-btn-icon"
                aria-label={i18n.t("groups.closeCreate")}
                onClick={closeDialog}
              >
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                  <line x1="4" y1="4" x2="14" y2="14"/><line x1="14" y1="4" x2="4" y2="14"/>
                </svg>
              </button>
            </div>

            <form className="space-y-3" onSubmit={(e) => void onCreate(e)}>
              <div>
                <label htmlFor="group-name" className="text-label text-mist">
                  {i18n.t("groups.name")}
                </label>
                <input
                  id="group-name"
                  ref={inputRef}
                  type="text"
                  className="iceq-input mt-1.5"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  minLength={3}
                  maxLength={50}
                  disabled={creating}
                  required
                />
              </div>
              {localError && (
                <div className="iceq-alert-error">{localError}</div>
              )}
              <div className="iceq-modal-buttons">
                <button type="button" className="iceq-btn-secondary" onClick={closeDialog} disabled={creating}>
                  {i18n.t("common.cancel")}
                </button>
                <button type="submit" className="iceq-btn-primary" disabled={creating}>
                  {creating ? i18n.t("groups.creating") : i18n.t("groups.create")}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
}

export default GroupList;
