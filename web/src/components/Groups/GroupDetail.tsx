import { useEffect, useMemo, useState } from "react";
import type { GroupWire } from "../../api/groups";
import { useAuthStore } from "../../store/authStore";
import { useGroupStore } from "../../store/groupStore";
import { useI18n } from "../../i18n";

interface GroupDetailProps {
  group: GroupWire;
}

export function GroupDetail({ group }: GroupDetailProps): JSX.Element {
  const i18n = useI18n();
  const selfUin = useAuthStore((s) => s.uin);
  const members = useGroupStore((s) => s.members[group.group_id] ?? []);
  const loadMembers = useGroupStore((s) => s.loadMembers);
  const inviteMember = useGroupStore((s) => s.inviteMember);
  const kickMember = useGroupStore((s) => s.kickMember);
  const [uin, setUin] = useState("");
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  useEffect(() => {
    loadMembers(group.group_id).catch((e: Error) => setLocalError(e.message));
  }, [group.group_id, loadMembers]);

  const selfMember = useMemo(
    () => members.find((member) => member.uin === selfUin),
    [members, selfUin],
  );
  const canManageMembers = selfMember?.role === "admin" || selfUin === group.owner_uin;

  async function onAdd(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    const parsedUin = Number.parseInt(uin.trim(), 10);
    if (!Number.isFinite(parsedUin) || parsedUin <= 0) {
      setLocalError(i18n.t("groups.uinInvalid"));
      return;
    }
    setBusy(true);
    setLocalError(null);
    try {
      await inviteMember(group.group_id, parsedUin);
      setUin("");
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function onRemove(memberUin: number): Promise<void> {
    setBusy(true);
    setLocalError(null);
    try {
      await kickMember(group.group_id, memberUin);
    } catch (err) {
      setLocalError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <aside className="hidden w-72 shrink-0 border-l border-border bg-bg/50 md:flex md:min-h-0 md:flex-col">
      <div className="border-b border-border p-4">
        <div className="text-sm font-semibold text-text">{i18n.t("groups.members")}</div>
        <div className="mt-1 text-xs text-text-2">
          {i18n.t(members.length === 1 ? "groups.memberCount" : "groups.memberCountPlural", { count: members.length })}
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        <ul role="list" className="divide-y divide-border">
          {members.map((member) => (
            <li key={member.uin} className="flex items-center gap-3 p-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-border text-xs font-medium text-text">
                {member.username.slice(0, 1).toUpperCase()}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium text-text">{member.username}</span>
                  {member.uin === group.owner_uin && (
                    <span className="rounded bg-accent px-1.5 py-0.5 text-[10px] font-semibold uppercase leading-none text-bg">
                      {i18n.t("groups.admin")}
                    </span>
                  )}
                </div>
                <div className="text-xs text-text-2">#{member.uin}</div>
              </div>
              {canManageMembers && member.uin !== selfUin && (
                <button
                  type="button"
                  className="iceq-btn-secondary text-xs"
                  onClick={() => void onRemove(member.uin)}
                  disabled={busy}
                >
                  {i18n.t("groups.remove")}
                </button>
              )}
            </li>
          ))}
        </ul>
      </div>

      {canManageMembers && (
        <form className="border-t border-border p-3" onSubmit={(e) => void onAdd(e)}>
          <label htmlFor="group-member-uin" className="text-xs font-medium text-text-2">
            {i18n.t("groups.addByUin")}
          </label>
          <div className="mt-2 flex gap-2">
            <input
              id="group-member-uin"
              className="iceq-input"
              inputMode="numeric"
              value={uin}
              onChange={(e) => setUin(e.target.value)}
              disabled={busy}
            />
            <button
              type="submit"
              className="iceq-btn-primary"
              disabled={busy || uin.trim().length === 0}
            >
              {i18n.t("groups.add")}
            </button>
          </div>
          {localError && <div className="mt-2 text-xs text-presence-dnd">{localError}</div>}
        </form>
      )}
    </aside>
  );
}

export default GroupDetail;
