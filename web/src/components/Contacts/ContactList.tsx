// src/components/Contacts/ContactList.tsx
//
// Contact list — Arctic Signal design.
// Buckets: incoming requests, outgoing requests, accepted, blocked.

import { useEffect, useMemo, useState } from "react";
import {
  useContactStatusStore,
  useContactStore,
} from "../../store/contactStore";
import { AddContact } from "./AddContact";
import { ContactItem } from "./ContactItem";
import type { Contact } from "../../types/models";
import { useI18n } from "../../i18n";
import { getBulkPresence } from "../../api/presence";
import { permitsPrivacySignal } from "../../lib/privacySettings";

interface ContactListProps {
  onContactSelected?: () => void;
}

export function ContactList({ onContactSelected }: ContactListProps): JSX.Element {
  const i18n = useI18n();
  const contacts = useContactStore((s) => s.contacts);
  const loadContacts = useContactStore((s) => s.loadContacts);
  const statuses = useContactStatusStore((s) => s.statuses);
  const directions = useContactStatusStore((s) => s.directions);
  const acceptContact = useContactStore((s) => s.acceptContact);
  const blockContact = useContactStore((s) => s.blockContact);
  const removeContactAsync = useContactStore((s) => s.removeContactAsync);
  const [showBlocked, setShowBlocked] = useState(false);
  const [busyUin, setBusyUin] = useState<number | null>(null);
  const [privacyGeneration, setPrivacyGeneration] = useState(0);

  useEffect(() => {
    const onPrivacyChanged = (): void => setPrivacyGeneration((g) => g + 1);
    window.addEventListener("iceq:privacy-changed", onPrivacyChanged);
    return () => window.removeEventListener("iceq:privacy-changed", onPrivacyChanged);
  }, []);

  useEffect(() => {
    loadContacts().catch(() => {
      // Stale list is better than a spinner.
    });
  }, [loadContacts]);

  const { incoming, outgoing, accepted, blocked } = useMemo(() => {
    const incoming: Contact[] = [];
    const outgoing: Contact[] = [];
    const accepted: Contact[] = [];
    const blocked: Contact[] = [];
    for (const c of contacts) {
      const status = statuses[c.uin] ?? "accepted";
      const direction = directions[c.uin];
      if (status === "pending" && direction === "incoming") incoming.push(c);
      else if (status === "pending") outgoing.push(c);
      else if (status === "blocked") blocked.push(c);
      else accepted.push(c);
    }
    incoming.sort((a, b) => a.uin - b.uin);
    outgoing.sort((a, b) => a.uin - b.uin);
    accepted.sort((a, b) => a.username.localeCompare(b.username));
    blocked.sort((a, b) => a.uin - b.uin);
    return { incoming, outgoing, accepted, blocked };
  }, [contacts, statuses, directions]);

  const acceptedUinsKey = accepted.map((c) => c.uin).join(",");
  useEffect(() => {
    if (!permitsPrivacySignal("presence") || acceptedUinsKey === "") return;
    const uins = acceptedUinsKey.split(",").map(Number);
    let cancelled = false;
    void getBulkPresence(uins)
      .then((snapshot) => {
        if (cancelled) return;
        const updatePresence = useContactStore.getState().updatePresence;
        for (const [uinStr, entry] of Object.entries(snapshot)) {
          updatePresence(Number(uinStr), entry.status, entry.last_seen);
        }
      })
      .catch(() => {
        // Best-effort: real-time subscription covers future transitions.
      });
    return () => { cancelled = true; };
  }, [acceptedUinsKey, privacyGeneration]);

  async function onAccept(uin: number): Promise<void> {
    setBusyUin(uin);
    try { await acceptContact(uin); } catch {} finally { setBusyUin(null); }
  }

  async function onBlock(uin: number): Promise<void> {
    setBusyUin(uin);
    try { await blockContact(uin); } catch {} finally { setBusyUin(null); }
  }

  async function onRemove(uin: number): Promise<void> {
    setBusyUin(uin);
    try { await removeContactAsync(uin); } catch {} finally { setBusyUin(null); }
  }

  const isEmpty = incoming.length === 0 && outgoing.length === 0 && accepted.length === 0 && blocked.length === 0;

  return (
    <div>
      <AddContact />

      {isEmpty && (
        <div className="iceq-empty py-6">
          <p className="iceq-empty-text px-4">{i18n.t("contacts.empty")}</p>
        </div>
      )}

      {/* ── Incoming requests ─────────────────────────────────────── */}
      {incoming.length > 0 && (
        <section aria-label={i18n.t("contacts.incoming")}>
          <h2 className="iceq-section-header">
            {i18n.t("contacts.requests")} · {incoming.length}
          </h2>
          <ul role="list" className="divide-y divide-ice-border">
            {incoming.map((c) => (
              <li key={c.uin} className="flex items-center gap-2 px-3 py-2.5">
                <span aria-hidden="true" className="inline-block h-2 w-2 shrink-0 rounded-full bg-warning" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-frozen">
                    {c.nickname ?? c.username}
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-mist">
                    <span className="iceq-badge iceq-badge--warning">{i18n.t("contacts.pending")}</span>
                    <span className="text-mono text-[11px] text-mist-dim">#{c.uin}</span>
                  </div>
                </div>
                <button
                  type="button"
                  className="iceq-btn-primary text-xs"
                  onClick={() => void onAccept(c.uin)}
                  disabled={busyUin === c.uin}
                >
                  {busyUin === c.uin ? "…" : i18n.t("contacts.accept")}
                </button>
                <button
                  type="button"
                  className="iceq-btn-ghost text-xs"
                  onClick={() => void onBlock(c.uin)}
                  disabled={busyUin === c.uin}
                  aria-label={i18n.t("contacts.block")}
                >
                  {i18n.t("contacts.block")}
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* ── Outgoing requests ─────────────────────────────────────── */}
      {outgoing.length > 0 && (
        <section aria-label={i18n.t("contacts.outgoing")}>
          <h2 className="iceq-section-header">
            {i18n.t("contacts.sentRequests")} · {outgoing.length}
          </h2>
          <ul role="list" className="divide-y divide-ice-border">
            {outgoing.map((c) => (
              <li key={c.uin} className="flex items-center gap-3 px-3 py-2.5">
                <span aria-hidden="true" className="inline-block h-2 w-2 shrink-0 rounded-full bg-offline" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-frozen">
                    {c.nickname ?? c.username}
                  </div>
                  <div className="flex items-center gap-1.5 text-xs text-mist">
                    <span>{i18n.t("contacts.waiting")}</span>
                    <span className="text-mono text-[11px] text-mist-dim">#{c.uin}</span>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* ── Accepted contacts ─────────────────────────────────────── */}
      {accepted.length > 0 && (
        <section aria-label={i18n.t("contacts.title")}>
          <h2 className="iceq-section-header">{i18n.t("contacts.title")}</h2>
          <ul role="list" className="divide-y divide-ice-border">
            {accepted.map((c) => (
              <li key={c.uin}>
                <ContactItem contact={c} onClick={onContactSelected} />
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* ── Blocked contacts ──────────────────────────────────────── */}
      {blocked.length > 0 && (
        <section aria-label={i18n.t("contacts.blockedTitle")} className="mt-2">
          <button
            type="button"
            className="iceq-section-header flex w-full items-center gap-1 hover:text-frozen transition-colors"
            onClick={() => setShowBlocked((s) => !s)}
            aria-expanded={showBlocked}
          >
            {i18n.t("contacts.blocked")} · {blocked.length}
            <span className="text-[10px]">{showBlocked ? "▾" : "▸"}</span>
          </button>
          {showBlocked && (
            <ul role="list" className="divide-y divide-ice-border">
              {blocked.map((c) => (
                <li key={c.uin} className="flex items-center gap-2 px-3 py-2.5">
                  <span className="inline-block h-2 w-2 shrink-0 rounded-full bg-destructive opacity-40" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-mist line-through opacity-50">
                      #{c.uin}
                    </div>
                    <div className="text-[11px] text-mist-dim">{i18n.t("contacts.blocked")}</div>
                  </div>
                  <button
                    type="button"
                    className="iceq-btn-ghost text-xs"
                    onClick={() => void onRemove(c.uin)}
                    disabled={busyUin === c.uin}
                  >
                    {i18n.t("contacts.unblock")}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}

export default ContactList;
