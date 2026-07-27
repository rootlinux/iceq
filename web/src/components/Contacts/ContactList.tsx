// src/components/Contacts/ContactList.tsx
//
// The list of contacts. Step 10 reorganizes the list into
// three buckets by status:
//
//   1. Incoming requests (status=pending, direction=incoming)
//      surfaced at the TOP with a single-click Accept button.
//   2. Outgoing requests (status=pending, direction=outgoing)
//      shown as sent requests and never rendered with Accept.
//   3. Accepted contacts — the regular chat list, sorted
//      by presence (online first, then by username).
//   4. Blocked — hidden by default behind a "Show blocked"
//      toggle so a user with a long block list still sees
//      their real contacts at the top.
//
// The "+ Add contact" button sits at the very top of the
// list (above the buckets).

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

  // Re-run the presence snapshot fetch below when the user flips the
  // "presence" privacy toggle on -- otherwise turning it on mid-session
  // would only take effect the next time the accepted-contacts list
  // itself changes.
  useEffect(() => {
    const onPrivacyChanged = (): void => setPrivacyGeneration((g) => g + 1);
    window.addEventListener("iceq:privacy-changed", onPrivacyChanged);
    return () => window.removeEventListener("iceq:privacy-changed", onPrivacyChanged);
  }, []);

  // Re-fetch the wire data on mount. The contact list is
  // the source of truth for the sidebar so a fresh load
  // on every chat-shell mount is the right default. If
  // the request fails (no token, server down) we fall
  // back to whatever's already in the store — better a
  // stale list than a spinner forever.
  useEffect(() => {
    loadContacts().catch(() => {
      // Statuses remain at {} (or stale). The list still
      // renders; status badges just won't show.
    });
  }, [loadContacts]);

  // Partition the in-memory contacts by status. The
  // status is stored in the parallel `statuses` map
  // because the `Contact` type does not carry it. UINs
  // not in the map default to "accepted" (the dominant
  // bucket) so the list still renders cleanly while the
  // status fetch is in flight.
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
    // Stable sort: pending first by uin ASC, then
    // accepted by username ASC. The "presence first"
    // ordering lives inside ContactItem where the
    // presence map is consulted.
    incoming.sort((a, b) => a.uin - b.uin);
    outgoing.sort((a, b) => a.uin - b.uin);
    accepted.sort((a, b) => a.username.localeCompare(b.username));
    blocked.sort((a, b) => a.uin - b.uin);
    return { incoming, outgoing, accepted, blocked };
  }, [contacts, statuses, directions]);

  // Snapshot fetch: the real-time "presence" WS case only delivers
  // transitions that happen after this client is connected, so a
  // contact who was already online beforehand is otherwise stuck at
  // the store's "offline" fallback until their next status change.
  // Mirrors the "presence" privacy toggle that already gates the
  // real-time subscription (see useWebSocket.ts) for consistency.
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
        // Best-effort: the real-time subscription still covers future
        // transitions even if this initial snapshot fetch fails.
      });
    return () => {
      cancelled = true;
    };
  }, [acceptedUinsKey, privacyGeneration]);

  async function onAccept(uin: number): Promise<void> {
    setBusyUin(uin);
    try {
      await acceptContact(uin);
    } catch {
      // Error is already in the contact store's
      // `error` field; components that care can read
      // it. Inline-error UI for the list is out of
      // scope for Step 10.
    } finally {
      setBusyUin(null);
    }
  }

  async function onBlock(uin: number): Promise<void> {
    setBusyUin(uin);
    try {
      await blockContact(uin);
    } catch {
      // Same as above.
    } finally {
      setBusyUin(null);
    }
  }

  async function onRemove(uin: number): Promise<void> {
    setBusyUin(uin);
    try {
      await removeContactAsync(uin);
    } catch {
      // Same as above.
    } finally {
      setBusyUin(null);
    }
  }

  const isEmpty = incoming.length === 0 && outgoing.length === 0 && accepted.length === 0 && blocked.length === 0;

  return (
    <div>
      <AddContact />

      {isEmpty && (
        <div className="p-4 text-sm text-text-2">
          {i18n.t("contacts.empty")}
        </div>
      )}

      {incoming.length > 0 && (
        <section aria-label={i18n.t("contacts.incoming")}>
          <h2 className="px-3 pt-3 text-xs font-semibold uppercase tracking-wide text-text-2">
            {i18n.t("contacts.requests")} · {incoming.length}
          </h2>
          <ul role="list" className="divide-y divide-border">
            {incoming.map((c) => (
              <li key={c.uin} className="flex items-center gap-3 p-3">
                <div className="flex min-w-0 flex-1 items-center gap-3">
                  <span
                    aria-hidden="true"
                    className="inline-block h-2.5 w-2.5 rounded-full bg-text-2/50"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium text-text">
                      {c.nickname ?? c.username}
                    </div>
                    <div className="flex items-center gap-2 text-xs text-text-2">
                      <span>{i18n.t("contacts.pending")}</span>
                      <span>#{c.uin}</span>
                    </div>
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
                  className="iceq-btn-secondary text-xs"
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

      {outgoing.length > 0 && (
        <section aria-label={i18n.t("contacts.outgoing")}>
          <h2 className="px-3 pt-3 text-xs font-semibold uppercase tracking-wide text-text-2">
            {i18n.t("contacts.sentRequests")} · {outgoing.length}
          </h2>
          <ul role="list" className="divide-y divide-border">
            {outgoing.map((c) => (
              <li key={c.uin} className="flex items-center gap-3 p-3">
                <div className="flex min-w-0 flex-1 items-center gap-3">
                  <span
                    aria-hidden="true"
                    className="inline-block h-2.5 w-2.5 rounded-full bg-text-2/50"
                  />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium text-text">
                      {c.nickname ?? c.username}
                    </div>
                    <div className="flex items-center gap-2 text-xs text-text-2">
                      <span>{i18n.t("contacts.waiting")}</span>
                      <span>#{c.uin}</span>
                    </div>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {accepted.length > 0 && (
        <section aria-label={i18n.t("contacts.title")}>
          <h2 className="px-3 pt-3 text-xs font-semibold uppercase tracking-wide text-text-2">
            {i18n.t("contacts.title")}
          </h2>
          <ul role="list" className="divide-y divide-border">
            {accepted.map((c) => (
              <li key={c.uin}>
                <ContactItem contact={c} onClick={onContactSelected} />
              </li>
            ))}
          </ul>
        </section>
      )}

      {blocked.length > 0 && (
        <section aria-label={i18n.t("contacts.blockedTitle")} className="mt-2">
          <button
            type="button"
            className="px-3 pt-3 text-xs font-semibold uppercase tracking-wide text-text-2 hover:text-text"
            onClick={() => setShowBlocked((s) => !s)}
            aria-expanded={showBlocked}
          >
            {i18n.t("contacts.blocked")} · {blocked.length} {showBlocked ? "▾" : "▸"}
          </button>
          {showBlocked && (
            <ul role="list" className="divide-y divide-border">
              {blocked.map((c) => (
                <li key={c.uin} className="flex items-center gap-2 p-3">
                  <div className="flex-1">
                    <div className="text-sm font-medium text-text line-through opacity-60">
                      #{c.uin}
                    </div>
                    <div className="text-xs text-text-2">{i18n.t("contacts.blocked")}</div>
                  </div>
                  <button
                    type="button"
                    className="iceq-btn-secondary text-xs"
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
