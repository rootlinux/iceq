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

interface ContactListProps {
  onContactSelected?: () => void;
}

export function ContactList({ onContactSelected }: ContactListProps): JSX.Element {
  const contacts = useContactStore((s) => s.contacts);
  const loadContacts = useContactStore((s) => s.loadContacts);
  const statuses = useContactStatusStore((s) => s.statuses);
  const directions = useContactStatusStore((s) => s.directions);
  const acceptContact = useContactStore((s) => s.acceptContact);
  const blockContact = useContactStore((s) => s.blockContact);
  const removeContactAsync = useContactStore((s) => s.removeContactAsync);
  const [showBlocked, setShowBlocked] = useState(false);
  const [busyUin, setBusyUin] = useState<number | null>(null);

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
          No contacts yet. Add a friend by their UIN to start chatting.
        </div>
      )}

      {incoming.length > 0 && (
        <section aria-label="Incoming contact requests">
          <h2 className="px-3 pt-3 text-xs font-semibold uppercase tracking-wide text-text-2">
            Requests · {incoming.length}
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
                      <span>Pending</span>
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
                  {busyUin === c.uin ? "…" : "Accept"}
                </button>
                <button
                  type="button"
                  className="iceq-btn-secondary text-xs"
                  onClick={() => void onBlock(c.uin)}
                  disabled={busyUin === c.uin}
                  aria-label="Block"
                >
                  Block
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {outgoing.length > 0 && (
        <section aria-label="Outgoing contact requests">
          <h2 className="px-3 pt-3 text-xs font-semibold uppercase tracking-wide text-text-2">
            Sent requests · {outgoing.length}
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
                      <span>Waiting for accept</span>
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
        <section aria-label="Contacts">
          <h2 className="px-3 pt-3 text-xs font-semibold uppercase tracking-wide text-text-2">
            Contacts
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
        <section aria-label="Blocked contacts" className="mt-2">
          <button
            type="button"
            className="px-3 pt-3 text-xs font-semibold uppercase tracking-wide text-text-2 hover:text-text"
            onClick={() => setShowBlocked((s) => !s)}
            aria-expanded={showBlocked}
          >
            Blocked · {blocked.length} {showBlocked ? "▾" : "▸"}
          </button>
          {showBlocked && (
            <ul role="list" className="divide-y divide-border">
              {blocked.map((c) => (
                <li key={c.uin} className="flex items-center gap-2 p-3">
                  <div className="flex-1">
                    <div className="text-sm font-medium text-text line-through opacity-60">
                      #{c.uin}
                    </div>
                    <div className="text-xs text-text-2">blocked</div>
                  </div>
                  <button
                    type="button"
                    className="iceq-btn-secondary text-xs"
                    onClick={() => void onRemove(c.uin)}
                    disabled={busyUin === c.uin}
                  >
                    Unblock
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
