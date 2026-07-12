// src/store/contactStore.ts
//
// Contact list + presence map. The two are kept in
// independent shapes:
//
//   contacts: Contact[]               — stable list, changes on
//                                       add/remove only.
//   presence : Map<uin, PresenceState> — high-frequency
//                                       updates from the
//                                       presence-service.
//
// Splitting them prevents every presence tick from
// re-rendering the whole contact list.
//
// Step 10 adds the async actions that wrap the REST
// client in api/contacts.ts. The actions update the local
// store optimistically (or after the server replies) and
// re-throw on failure so the calling component can show
// an inline error. The store does NOT swallow errors
// itself — keeping them in the component layer matches
// the pattern in LoginForm / RegisterForm.

import { create } from "zustand";
import type { Contact, PresenceState, PresenceStatus } from "../types/models";
import * as contactsApi from "../api/contacts";
import type { ContactDirection, ContactWire } from "../api/contacts";
import { ApiError } from "../api/client";

// ----------------------------------------------------------------------------
// Adapter. The wire type and the in-memory type are
// different on purpose:
//
//   - the wire type has `avatar_url` (string) and
//     `status` (per-edge state) that the in-memory type
//     does NOT carry directly.
//   - the in-memory type has `added_at` and an optional
//     `last_known_status` for the first-paint fallback.
//
// We keep them separate so a future change to the wire
// shape does not silently propagate into every place
// that reads `Contact`.
// ----------------------------------------------------------------------------

function wireToContact(w: ContactWire): Contact {
  return {
    uin: w.uin,
    username: w.username,
    added_at: new Date().toISOString(),
    last_known_status: undefined,
  };
}

function syncContactsFromWire(wire: ContactWire[]): void {
  useContactStore.setState({ contacts: wire.map(wireToContact), loading: false, error: null });
  const statuses: Record<number, "pending" | "accepted" | "blocked"> = {};
  const directions: Record<number, ContactDirection> = {};
  for (const contact of wire) {
    statuses[contact.uin] = contact.status;
    if (contact.direction) {
      directions[contact.uin] = contact.direction;
    }
  }
  useContactStatusStore.getState().setStatusMeta(statuses, directions);
}

interface ContactState {
  contacts: Contact[];
  presence: Record<number, PresenceState>;

  // Loading + error flags. Step 10 introduces them
  // because the contact list is now fetched on chat-shell
  // mount (it wasn't in earlier steps — the list was
  // assumed pre-populated).
  loading: boolean;
  error: string | null;

  setContacts: (contacts: Contact[]) => void;
  upsertContact: (contact: Contact) => void;
  removeContact: (uin: number) => void;
  updatePresence: (uin: number, status: PresenceStatus, lastSeenTs: number) => void;

  // Step 10 async actions. Each one is a thin wrapper
  // over the REST client that mutates the local store
  // after a successful response (and re-throws on
  // failure so the UI can surface the error).
  loadContacts: () => Promise<void>;
  addContact: (targetUIN: number) => Promise<void>;
  acceptContact: (targetUIN: number) => Promise<void>;
  blockContact: (targetUIN: number) => Promise<void>;
  removeContactAsync: (targetUIN: number) => Promise<void>;
}

export const useContactStore = create<ContactState>((set, get) => ({
  contacts: [],
  presence: {},
  loading: false,
  error: null,

  setContacts: (contacts) => set({ contacts }),

  upsertContact: (contact) =>
    set((s) => {
      const i = s.contacts.findIndex((c) => c.uin === contact.uin);
      if (i === -1) {
        return { contacts: [...s.contacts, contact] };
      }
      const next = s.contacts.slice();
      next[i] = contact;
      return { contacts: next };
    }),

  removeContact: (uin) =>
    set((s) => ({
      contacts: s.contacts.filter((c) => c.uin !== uin),
    })),

  updatePresence: (uin, status, lastSeenTs) =>
    set((s) => ({
      presence: { ...s.presence, [uin]: { uin, status, last_seen_ts: lastSeenTs } },
    })),

  // --- Async actions ----------------------------------------------------

  loadContacts: async () => {
    set({ loading: true, error: null });
    try {
      const wire = await contactsApi.getContacts();
      syncContactsFromWire(wire);
    } catch (e) {
      set({ loading: false, error: (e as Error).message });
      throw e;
    }
  },

  addContact: async (targetUIN: number) => {
    const existingStatus = useContactStatusStore.getState().statuses[targetUIN];
    if (existingStatus) {
      throw new ApiError("Already added", 409, "CONTACT_EXISTS");
    }
    try {
      await contactsApi.addContact(targetUIN);
      await get().loadContacts();
    } catch (e) {
      set({ error: (e as Error).message });
      throw e;
    }
  },

  acceptContact: async (targetUIN: number) => {
    // The server requires an existing pending edge; we
    // do NOT optimistically re-write the row because the
    // 404 path is meaningful (the user accepted a request
    // that's already been withdrawn). Re-load on success
    // so the row's status flips from pending to accepted.
    try {
      await contactsApi.acceptContact(targetUIN);
      await get().loadContacts();
    } catch (e) {
      set({ error: (e as Error).message });
      throw e;
    }
  },

  blockContact: async (targetUIN: number) => {
    try {
      await contactsApi.blockContact(targetUIN);
      await get().loadContacts();
    } catch (e) {
      set({ error: (e as Error).message });
      throw e;
    }
  },

  removeContactAsync: async (targetUIN: number) => {
    // Optimistic remove — drop the row immediately. If
    // the server returns 4xx, we restore from the
    // pre-call snapshot.
    const before = get().contacts;
    set({ contacts: before.filter((c) => c.uin !== targetUIN) });
    try {
      await contactsApi.removeContact(targetUIN);
    } catch (e) {
      set({ contacts: before, error: (e as Error).message });
      throw e;
    }
  },
}));

export const selectPresence = (uin: number) => (s: ContactState): PresenceState | undefined =>
  s.presence[uin];

// ----------------------------------------------------------------------------
// Status accessor. The Contact type in models.ts doesn't
// carry a `status` field (it predates the per-edge status
// model) but the wire response does. The contact list
// groups rows by status, so the list fetches the wire
// data via a parallel getContacts() call and indexes by
// uin. This helper is the "give me the status of uin X"
// accessor used by the list / item components.
//
// Step 10 intentionally keeps the store's in-memory
// `Contact` shape minimal (matching the existing
// `Contact` interface) and stores the status in a
// separate map. A future refactor could merge them but
// the cost of doing so right now is touching every place
// that reads `Contact`, which is out of scope.
// ----------------------------------------------------------------------------

interface ContactStatusState {
  statuses: Record<number, "pending" | "accepted" | "blocked">;
  directions: Record<number, ContactDirection>;
  setStatuses: (statuses: Record<number, "pending" | "accepted" | "blocked">) => void;
  setStatusMeta: (
    statuses: Record<number, "pending" | "accepted" | "blocked">,
    directions: Record<number, ContactDirection>,
  ) => void;
}

export const useContactStatusStore = create<ContactStatusState>((set) => ({
  statuses: {},
  directions: {},
  setStatuses: (statuses) => set({ statuses }),
  setStatusMeta: (statuses, directions) => set({ statuses, directions }),
}));

export async function refreshContactStatuses(): Promise<void> {
  const wire = await contactsApi.getContacts();
  syncContactsFromWire(wire);
}
