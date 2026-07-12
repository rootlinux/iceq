// src/api/contacts.ts
//
// REST client for the contact management endpoints served by
// auth-service (mounted at /api/contacts/* in the Caddyfile).
//
// All five endpoints require a Bearer token; the standard
// `fetchJSON` wrapper in api/client.ts injects the auth
// header and the single-flight refresh-on-401 path is
// unchanged from the rest of the app.
//
// Wire types are colocated with each function so the
// JSON-tagged shape is right next to the call site. The
// `Contact` model in types/models.ts is the in-memory
// representation; the wire types here are intentionally a
// superset (avatar_url, status) so the same call can power
// the contact list and the "add contact" flow.

import { fetchJSON } from "./client";

// ----------------------------------------------------------------------------
// Wire types
// ----------------------------------------------------------------------------

export type ContactStatus = "pending" | "accepted" | "blocked";
export type ContactDirection = "incoming" | "outgoing" | "";

export interface ContactWire {
  uin: number;
  username: string;
  avatar_url: string;
  status: ContactStatus;
  direction?: ContactDirection;
}

export interface ListContactsResponse {
  contacts: ContactWire[];
}

export interface AddContactRequest {
  target_uin: number;
}

export interface ContactStatusResponse {
  status: ContactStatus;
}

// ----------------------------------------------------------------------------
// Endpoints
// ----------------------------------------------------------------------------

// getContacts returns the requesting user's full contact
// list, joined against users for the public fields. The
// server returns pending, accepted, and blocked rows in a
// single flat array; the client sorts by status (pending
// first, then accepted, then blocked) for display.
export async function getContacts(): Promise<ContactWire[]> {
  const resp = await fetchJSON<ListContactsResponse>("/api/contacts/", { method: "GET" });
  return resp.contacts;
}

// addContact creates a directed edge in BOTH directions
// (owner -> target, target -> owner), both with
// status=pending. The server emits a notification on
// `notification.<target_uin>`; the WS handler in the
// web-client surfaces it as a toast.
//
// Errors:
//   422 SELF_CONTACT_FORBIDDEN — target_uin == self
//   404 USER_NOT_FOUND          — target UIN not registered
//   422 FIELD_INVALID           — target_uin <= 0
export async function addContact(targetUIN: number): Promise<ContactStatusResponse> {
  return fetchJSON<ContactStatusResponse>("/api/contacts/", {
    method: "POST",
    body: { target_uin: targetUIN } satisfies AddContactRequest,
  });
}

// acceptContact flips both edges of a contact request to
// 'accepted'. The path parameter is the requester's UIN
// (the user whose contact request I am accepting).
//
// Errors:
//   404 REQUEST_NOT_FOUND — no pending request from this user
//   400 FIELD_INVALID     — target_uin not a positive int
export async function acceptContact(targetUIN: number): Promise<ContactStatusResponse> {
  return fetchJSON<ContactStatusResponse>(
    `/api/contacts/${encodeURIComponent(String(targetUIN))}/accept`,
    { method: "PUT" },
  );
}

// blockContact sets the requester's edge to 'blocked'.
// Idempotent: re-blocking an already-blocked user returns
// 200. Blocking without a prior contact creates a fresh
// blocked row.
export async function blockContact(targetUIN: number): Promise<ContactStatusResponse> {
  return fetchJSON<ContactStatusResponse>(
    `/api/contacts/${encodeURIComponent(String(targetUIN))}/block`,
    { method: "PUT" },
  );
}

// removeContact deletes the requester's edge. Idempotent
// (204 even if the row didn't exist). The reverse edge
// is preserved — the other party can still see the
// requester in their list.
export async function removeContact(targetUIN: number): Promise<void> {
  await fetchJSON<void>(
    `/api/contacts/${encodeURIComponent(String(targetUIN))}`,
    { method: "DELETE" },
  );
}
