// src/types/models.ts
// Domain models — User, Contact, Message, PresenceState. These
// are the in-memory shapes used by the Zustand stores and React
// components; the wire types in `envelope.ts` are a separate
// layer that maps onto these.

import type { EncryptedFileManifest } from "../lib/fileCrypto";

export interface User {
  uin: number;
  username: string;
  // ISO-8601 string. Set after the first /api/auth/me or
  // register response; absent for cached rows in older app
  // versions.
  created_at?: string;
  // Optional avatar object key (avatar bucket, "avatars/<uin>"
  // path). The client never assembles the URL itself; it asks
  // the file-service for a download-url when rendering the
  // <img>.
  avatar_object_key?: string;
}

// ----------------------------------------------------------------------------
// Contact. Mirrors the rows the auth-service / contact-service
// returns. The client flattens the list into a single array on
// load; presence is a separate map keyed by UIN so a single
// presence update doesn't re-render the whole contact list.
// ----------------------------------------------------------------------------
export interface Contact {
  uin: number;
  username: string;
  nickname?: string;
  added_at: string;
  // Last known presence. The presence-store is the source of
  // truth; this is only a fallback for the first paint.
  last_known_status?: PresenceStatus;
}

// ----------------------------------------------------------------------------
// PresenceState. The 4 canonical states; "offline" is a derived
// state (last-heartbeat > TTL) but is enumerated here so the
// UI never has to handle a 5th case.
// ----------------------------------------------------------------------------
export type PresenceStatus = "online" | "away" | "dnd" | "offline";

export interface PresenceState {
  uin: number;
  status: PresenceStatus;
  // Server clock (unix ms) of the last state change we know
  // about. Used by the UI to render "last seen 5m ago".
  last_seen_ts: number;
}

// ----------------------------------------------------------------------------
// Message. The decrypted, UI-ready message. The server-side
// counterpart is a row in Scylla with `ciphertext` populated;
// the client only ever sees `plaintext` (after Signal decrypt)
// or `content` (server-side systems, plaintext mode).
//
// `state` is the delivery state. A message transitions
// sending -> delivered -> read. The ack frame is what drives
// the transition on the sender's side; the read frame drives
// it on the recipient's side.
// ----------------------------------------------------------------------------
export type MessageState = "sending" | "delivered" | "read" | "failed";

export interface MessageAttachment {
  object_key: string;
  manifest: EncryptedFileManifest;
  name: string;
  mime_type: string;
  size: number;
}

export interface Message {
  id: string;
  // Server-assigned conversation id. For 1:1 this is a stable
  // hash of (min(uin_a, uin_b), max(uin_a, uin_b)) and is
  // identical on both sides.
  conversation_id: string;
  sender_uin: number;
  receiver_uin: number;
  // Decrypted plaintext. NEVER sent to the wire.
  plaintext: string;
  content_type: "text" | "image" | "file";
  file_url?: string;
  // For image/file messages, the local object key so the
  // client can re-fetch a download URL when the original
  // presigned URL has expired.
  file_object_key?: string;
  attachment?: MessageAttachment;
  // RFC3339 timestamp from the server. The client uses this
  // for ordering and to compute "X minutes ago".
  created_at: string;
  // Local-only state. Default for outgoing: "sending". After
  // the first ack: "delivered". After a read frame: "read".
  state: MessageState;
  // True if the user is the original sender. The UI uses
  // this to render the message on the right vs. left and to
  // know whether to show the read-receipt tick.
  is_outgoing: boolean;
}

// ----------------------------------------------------------------------------
// Conversation. A 1:1 or group chat. The store keys these by
// conversation_id; the chat window reads them by id.
// ----------------------------------------------------------------------------
export interface Conversation {
  id: string;
  // The "other" UIN in a 1:1 chat. For a group, the group
  // is keyed by id and the members are an array.
  kind: "direct" | "group";
  // Direct: the peer's UIN + username. Group: undefined.
  peer_uin?: number;
  peer_username?: string;
  // Last message in the conversation (used by the sidebar
  // preview). Capped at 80 chars by the backend.
  last_message_preview?: string;
  last_message_ts?: string;
  // Unread counter. The client resets this to 0 when the
  // chat window mounts and the user scrolls to the bottom.
  unread: number;
  // Active group members. Empty for direct conversations.
  members?: number[];
}

// ----------------------------------------------------------------------------
// Helpers.
// ----------------------------------------------------------------------------
export function peerOf(msg: Message, _selfUin: number): number {
  return msg.is_outgoing ? msg.receiver_uin : msg.sender_uin;
}

export function conversationIdForPair(a: number, b: number): string {
  // Stable, order-independent. The server uses the same rule
  // (see message-service/handlers/messages.go) so the two
  // sides arrive at the same id without coordination.
  const lo = Math.min(a, b);
  const hi = Math.max(a, b);
  return `dm:${lo}:${hi}`;
}
