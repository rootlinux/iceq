// src/types/envelope.ts
// WebSocket envelope + payload types. These mirror the Go-side
// `models.Envelope` shape defined in
// backend/shared/models/envelope.go.
//
// Design notes:
//
//   * The wire format uses lowercase snake_case. We keep that on
//     the TypeScript side so a single `JSON.parse` round-trip
//     produces typed values without a re-mapping layer.
//
//   * `Payload` is intentionally typed as `Record<string, unknown>`
//     at the envelope level. The discriminator (`type`) drives
//     a per-type narrowing in the WebSocket dispatcher; each
//     consumer parses the payload into the correct payload type
//     using the matching `<T>(...)` factory.
//
//   * The string literal union on `EnvelopeType` doubles as an
//     exhaustive-switch helper. If the backend adds a new type,
//     TypeScript will flag every `switch (envelope.type)` that
//     doesn't handle it.
//
//   * The auth_* types (`auth`, `auth_ok`, `auth_fail`) are an
//     IceQ-specific extension. The Go-side auth flow is a
//     bearer-token check at the HTTP upgrade; the WS handshake
//     adds a follow-up `auth` frame so a stolen token can be
//     revoked mid-session without dropping the connection.

export type EnvelopeType =
  // Auth handshake. Sent by the client immediately on
  // connect, with the access token in the payload. Server
  // replies with auth_ok or auth_fail.
  | "auth"
  | "auth_ok"
  | "auth_fail"
  // Chat. `message` is 1:1, `group_msg` is a group conversation.
  // Both carry an opaque `ciphertext` blob that the server
  // stores without inspection.
  | "message"
  | "group_msg"
  // Server-to-client ack for a previously-sent message. State
  // is one of "delivered" | "read" | "persisted".
  | "ack"
  // Presence change (online / away / dnd / offline).
  | "presence"
  // Transient typing indicator. The server does not persist it.
  | "typing"
  // Read receipt for a specific message.
  | "read"
  // Keep-alive. The client sends a `ping`; the server replies
  // with `pong`. If the client doesn't see a `pong` within
  // 5 s, it forces a reconnect.
  | "ping"
  | "pong"
  // Server-to-client error. Rendered as a console error by
  // the dispatcher; UI is intentionally minimal.
  | "error";

// ----------------------------------------------------------------------------
// Envelope — the wire shape. The server wraps every WS frame in
// this struct. `payload` is a raw object on the client side; the
// dispatcher decodes it into a per-type payload via the
// `parseEnvelope` helper below.
// ----------------------------------------------------------------------------
export interface Envelope<P = unknown> {
  type: EnvelopeType;
  // Server-assigned UUID. Clients can use it to dedupe
  // messages received via the WS and via the history API.
  id: string;
  // Server clock in unix milliseconds.
  ts: number;
  payload: P;
}

// ----------------------------------------------------------------------------
// Per-type payload interfaces. Each maps 1:1 to a Go struct in
// envelope.go. Fields are optional where the backend omits them
// (omitempty in the Go tag).
// ----------------------------------------------------------------------------
export interface AuthPayload {
  access_token: string;
  presence_enabled?: boolean;
}

export interface AuthOkPayload {
  uin: number;
  username: string;
}

export interface AuthFailPayload {
  reason: "invalid_token" | "expired_token" | "revoked" | "wiped" | "rate_limited";
}

export interface MessagePayload {
  // Conversation ID is the same value the message-service uses
  // as the Scylla partition key. The server assigns it on
  // outbound, so the client treats it as a server-controlled
  // value.
  conversation_id: string;
  sender_uin: number;
  to_uin: number;
  receiver_uin: number;
  // Optional inline plaintext. When the E2EE layer is on, the
  // server never sees plaintext; `content` is empty and
  // `ciphertext` carries the encrypted blob. The client
  // decrypts locally and the resulting plaintext is NEVER
  // sent back to the wire.
  content: string;
  content_type: "text" | "image" | "file";
  file_url?: string;
  // Client-generated message id. Used for optimistic UI and
  // ack matching. Optional — the server may have assigned its
  // own id in `Envelope.id`.
  client_id?: string;
  // Base64url-encoded ciphertext. Empty for plaintext-mode
  // messages (server-side systems, support tooling, etc.).
  ciphertext?: string;
  // "prekey_message" if this is the first message in a new
  // session (the recipient has to bootstrap with X3DH), or
  // "signal_message" once a session exists.
  msg_type?: "prekey_message" | "signal_message";
  expires_in_seconds?: number;
}

export interface GroupMessagePayload {
  conversation_id?: string;
  group_id: string;
  sender_uin: number;
  content: string;
  content_type: "text" | "image" | "file";
  file_url?: string;
  client_id?: string;
  ciphertext?: string;
  msg_type: "group_ciphertext";
  crypto_version: 1;
  crypto_epoch: number;
  expires_in_seconds?: number;
}

export interface AckPayload {
  message_id: string;
  state: "delivered" | "read" | "persisted" | "pong";
  recipient_uin: number;
}

export interface PresencePayload {
  uin: number;
  status: "online" | "away" | "dnd" | "offline";
  ts: number;
}

export interface TypingPayload {
  conversation_id: string;
  sender_uin: number;
  is_group: boolean;
  group_id?: string;
}

export interface ReadPayload {
  conversation_id: string;
  reader_uin: number;
  sender_uin: number;
  message_id: string;
  created_at: string; // RFC3339 timestamp
  is_group: boolean;
  group_id?: string;
}

export interface PingPayload {
  // Optional nonce echoed back in the pong.
  nonce?: string;
}

export type PongPayload = PingPayload;

export interface ErrorPayload {
  code: string;
  message: string;
}

// ----------------------------------------------------------------------------
// parseEnvelope — the safe decoder. Validates the type discriminator
// and parses the payload as the corresponding type. Returns null on
// a parse failure (we log via the caller's console.error and
// drop the envelope; we do not crash the WS loop on a single bad
// frame).
// ----------------------------------------------------------------------------
export function parseEnvelope(
  raw: string,
): { envelope: Envelope; ok: true } | { ok: false; error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    return { ok: false, error: `not-json: ${(e as Error).message}` };
  }
  if (!isObject(parsed)) {
    return { ok: false, error: "envelope not an object" };
  }
  const t = parsed["type"];
  const id = parsed["id"];
  const ts = parsed["ts"];
  const payload = parsed["payload"];
  if (typeof t !== "string" || typeof id !== "string" || typeof ts !== "number") {
    return { ok: false, error: "envelope missing required fields" };
  }
  return {
    ok: true,
    envelope: {
      type: t as EnvelopeType,
      id,
      ts,
      payload: payload ?? null,
    },
  };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
