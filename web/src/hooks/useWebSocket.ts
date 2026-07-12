// src/hooks/useWebSocket.ts
//
// Core WebSocket lifecycle hook. Responsibilities:
//
//   1. Open wss://<host>/ws on mount; close on unmount.
//   2. Send an `auth` frame immediately after open with the
//      current access token; the server replies with auth_ok
//      or auth_fail (or closes with 4401).
//   3. Exponential reconnect: 1s, 2s, 4s, 8s, 16s, 30s, 30s...
//      Reset on successful auth_ok.
//   4. Periodic ping every 30s; if no pong within 5s, force
//      a reconnect (the server may have lost the connection
//      silently).
//   5. Dispatch incoming envelopes to the appropriate store:
//        message / group_msg  -> decrypt + chatStore.addMessage
//        presence            -> contactStore.updatePresence
//        typing              -> chatStore.setTyping
//        ack                 -> chatStore.markDelivered
//        error               -> console.error
//   6. On close code 4403, call clearLocalState() and dispatch
//      a "iceq:wiped" event the auth-store listens to.
//   7. Concurrency: only one WS at a time. We use a ref to
//      hold the current socket; reconnect attempts that fire
//      while a connection is in flight are dropped.

import { useEffect, useRef, useState } from "react";
import { refreshSession, tokenStore } from "../api/client";
import { useAuthStore } from "../store/authStore";
import { useChatStore, conversationIdForPair } from "../store/chatStore";
import { useContactStore } from "../store/contactStore";
import { clearLocalState, classifyClose } from "../lib/wsCloseCodes";
import { decryptMessage } from "../lib/signal";
import type {
  AckPayload,
  AuthPayload,
  Envelope,
  ErrorPayload,
  GroupMessagePayload,
  MessagePayload,
  PingPayload,
  PongPayload,
  PresencePayload,
  ReadPayload,
  TypingPayload,
} from "../types/envelope";
import type { Message } from "../types/models";
import { parseEnvelope } from "../types/envelope";

// ----------------------------------------------------------------------------
// Backoff schedule. Reset on a successful auth_ok. The 5th
// and later retries use the same 30s ceiling so we don't
// hammer the server if the outage is long.
// ----------------------------------------------------------------------------
const BACKOFF_STEPS_MS = [1000, 2000, 4000, 8000, 16000, 30000];

const PING_INTERVAL_MS = 30_000;
const PONG_TIMEOUT_MS = 5_000;

// ----------------------------------------------------------------------------
// Public surface.
// ----------------------------------------------------------------------------
export interface UseWebSocketResult {
  // Publish a frame. The caller passes the full
  // Envelope (with type/id/ts/payload) so the
  // transport can serialise exactly what's on the
  // wire. To keep the call-site short, helper
  // constructors exist next to this hook.
  send: (frame: Envelope) => void;
  connected: boolean;
  lastEnvelope: Envelope | null;
}

// ----------------------------------------------------------------------------
// Hook.
// ----------------------------------------------------------------------------
export function useWebSocket(): UseWebSocketResult {
  const [connected, setConnected] = useState(false);
  const [lastEnvelope, setLastEnvelope] = useState<Envelope | null>(null);

  // Refs for state the WS loop reads. Keeping these in refs
  // means the loop doesn't need to re-subscribe when React
  // re-renders.
  const wsRef = useRef<WebSocket | null>(null);
  const backoffIdxRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pingTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const pongTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const closedByUsRef = useRef(false);
  const authInflightRef = useRef(false);

  const accessToken = useAuthStore((s) => s.accessToken);
  const selfUin = useAuthStore((s) => s.uin);
  const logout = useAuthStore((s) => s.logout);

  useEffect(() => {
    if (!accessToken) {
      // Not logged in; nothing to do. The App component
      // gates the WebSocket on isAuthenticated, so we
      // shouldn't get here in practice.
      return;
    }
    closedByUsRef.current = false;
    void connect();

    return () => {
      closedByUsRef.current = true;
      tearDown();
    };
    // We deliberately depend on `accessToken` only; the
    // user object is read via the ref so a slow /me
    // response doesn't restart the connection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken]);

  // ----------------------------------------------------------------------------
  // connect — open a fresh socket. The only place that
  // constructs WebSocket.
  // ----------------------------------------------------------------------------
  function connect(): void {
    if (closedByUsRef.current) return;
    if (wsRef.current && wsRef.current.readyState !== WebSocket.CLOSED) {
      // A connection is already in flight; drop this attempt.
      return;
    }
    const url = buildWSURL();
    let ws: WebSocket;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      scheduleReconnect();
      return;
    }
    wsRef.current = ws;
    authInflightRef.current = false;

    ws.onopen = () => {
      // Send the auth frame. The server may close with 4401
      // immediately if the token is bad; we treat that as
      // an auth fail and bail without backoff.
      const authFrame: Envelope<AuthPayload> = {
        type: "auth",
        id: cryptoRandomId(),
        ts: Date.now(),
        payload: { access_token: tokenStore.accessToken ?? "" },
      };
      authInflightRef.current = true;
      safeSend(ws, authFrame);
    };

    ws.onmessage = (ev) => {
      const result = parseEnvelope(typeof ev.data === "string" ? ev.data : "");
      if (!result.ok) {
        if (__DEV__) console.warn("[ws] parse error:", result.error);
        return;
      }
      const env = result.envelope;
      setLastEnvelope(env);
      void dispatch(env, ws);
    };

    ws.onerror = () => {
      // The spec doesn't promise anything useful on `error`;
      // the close event will fire next and drives the
      // reconnect / logout decision.
    };

    ws.onclose = (ev) => {
      cleanupTimers();
      wsRef.current = null;
      const action = classifyClose(ev.code);
      switch (action.kind) {
        case "wiped":
          // 4403 — server-initiated wipe. Drop everything
          // local, including the Signal store, then bounce
          // to /login.
          // clearLocalState is fire-and-forget; it kicks
          // off an async chain internally and resolves
          // to void.
          Promise.resolve(clearLocalState()).then(() => {
            window.dispatchEvent(new CustomEvent("iceq:wiped"));
            void logout();
            setConnected(false);
          }).catch(() => {
            setConnected(false);
          });
          return;
        case "unauthorized":
          // 4401 — the WS path may be the first place we
          // discover an expired access token, so try the
          // refresh flow before backing off.
          if (closedByUsRef.current) {
            setConnected(false);
            return;
          }
          setConnected(false);
          void refreshSession().then((ok) => {
            if (closedByUsRef.current) return;
            if (ok) {
              connect();
              return;
            }
            scheduleReconnect();
          });
          return;
        case "transient":
        default:
          if (closedByUsRef.current) {
            setConnected(false);
            return;
          }
          scheduleReconnect();
          setConnected(false);
          return;
      }
    };
  }

  // ----------------------------------------------------------------------------
  // dispatch — the envelope router. Each branch handles exactly
  // one EnvelopeType; the auth_* types also flip the local
  // `connected` flag.
  // ----------------------------------------------------------------------------
  async function dispatch(env: Envelope, ws: WebSocket): Promise<void> {
    switch (env.type) {
      case "auth": {
        // The server is asking us to (re-)authenticate.
        // The client only ever sends `auth`; the server
        // replying with `auth` is a non-standard case we
        // handle by re-sending our access token.
        if (__DEV__) console.warn("[ws] server sent auth frame — resending token");
        const authFrame: Envelope<AuthPayload> = {
          type: "auth",
          id: cryptoRandomId(),
          ts: Date.now(),
          payload: { access_token: tokenStore.accessToken ?? "" },
        };
        safeSend(ws, authFrame);
        return;
      }
      case "auth_ok": {
        if (authInflightRef.current) {
          authInflightRef.current = false;
          backoffIdxRef.current = 0;
          setConnected(true);
          startPingLoop();
        }
        return;
      }
      case "auth_fail": {
        const p = env.payload as { reason?: string };
        // Server explicitly rejected the auth frame. The
        // 4401 close will follow shortly; this branch
        // exists so we can surface the reason in dev.
        if (__DEV__) console.warn("[ws] auth_fail:", p.reason);
        return;
      }
      case "ping": {
        const p = env.payload as PingPayload;
        safeSend(ws, { type: "pong", id: cryptoRandomId(), ts: Date.now(), payload: { nonce: p.nonce ?? "" } });
        return;
      }
      case "pong": {
        // Reset the pong-timeout. The ping loop is
        // already running; we just need to clear the
        // pending timeout.
        if (pongTimerRef.current) {
          clearTimeout(pongTimerRef.current);
          pongTimerRef.current = null;
        }
        return;
      }
      case "presence": {
        const p = env.payload as PresencePayload;
        useContactStore.getState().updatePresence(p.uin, p.status, p.ts);
        return;
      }
      case "typing": {
        const p = env.payload as TypingPayload;
        const convId = p.conversation_id;
        if (!convId) return;
        useChatStore.getState().setTyping(convId, p.sender_uin, true);
        // Auto-clear after 5s. The server also sends an
        // "is_typing: false" frame, but a local timer
        // covers the case where the typing side closes
        // the tab without sending.
        setTimeout(() => {
          useChatStore.getState().setTyping(convId, p.sender_uin, false);
        }, 5000);
        return;
      }
      case "ack": {
        const p = env.payload as AckPayload;
        if (p.state === "pong") {
          if (pongTimerRef.current) {
            clearTimeout(pongTimerRef.current);
            pongTimerRef.current = null;
          }
          return;
        }
        // Ack frames don't carry a conversation_id; we
        // locate the message in the local store and
        // pick its conversation. The list scan is O(n)
        // but n is the number of messages on screen,
        // which is bounded by the chat window's paging.
        for (const [convId, list] of Object.entries(useChatStore.getState().messagesByConversation)) {
          if (list.some((m) => m.id === p.message_id)) {
            if (p.state === "delivered" || p.state === "persisted") useChatStore.getState().markDelivered(p.message_id, convId);
            else if (p.state === "read") useChatStore.getState().markRead(p.message_id, convId);
            return;
          }
        }
        return;
      }
      case "read": {
        const p = env.payload as ReadPayload;
        if (p.conversation_id && p.message_id) {
          useChatStore.getState().markRead(p.message_id, p.conversation_id);
        }
        return;
      }
      case "message":
      case "group_msg": {
        const p = env.payload as MessagePayload | GroupMessagePayload;
        // We must decrypt the ciphertext to populate
        // `plaintext`. If the user doesn't have a Signal
        // session yet (e.g. they were wiped mid-stream),
        // the decrypt throws and the message is dropped
        // with a console error.
        const isGroupMessage = env.type === "group_msg";
        if (!isGroupMessage && (!p.ciphertext || !p.msg_type)) {
          if (__DEV__) console.warn("[ws] message missing ciphertext", p);
          return;
        }
        const senderUin = p.sender_uin;
        try {
          const decoder = new TextDecoder();
          const plaintext = isGroupMessage && (p as GroupMessagePayload).content
            ? (p as GroupMessagePayload).content
            : p.msg_type === "plaintext" && p.ciphertext
              ? decodeBase64UrlText(p.ciphertext)
              : decoder.decode(await decryptMessage(senderUin, p.ciphertext ?? "", p.msg_type as "prekey_message" | "signal_message"));
          const conversationId = env.type === "message"
            ? conversationIdForPair(senderUin, (p as MessagePayload).receiver_uin)
            : `group:${(p as GroupMessagePayload).group_id}`;
          const message: Message = {
            id: selfUin !== null && senderUin === selfUin && p.client_id ? p.client_id : env.id,
            conversation_id: conversationId,
            sender_uin: senderUin,
            receiver_uin: env.type === "message" ? (p as MessagePayload).receiver_uin : 0,
            plaintext,
            content_type: p.content_type,
            ...(p.file_url ? { file_url: p.file_url } : {}),
            created_at: new Date(env.ts).toISOString(),
            state: "delivered",
            is_outgoing: selfUin !== null && senderUin === selfUin,
          };
          const chatState = useChatStore.getState();
          chatState.addMessage(message.conversation_id, message);
          const activeConversationId = chatState.activeConversation?.conversationId;
          const isActiveConversation = activeConversationId === message.conversation_id;
          if (!message.is_outgoing) {
            if (isActiveConversation) {
              chatState.markRead(message.id, message.conversation_id);
              chatState.markConversationRead(message.conversation_id);
              sendReadReceipt(ws, message);
            } else {
              chatState.incrementUnread(message.conversation_id);
            }
          }
        } catch (e) {
          if (__DEV__) console.error("[ws] decrypt failed:", e);
        }
        return;
      }
      case "error": {
        const p = env.payload as ErrorPayload;
        if (__DEV__) console.error("[ws] error frame:", p);
        return;
      }
      default: {
        // Exhaustiveness guard. If a new EnvelopeType is
        // added, TypeScript will flag this `default`
        // branch as no-longer-unreachable.
        const _exhaustive: never = env.type;
        if (__DEV__) console.warn("[ws] unhandled type:", _exhaustive);
        return;
      }
    }
  }

  // ----------------------------------------------------------------------------
  // send — public API. Components call this to publish
  // frames. We accept the full Envelope so the caller
  // controls id / ts / payload shape exactly.
  // ----------------------------------------------------------------------------
  function send(frame: Envelope): void {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    safeSend(ws, frame);
  }

  // ----------------------------------------------------------------------------
  // scheduleReconnect — bumps the backoff index and re-opens
  // after the delay. The index is reset to 0 on a successful
  // auth_ok (inside dispatch).
  // ----------------------------------------------------------------------------
  function scheduleReconnect(): void {
    if (closedByUsRef.current) return;
    if (reconnectTimerRef.current) return;
    const idx = Math.min(backoffIdxRef.current, BACKOFF_STEPS_MS.length - 1);
    const delay = BACKOFF_STEPS_MS[idx] ?? 30000;
    backoffIdxRef.current = backoffIdxRef.current + 1;
    reconnectTimerRef.current = setTimeout(() => {
      reconnectTimerRef.current = null;
      void connect();
    }, delay);
  }

  // ----------------------------------------------------------------------------
  // startPingLoop — fires every 30s. The pong is reset by
  // the message dispatcher; if the timer fires before
  // reset, we force a reconnect.
  // ----------------------------------------------------------------------------
  function startPingLoop(): void {
    if (pingTimerRef.current) return;
    pingTimerRef.current = setInterval(() => {
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      safeSend(ws, { type: "ping", id: cryptoRandomId(), ts: Date.now(), payload: {} });
      if (pongTimerRef.current) clearTimeout(pongTimerRef.current);
      pongTimerRef.current = setTimeout(() => {
        // No pong in time. Force a reconnect.
        if (wsRef.current) {
          try {
            wsRef.current.close(4000, "ping_timeout");
          } catch {
            // ignore
          }
        }
      }, PONG_TIMEOUT_MS);
    }, PING_INTERVAL_MS);
  }

  // ----------------------------------------------------------------------------
  // tearDown — clean up everything. Called on unmount.
  // ----------------------------------------------------------------------------
  function tearDown(): void {
    cleanupTimers();
    if (wsRef.current) {
      try {
        wsRef.current.close(1000, "client_tear_down");
      } catch {
        // ignore
      }
      wsRef.current = null;
    }
    setConnected(false);
  }

  function cleanupTimers(): void {
    if (pingTimerRef.current) {
      clearInterval(pingTimerRef.current);
      pingTimerRef.current = null;
    }
    if (pongTimerRef.current) {
      clearTimeout(pongTimerRef.current);
      pongTimerRef.current = null;
    }
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }

  return { send, connected, lastEnvelope };
}

// ----------------------------------------------------------------------------
// Helpers.
// ----------------------------------------------------------------------------
function buildWSURL(): string {
  const loc = window.location;
  const scheme = loc.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${loc.host}/ws`;
}

function safeSend(ws: WebSocket, frame: Envelope): void {
  try {
    ws.send(JSON.stringify(frame));
  } catch {
    // The socket may have closed between the OPEN check
    // and the send. Drop the frame; the dispatcher will
    // reconnect on close.
  }
}

function cryptoRandomId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  // Fallback for older Safari.
  return "id-" + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

// Re-export a small helper so the chat input can use the
// same id generator for client_id.
export { cryptoRandomId };

function sendReadReceipt(ws: WebSocket, message: Message): void {
  safeSend(ws, {
    type: "read",
    id: cryptoRandomId(),
    ts: Date.now(),
    payload: {
      conversation_id: message.conversation_id,
      reader_uin: message.receiver_uin,
      sender_uin: message.sender_uin,
      message_id: message.id,
      created_at: message.created_at,
      is_group: message.conversation_id.startsWith("group:"),
      ...(message.conversation_id.startsWith("group:")
        ? { group_id: message.conversation_id.slice("group:".length) }
        : {}),
    } satisfies ReadPayload,
  });
}

function decodeBase64UrlText(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

// The __DEV__ global is set in vite.config.ts. We declare
// it here so TypeScript doesn't flag the references.
declare const __DEV__: boolean;

// Type PongPayload to keep the re-export honest. (Vite tree-
// shakes unused type-only imports.)
export type { PingPayload, PongPayload };
