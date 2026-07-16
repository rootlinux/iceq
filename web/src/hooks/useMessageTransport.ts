import { useCallback, useEffect, useRef } from "react";
import { pollEnvelopes, sendEnvelopeHTTP } from "../api/poll";
import { parseEnvelope, type Envelope } from "../types/envelope";
import { useWebSocket, type UseWebSocketResult } from "./useWebSocket";
import { useChatStore } from "../store/chatStore";

export type TransportSource = "ws" | "poll";

/** Shared, bounded parser/deduper used by every receive transport. */
export class TransportInbox {
  private readonly seen = new Set<string>();
  private readonly order: string[] = [];
  constructor(
    private readonly callback: (envelope: Envelope, source: TransportSource) => void,
    private readonly maxSeen = 2048,
  ) {}

  consume(raw: string, source: TransportSource): boolean {
    const parsed = parseEnvelope(raw);
    if (!parsed.ok || this.seen.has(parsed.envelope.id)) return false;
    this.seen.add(parsed.envelope.id);
    this.order.push(parsed.envelope.id);
    while (this.order.length > Math.max(1, this.maxSeen)) {
      const oldest = this.order.shift();
      if (oldest) this.seen.delete(oldest);
    }
    this.callback(parsed.envelope, source);
    return true;
  }
}

export function markEnvelopeRetryable<T extends Record<string, Array<{ id: string; state: string }>>>(state: T, envelope: Envelope): T {
  const clientID = (envelope.payload as { client_id?: string } | null)?.client_id;
  if (!clientID) return state;
  const next = Object.fromEntries(Object.entries(state).map(([key, messages]) => [key, messages.map((message) => message.id === clientID ? { ...message, state: "failed" } : message)]));
  return next as T;
}

/** WebSocket-first receive transport with cancellable long-poll fallback. */
export function useMessageTransport(): UseWebSocketResult {
  const ws = useWebSocket();
  const cursorRef = useRef<string | null>(null);

  useEffect(() => {
    if (ws.connected) return;
    const controller = new AbortController();
    let stopped = false;
    const run = async (): Promise<void> => {
      while (!stopped && !controller.signal.aborted) {
        try {
          const page = await pollEnvelopes(cursorRef.current, controller.signal);
          cursorRef.current = page.cursor;
          for (const envelope of page.envelopes) ws.consumeExternal(envelope);
        } catch (error) {
          if ((error as { name?: string }).name === "AbortError") return;
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }
      }
    };
    void run();
    return () => { stopped = true; controller.abort(); };
  }, [ws.connected, ws.consumeExternal]);

  const send = useCallback((envelope: Envelope): boolean => {
    if (ws.connected && ws.send(envelope)) return true;
    void sendEnvelopeHTTP(envelope).then((ack) => {
      ws.consumeExternal(ack);
    }).catch(() => {
      useChatStore.setState((state) => ({ messagesByConversation: markEnvelopeRetryable(state.messagesByConversation, envelope) }));
    });
    return true;
  }, [ws.connected, ws.consumeExternal, ws.send]);

  return { ...ws, send };
}
