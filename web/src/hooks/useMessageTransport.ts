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

interface CoordinatorDeps {
  poll: typeof pollEnvelopes;
  httpSend: typeof sendEnvelopeHTTP;
  wsSend: (envelope: Envelope) => boolean;
  consume: (envelope: Envelope) => void;
  onSendFailure: (envelope: Envelope) => void;
  retryDelayMs?: number;
}

export class MessageTransportCoordinator {
  private controller: AbortController | null = null;
  private cursor: string | null = null;
  private connected = true;
  private generation = 0;
  constructor(private readonly deps: CoordinatorDeps) {}

  setConnected(connected: boolean): void {
    this.connected = connected;
    if (connected) { this.stopPolling(); return; }
    this.startPolling();
  }
  send(envelope: Envelope): boolean {
    if (this.connected && this.deps.wsSend(envelope)) return true;
    void this.deps.httpSend(envelope).then((ack) => this.deps.consume(ack)).catch(() => this.deps.onSendFailure(envelope));
    return true;
  }
  stop(): void { this.connected = true; this.stopPolling(); }
  private stopPolling(): void { this.generation += 1; this.controller?.abort(); this.controller = null; }
  private startPolling(): void {
    if (this.controller) return;
    const controller = new AbortController(); this.controller = controller; const generation = ++this.generation;
    const run = async (): Promise<void> => {
      while (!controller.signal.aborted && !this.connected && generation === this.generation) {
        try {
          const page = await this.deps.poll(this.cursor, controller.signal);
          if (controller.signal.aborted || this.connected || generation !== this.generation) return;
          this.cursor = page.cursor; for (const envelope of page.envelopes) this.deps.consume(envelope);
        } catch (error) {
          if (controller.signal.aborted || (error as { name?: string }).name === "AbortError") return;
          await new Promise((resolve) => setTimeout(resolve, this.deps.retryDelayMs ?? 1000));
        }
      }
    };
    void run();
  }
}

/** WebSocket-first receive transport with cancellable long-poll fallback. */
export function useMessageTransport(): UseWebSocketResult {
  const ws = useWebSocket();
  const wsRef = useRef(ws); wsRef.current = ws;
  const coordinatorRef = useRef<MessageTransportCoordinator | null>(null);
  if (!coordinatorRef.current) {
    coordinatorRef.current = new MessageTransportCoordinator({
      poll: pollEnvelopes, httpSend: sendEnvelopeHTTP,
      wsSend: (envelope) => wsRef.current.send(envelope),
      consume: (envelope) => { wsRef.current.consumeExternal(envelope); },
      onSendFailure: (envelope) => useChatStore.setState((state) => ({ messagesByConversation: markEnvelopeRetryable(state.messagesByConversation, envelope) })),
    });
  }

  useEffect(() => {
    coordinatorRef.current?.setConnected(ws.connected);
    return () => coordinatorRef.current?.stop();
  }, [ws.connected]);

  const send = useCallback((envelope: Envelope): boolean => {
    return coordinatorRef.current?.send(envelope) ?? false;
  }, []);

  return { ...ws, send };
}
