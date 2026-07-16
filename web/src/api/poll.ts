import { fetchJSON } from "./client";
import type { Envelope } from "../types/envelope";

export interface PollResponse {
  cursor: string;
  envelopes: Envelope[];
}

export async function pollEnvelopes(cursor: string | null, signal: AbortSignal): Promise<PollResponse> {
  const query = new URLSearchParams({ limit: "50", wait_ms: "20000" });
  if (cursor) query.set("cursor", cursor);
  return fetchJSON<PollResponse>(`/api/transport/poll?${query.toString()}`, { signal });
}

export async function sendEnvelopeHTTP(envelope: Envelope): Promise<Envelope> {
  return fetchJSON<Envelope>("/api/transport/send", { method: "POST", body: envelope });
}
