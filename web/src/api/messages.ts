// src/api/messages.ts
//
// History API. The client calls these on chat-window mount
// to load the last N messages before the live WS updates
// fill the gap.
//
//   GET /api/messages/history              — 1:1 history
//   GET /api/messages/group-history        — group history
//
// The server returns messages sorted oldest -> newest. Each
// row has `ciphertext` populated and `content` empty; the
// client must run each row through Signal decrypt before
// rendering.

import { fetchJSON } from "./client";

export interface HistoryMessage {
  id: string;
  conversation_id: string;
  sender_uin: number;
  receiver_uin: number;
  content_type: "text" | "image" | "file";
  file_url?: string;
  // ISO 8601 timestamp. Server-assigned.
  created_at: string;
  ciphertext: string;
  msg_type: "prekey_message" | "signal_message" | "plaintext";
}

export interface HistoryResponse {
  messages: HistoryMessage[];
  // The server may signal "no more pages" with a falsy
  // next_cursor; absent for our v1 (we cap the page at 50
  // messages and let the live socket take over).
  next_cursor?: string | null;
}

export function buildHistoryDMPath(conversationId: string, limit = 50, before?: string): string {
  const params = new URLSearchParams({
    conversation_id: conversationId,
    limit: String(limit),
  });
  if (before) params.set("before", before);
  return `/api/messages/history?${params.toString()}`;
}

export async function historyDM(conversationId: string, limit = 50, before?: string): Promise<HistoryResponse> {
  return fetchJSON<HistoryResponse>(buildHistoryDMPath(conversationId, limit, before), { method: "GET" });
}

export async function historyGroup(groupId: string, limit = 50): Promise<HistoryResponse> {
  return fetchJSON<HistoryResponse>(
    `/api/messages/group-history?group_id=${encodeURIComponent(groupId)}&limit=${limit}`,
    { method: "GET" },
  );
}
