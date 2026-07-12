// src/store/chatStore.ts
//
// Chat state. Maps conversation_id -> ordered list of
// decrypted messages, plus a typing indicator map.
//
// Critical privacy boundary:
//   The chatStore is the ONLY place decrypted plaintext lives
//   in the React tree. It is intentionally not persisted —
//   messages in this store evaporate on page reload and the
//   client re-fetches the history (which is encrypted on
//   the wire) and re-decrypts on the fly.
//
//   Persistence would mean leaving plaintext in
//   localStorage / IndexedDB across sessions, which is a
//   footgun for E2EE. The server is the durable store; the
//   client is a thin decrypt-and-display layer.

import { create } from "zustand";
import type { Message, MessageState } from "../types/models";
import { conversationIdForPair } from "../types/models";
import type { GroupWire } from "../api/groups";

interface ActiveDirectConversation {
  kind: "direct";
  conversationId: string;
  peerUin: number;
  peerUsername: string;
}

interface ActiveGroupConversation {
  kind: "group";
  conversationId: string;
  group: GroupWire;
}

type ActiveConversation = ActiveDirectConversation | ActiveGroupConversation;

interface ChatState {
  // Map<conversationId, Message[]>. We use a Record rather
  // than a Map for Zustand's structural-equality reactivity.
  messagesByConversation: Record<string, Message[]>;
  unreadCounts: Record<string, number>;
  typing: Record<string, Set<number>>;
  activeConversation: ActiveConversation | null;

  addMessage: (conversationId: string, message: Message) => void;
  setMessages: (conversationId: string, messages: Message[]) => void;
  incrementUnread: (conversationId: string) => void;
  markConversationRead: (conversationId: string) => void;
  markDelivered: (messageId: string, conversationId: string) => void;
  markRead: (messageId: string, conversationId: string) => void;
  setTyping: (conversationId: string, uin: number, isTyping: boolean) => void;
  setActiveConversation: (peerUin: number, peerUsername: string, selfUin: number) => void;
  setActiveGroupConversation: (group: GroupWire) => void;
  clearActiveConversation: () => void;
  clear: () => void;
}

export const useChatStore = create<ChatState>((set) => ({
  messagesByConversation: {},
  unreadCounts: {},
  typing: {},
  activeConversation: null,

  addMessage: (conversationId, message) =>
    set((s) => {
      return {
        messagesByConversation: {
          ...s.messagesByConversation,
          [conversationId]: mergeMessages(
            s.messagesByConversation[conversationId] ?? [],
            [message],
          ),
        },
      };
    }),

  setMessages: (conversationId, messages) =>
    set((s) => ({
      messagesByConversation: {
        ...s.messagesByConversation,
        [conversationId]: mergeMessages(
          s.messagesByConversation[conversationId] ?? [],
          messages,
        ),
      },
    })),

  incrementUnread: (conversationId) =>
    set((s) => ({
      unreadCounts: {
        ...s.unreadCounts,
        [conversationId]: (s.unreadCounts[conversationId] ?? 0) + 1,
      },
    })),

  markConversationRead: (conversationId) =>
    set((s) => ({
      unreadCounts: {
        ...s.unreadCounts,
        [conversationId]: 0,
      },
    })),

  markDelivered: (messageId, conversationId) =>
    set((s) => updateMessageState(s, conversationId, messageId, "delivered")),

  markRead: (messageId, conversationId) =>
    set((s) => updateMessageState(s, conversationId, messageId, "read")),

  setTyping: (conversationId, uin, isTyping) =>
    set((s) => {
      const current = new Set(s.typing[conversationId] ?? new Set<number>());
      if (isTyping) {
        current.add(uin);
      } else {
        current.delete(uin);
      }
      return {
        typing: { ...s.typing, [conversationId]: current },
      };
    }),

  setActiveConversation: (peerUin, peerUsername, selfUin) =>
    set((s) => {
      const conversationId = conversationIdForPair(selfUin, peerUin);
      return {
        activeConversation: {
          kind: "direct",
          conversationId,
          peerUin,
          peerUsername,
        },
        unreadCounts: {
          ...s.unreadCounts,
          [conversationId]: 0,
        },
      };
    }),

  setActiveGroupConversation: (group) =>
    set((s) => {
      const conversationId = `group:${group.group_id}`;
      return {
        activeConversation: {
          kind: "group",
          conversationId,
          group,
        },
        unreadCounts: {
          ...s.unreadCounts,
          [conversationId]: 0,
        },
      };
    }),

  clearActiveConversation: () => set({ activeConversation: null }),

  clear: () => set({
    messagesByConversation: {},
    unreadCounts: {},
    typing: {},
    activeConversation: null,
  }),
}));

function mergeMessages(existing: Message[], incoming: Message[]): Message[] {
  const byId = new Map<string, Message>();
  for (const message of existing) {
    byId.set(message.id, message);
  }
  for (const message of incoming) {
    byId.set(message.id, message);
  }
  return Array.from(byId.values()).sort((a, b) =>
    a.created_at.localeCompare(b.created_at),
  );
}

function updateMessageState(
  s: ChatState,
  conversationId: string,
  messageId: string,
  state: MessageState,
): Pick<ChatState, "messagesByConversation"> {
  const list = s.messagesByConversation[conversationId];
  if (!list) return { messagesByConversation: s.messagesByConversation };
  const next = list.map((m) => (m.id === messageId ? { ...m, state } : m));
  return {
    messagesByConversation: {
      ...s.messagesByConversation,
      [conversationId]: next,
    },
  };
}

// ----------------------------------------------------------------------------
// Selector helpers.
// ----------------------------------------------------------------------------
export const selectMessages = (conversationId: string) => (s: ChatState): Message[] =>
  s.messagesByConversation[conversationId] ?? [];

export const selectTyping = (conversationId: string) => (s: ChatState): number[] => {
  const set = s.typing[conversationId];
  return set ? Array.from(set) : [];
};

export { conversationIdForPair };
