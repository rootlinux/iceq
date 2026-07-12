// src/store/signalStore.ts
//
// Signal Protocol state. The actual keys / sessions live
// in IndexedDB (lib/indexeddb.ts). This store is a thin
// React-friendly facade: it exposes "is the Signal store
// ready?" and "how many prekeys do we have left?" so the
// UI can prompt for re-key when the pool runs low.
//
// We deliberately do NOT cache the private key here. The
// Signal bindings manage their own in-memory state; passing
// the bytes through Zustand would put them into the
// React DevTools / Redux DevTools / a future persistence
// layer.

import { create } from "zustand";
import { loadPreKeys } from "../lib/indexeddb";

interface SignalState {
  ready: boolean;
  prekeyCount: number;
  // Last error surfaced from the Signal bindings. The
  // register form uses this to show "key generation failed".
  lastError: string | null;

  // Actions
  setReady: (ready: boolean) => void;
  refreshPrekeyCount: () => Promise<void>;
  setError: (message: string | null) => void;
}

export const useSignalStore = create<SignalState>((set) => ({
  ready: false,
  prekeyCount: 0,
  lastError: null,

  setReady: (ready) => set({ ready }),

  refreshPrekeyCount: async () => {
    const list = await loadPreKeys();
    set({ prekeyCount: list.length });
  },

  setError: (message) => set({ lastError: message }),
}));

// Threshold at which the chat shell prompts the user to
// upload more prekeys. Below 10 the server may struggle
// to satisfy bundle requests; below this, the user is
// asked to re-up. Exported so tests can use the same
// number.
export const PREKEY_LOW_WATERMARK = 10;
