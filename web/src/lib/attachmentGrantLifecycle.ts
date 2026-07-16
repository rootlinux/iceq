import { grantFileAccess, revokeFileAccess } from "../api/files";
import { registerMemoryReset } from "./localDataCleanup";

type TimerHandle = ReturnType<typeof setTimeout>;
type ExhaustionReason = "revoke_exhausted" | "grant_restore_exhausted";

export interface AttachmentGrantExhaustedEvent {
  messageId: string;
  attempts: number;
  reason: ExhaustionReason;
}

type PendingGrant = {
  objectKey: string;
  granteeUin: number;
  timer: TimerHandle;
  inFlight: Promise<boolean> | null;
  acknowledged: boolean;
  needsRestore: boolean;
};

interface GrantLifecycleDeps {
  grant: (objectKey: string, granteeUin: number) => Promise<void>;
  revoke: (objectKey: string, granteeUin: number) => Promise<void>;
  setTimer?: (fn: () => void, ms: number) => TimerHandle;
  clearTimer?: (timer: TimerHandle) => void;
  timeoutMs?: number;
  retryDelaysMs?: readonly number[];
  sleep?: (ms: number) => Promise<void>;
  onExhausted?: (event: AttachmentGrantExhaustedEvent) => void;
}

export class AttachmentGrantLifecycle {
  private readonly pending = new Map<string, PendingGrant>();
  private readonly setTimer: (fn: () => void, ms: number) => TimerHandle;
  private readonly clearTimer: (timer: TimerHandle) => void;
  private readonly timeoutMs: number;
  private readonly retryDelaysMs: readonly number[];
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(private readonly deps: GrantLifecycleDeps) {
    this.setTimer = deps.setTimer ?? setTimeout;
    this.clearTimer = deps.clearTimer ?? clearTimeout;
    this.timeoutMs = deps.timeoutMs ?? 30_000;
    this.retryDelaysMs = deps.retryDelaysMs ?? [250, 1_000, 3_000];
    this.sleep = deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  async prepare(messageId: string, objectKey: string, granteeUin: number): Promise<void> {
    await this.deps.grant(objectKey, granteeUin);
    const timer = this.setTimer(() => { void this.fail(messageId); }, this.timeoutMs);
    this.pending.set(messageId, {
      objectKey, granteeUin, timer, inFlight: null, acknowledged: false, needsRestore: false,
    });
  }

  ack(messageId: string, state: "persisted" | "delivered" | "read" | "pong"): void {
    if (state === "pong") return;
    const entry = this.pending.get(messageId);
    if (!entry) return;
    this.clearTimer(entry.timer);
    if (!entry.inFlight && !entry.needsRestore) {
      this.pending.delete(messageId);
      return;
    }
    // If revoke is already on the wire, remember the ACK. A successful revoke
    // is compensated by re-granting; a failed revoke needs no compensation.
    entry.acknowledged = true;
    if (entry.needsRestore && !entry.inFlight) void this.fail(messageId);
  }

  fail(messageId: string): Promise<boolean> {
    const entry = this.pending.get(messageId);
    if (!entry) return Promise.resolve(true);
    if (entry.inFlight) return entry.inFlight;
    this.clearTimer(entry.timer);
    const operation = this.settle(messageId, entry).finally(() => {
      if (entry.inFlight === operation) entry.inFlight = null;
    });
    entry.inFlight = operation;
    return operation;
  }

  async revokeAll(): Promise<void> {
    await Promise.allSettled([...this.pending.keys()].map((id) => this.fail(id)));
  }

  discardAll(): void {
    for (const entry of this.pending.values()) this.clearTimer(entry.timer);
    this.pending.clear();
  }

  private async settle(messageId: string, entry: PendingGrant): Promise<boolean> {
    if (entry.needsRestore) return this.restore(messageId, entry);
    const attempts = this.retryDelaysMs.length + 1;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      if (entry.acknowledged) {
        this.pending.delete(messageId);
        return true;
      }
      try {
        await this.deps.revoke(entry.objectKey, entry.granteeUin);
        if (entry.acknowledged) {
          entry.needsRestore = true;
          return this.restore(messageId, entry);
        }
        this.pending.delete(messageId);
        return true;
      } catch {
        if (entry.acknowledged) {
          // The revoke failed, so the acknowledged message's grant remains.
          this.pending.delete(messageId);
          return true;
        }
        if (attempt < attempts) await this.sleep(this.retryDelaysMs[attempt - 1] ?? 0);
      }
    }
    this.reportExhausted(messageId, attempts, "revoke_exhausted");
    return false;
  }

  private async restore(messageId: string, entry: PendingGrant): Promise<boolean> {
    const attempts = this.retryDelaysMs.length + 1;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        await this.deps.grant(entry.objectKey, entry.granteeUin);
        this.pending.delete(messageId);
        return true;
      } catch {
        if (attempt < attempts) await this.sleep(this.retryDelaysMs[attempt - 1] ?? 0);
      }
    }
    this.reportExhausted(messageId, attempts, "grant_restore_exhausted");
    return false;
  }

  private reportExhausted(messageId: string, attempts: number, reason: ExhaustionReason): void {
    try {
      this.deps.onExhausted?.({ messageId, attempts, reason });
    } catch {
      // Telemetry/UI hooks must never break cleanup or cause an unhandled rejection.
    }
  }
}

export const attachmentGrantLifecycle = new AttachmentGrantLifecycle({
  grant: grantFileAccess,
  revoke: revokeFileAccess,
  onExhausted: (detail) => {
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("iceq:attachment-grant-cleanup-failed", { detail }));
    }
  },
});

registerMemoryReset(() => attachmentGrantLifecycle.discardAll());
