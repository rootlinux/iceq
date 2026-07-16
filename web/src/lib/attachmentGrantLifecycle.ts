import { grantFileAccess, revokeFileAccess } from "../api/files";

type TimerHandle = ReturnType<typeof setTimeout>;
type PendingGrant = { objectKey: string; granteeUin: number; timer: TimerHandle };

interface GrantLifecycleDeps {
  grant: (objectKey: string, granteeUin: number) => Promise<void>;
  revoke: (objectKey: string, granteeUin: number) => Promise<void>;
  setTimer?: (fn: () => void, ms: number) => TimerHandle;
  clearTimer?: (timer: TimerHandle) => void;
  timeoutMs?: number;
}

export class AttachmentGrantLifecycle {
  private readonly pending = new Map<string, PendingGrant>();
  private readonly setTimer: (fn: () => void, ms: number) => TimerHandle;
  private readonly clearTimer: (timer: TimerHandle) => void;
  private readonly timeoutMs: number;

  constructor(private readonly deps: GrantLifecycleDeps) {
    this.setTimer = deps.setTimer ?? setTimeout;
    this.clearTimer = deps.clearTimer ?? clearTimeout;
    this.timeoutMs = deps.timeoutMs ?? 30_000;
  }

  async prepare(messageId: string, objectKey: string, granteeUin: number): Promise<void> {
    await this.deps.grant(objectKey, granteeUin);
    const timer = this.setTimer(() => { void this.fail(messageId); }, this.timeoutMs);
    this.pending.set(messageId, { objectKey, granteeUin, timer });
  }

  ack(messageId: string, state: "persisted" | "delivered" | "read" | "pong"): void {
    if (state === "pong") return;
    const grant = this.pending.get(messageId);
    if (!grant) return;
    this.clearTimer(grant.timer);
    this.pending.delete(messageId);
  }

  async fail(messageId: string): Promise<void> {
    const grant = this.pending.get(messageId);
    if (!grant) return;
    this.pending.delete(messageId);
    this.clearTimer(grant.timer);
    await this.deps.revoke(grant.objectKey, grant.granteeUin);
  }

  async revokeAll(): Promise<void> {
    const ids = [...this.pending.keys()];
    await Promise.allSettled(ids.map((id) => this.fail(id)));
  }
}

export const attachmentGrantLifecycle = new AttachmentGrantLifecycle({
  grant: grantFileAccess,
  revoke: revokeFileAccess,
});
