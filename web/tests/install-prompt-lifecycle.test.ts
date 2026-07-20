import assert from "node:assert/strict";
import test from "node:test";
import {
  INSTALL_PROMPT_DISMISS_KEY,
  INSTALL_PROMPT_DISMISS_TTL_MS,
  createInstallPromptLifecycle,
  type BeforeInstallPromptEvent,
} from "../src/lib/installPromptLifecycle.js";

class MemoryStorage {
  readonly values = new Map<string, string>();
  getItem(key: string): string | null { return this.values.get(key) ?? null; }
  setItem(key: string, value: string): void { this.values.set(key, value); }
}

class FakeInstallPromptEvent extends Event implements BeforeInstallPromptEvent {
  promptCalls = 0;
  constructor(readonly outcome: "accepted" | "dismissed" = "accepted") {
    super("beforeinstallprompt", { cancelable: true });
  }
  async prompt(): Promise<void> { this.promptCalls += 1; }
  get userChoice(): Promise<{ outcome: "accepted" | "dismissed" }> {
    return Promise.resolve({ outcome: this.outcome });
  }
}

class TrackingTarget {
  private readonly listeners = new Map<string, Set<EventListener>>();
  readonly added = new Map<string, number>();
  readonly removed = new Map<string, number>();

  addEventListener(type: string, listener: EventListener): void {
    const listeners = this.listeners.get(type) ?? new Set<EventListener>();
    listeners.add(listener);
    this.listeners.set(type, listeners);
    this.added.set(type, (this.added.get(type) ?? 0) + 1);
  }
  removeEventListener(type: string, listener: EventListener): void {
    this.listeners.get(type)?.delete(listener);
    this.removed.set(type, (this.removed.get(type) ?? 0) + 1);
  }
  dispatchEvent(event: Event): boolean {
    for (const listener of this.listeners.get(event.type) ?? []) listener(event);
    return !event.defaultPrevented;
  }
}

function setup(options: { standalone?: boolean } = {}) {
  const target = new TrackingTarget();
  const storage = new MemoryStorage();
  let now = 1_000;
  const lifecycle = createInstallPromptLifecycle({
    target,
    storage,
    now: () => now,
    isStandalone: () => options.standalone ?? false,
  });
  return { target, storage, lifecycle, advance: (ms: number) => { now += ms; } };
}

test("a pre-auth install event remains available to an authenticated subscriber", () => {
  const { target, lifecycle } = setup();
  lifecycle.start();
  const event = new FakeInstallPromptEvent();
  target.dispatchEvent(event);
  assert.equal(event.defaultPrevented, true);

  const observed: Array<BeforeInstallPromptEvent | null> = [];
  const unsubscribe = lifecycle.subscribe((value) => observed.push(value));
  assert.equal(observed.at(-1), event);
  unsubscribe();
  lifecycle.stop();
});

test("capture initialization is idempotent and stop removes its listener", () => {
  const { target, lifecycle } = setup();
  lifecycle.start();
  lifecycle.start();
  assert.equal(target.added.get("beforeinstallprompt"), 1);
  assert.equal(target.added.get("appinstalled"), 1);
  let notifications = 0;
  lifecycle.subscribe(() => { notifications += 1; });
  target.dispatchEvent(new FakeInstallPromptEvent());
  assert.equal(notifications, 2, "one immediate snapshot plus one captured event");
  lifecycle.stop();
  assert.equal(target.removed.get("beforeinstallprompt"), 1);
  assert.equal(target.removed.get("appinstalled"), 1);
  target.dispatchEvent(new FakeInstallPromptEvent());
  assert.equal(notifications, 2);
});

test("an external app install clears a captured prompt and removes stale UI state", () => {
  const { target, lifecycle } = setup();
  lifecycle.start();
  const observed: Array<BeforeInstallPromptEvent | null> = [];
  lifecycle.subscribe((event) => observed.push(event));
  const prompt = new FakeInstallPromptEvent();
  target.dispatchEvent(prompt);
  assert.equal(observed.at(-1), prompt);

  target.dispatchEvent(new Event("appinstalled"));
  assert.equal(lifecycle.current(), null);
  assert.equal(observed.at(-1), null);
});

test("explicit and browser dismissal suppress new prompts until the TTL expires", async () => {
  const { target, storage, lifecycle, advance } = setup();
  lifecycle.start();
  target.dispatchEvent(new FakeInstallPromptEvent());
  lifecycle.dismiss();
  assert.equal(storage.getItem(INSTALL_PROMPT_DISMISS_KEY), "1000");
  target.dispatchEvent(new FakeInstallPromptEvent());
  assert.equal(lifecycle.current(), null);

  advance(INSTALL_PROMPT_DISMISS_TTL_MS + 1);
  const browserDismissed = new FakeInstallPromptEvent("dismissed");
  target.dispatchEvent(browserDismissed);
  assert.equal(await lifecycle.prompt(), "dismissed");
  assert.equal(browserDismissed.promptCalls, 1);
  assert.equal(lifecycle.current(), null);
  assert.equal(storage.getItem(INSTALL_PROMPT_DISMISS_KEY), String(1_001 + INSTALL_PROMPT_DISMISS_TTL_MS));
});

test("standalone mode consumes the event without exposing install UI", () => {
  const { target, lifecycle } = setup({ standalone: true });
  lifecycle.start();
  const event = new FakeInstallPromptEvent();
  target.dispatchEvent(event);
  assert.equal(event.defaultPrevented, true);
  assert.equal(lifecycle.current(), null);
});

test("concurrent prompt calls share one browser prompt flight and reset after resolution", async () => {
  const { target, lifecycle } = setup();
  lifecycle.start();
  let resolvePrompt!: () => void;
  const promptGate = new Promise<void>((resolve) => { resolvePrompt = resolve; });
  const event = new FakeInstallPromptEvent();
  event.prompt = async () => { event.promptCalls += 1; await promptGate; };
  target.dispatchEvent(event);

  const first = lifecycle.prompt();
  const second = lifecycle.prompt();
  assert.equal(second, first);
  await Promise.resolve();
  assert.equal(event.promptCalls, 1);
  resolvePrompt();
  assert.deepEqual(await Promise.all([first, second]), ["accepted", "accepted"]);
  assert.equal(lifecycle.current(), null);

  const next = new FakeInstallPromptEvent();
  target.dispatchEvent(next);
  assert.equal(await lifecycle.prompt(), "accepted");
  assert.equal(next.promptCalls, 1);
});

test("concurrent prompt callers share rejection and a later event remains usable", async () => {
  const { target, lifecycle } = setup();
  lifecycle.start();
  const event = new FakeInstallPromptEvent();
  event.prompt = async () => { event.promptCalls += 1; throw new Error("prompt failed"); };
  target.dispatchEvent(event);

  const first = lifecycle.prompt();
  const second = lifecycle.prompt();
  assert.equal(second, first);
  const results = await Promise.allSettled([first, second]);
  assert.equal(event.promptCalls, 1);
  assert.deepEqual(results.map((result) => result.status), ["rejected", "rejected"]);
  assert.equal(lifecycle.current(), null);

  const next = new FakeInstallPromptEvent();
  target.dispatchEvent(next);
  assert.equal(await lifecycle.prompt(), "accepted");
});
