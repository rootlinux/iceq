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

function setup(options: { standalone?: boolean } = {}) {
  const target = new EventTarget();
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
  let notifications = 0;
  lifecycle.subscribe(() => { notifications += 1; });
  target.dispatchEvent(new FakeInstallPromptEvent());
  assert.equal(notifications, 2, "one immediate snapshot plus one captured event");
  lifecycle.stop();
  target.dispatchEvent(new FakeInstallPromptEvent());
  assert.equal(notifications, 2);
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
