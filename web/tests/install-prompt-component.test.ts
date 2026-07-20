import assert from "node:assert/strict";
import test from "node:test";
import { createInstallPromptLifecycle, type BeforeInstallPromptEvent } from "../src/lib/installPromptLifecycle.js";

interface InstallPromptComponentModule {
  handleInstallPrompt?: (
    prompt: () => Promise<unknown>,
    report?: (message: string) => void,
  ) => Promise<void>;
}

class RejectingInstallPromptEvent extends Event implements BeforeInstallPromptEvent {
  readonly userChoice = Promise.resolve({ outcome: "accepted" as const });
  promptCalls = 0;
  constructor() { super("beforeinstallprompt", { cancelable: true }); }
  async prompt(): Promise<void> {
    this.promptCalls += 1;
    throw new Error("sensitive browser detail");
  }
}

test("InstallPrompt safely handles browser prompt rejection and reports generic context", async () => {
  const component = await import("../src/components/PWA/InstallPrompt.js") as InstallPromptComponentModule;
  assert.equal(typeof component.handleInstallPrompt, "function");
  if (!component.handleInstallPrompt) return;

  const target = new EventTarget();
  const lifecycle = createInstallPromptLifecycle({ target });
  lifecycle.start();
  const observed: Array<BeforeInstallPromptEvent | null> = [];
  lifecycle.subscribe((event) => observed.push(event));
  const event = new RejectingInstallPromptEvent();
  target.dispatchEvent(event);
  const reports: string[] = [];

  await assert.doesNotReject(
    component.handleInstallPrompt(
      () => lifecycle.prompt(),
      (message) => reports.push(message),
    ),
  );

  assert.equal(event.promptCalls, 1);
  assert.deepEqual(reports, ["PWA install prompt failed"]);
  assert.doesNotMatch(reports[0] ?? "", /sensitive browser detail/);
  assert.equal(lifecycle.current(), null);
  assert.equal(observed.at(-1), null, "the rejected prompt must not resurrect the banner");
  lifecycle.stop();
});
