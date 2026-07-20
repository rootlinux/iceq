import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { StaticRouter } from "react-router-dom/server.js";

class MemoryStorage {
  private readonly values = new Map<string, string>();
  getItem(key: string): string | null { return this.values.get(key) ?? null; }
  setItem(key: string, value: string): void { this.values.set(key, value); }
  removeItem(key: string): void { this.values.delete(key); }
  clear(): void { this.values.clear(); }
  key(index: number): string | null { return [...this.values.keys()][index] ?? null; }
  get length(): number { return this.values.size; }
}

class BrowserWindow extends EventTarget {
  matchMedia(): MediaQueryList {
    return { matches: false } as MediaQueryList;
  }
}

class CapturedInstallEvent extends Event {
  readonly userChoice = Promise.resolve({ outcome: "accepted" as const });
  constructor() { super("beforeinstallprompt", { cancelable: true }); }
  async prompt(): Promise<void> {}
}

test("public login omits install UI while the authenticated shell renders a pre-auth capture", async () => {
  const browserWindow = new BrowserWindow();
  Object.defineProperty(globalThis, "window", { configurable: true, value: browserWindow });
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: new MemoryStorage() });
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { languages: ["en"], onLine: true, userAgent: "test", platform: "test", maxTouchPoints: 0 },
  });

  const [{ initializeInstallPromptCapture }, { MainLayout }, { LoginForm }] = await Promise.all([
    import("../src/lib/installPromptLifecycle.js"),
    import("../src/components/Layout/MainLayout.js"),
    import("../src/components/Auth/LoginForm.js"),
  ]);
  const stopCapture = initializeInstallPromptCapture();
  browserWindow.dispatchEvent(new CapturedInstallEvent());

  const publicMarkup = renderToStaticMarkup(
    React.createElement(StaticRouter, { location: "/login" }, React.createElement(LoginForm)),
  );
  assert.doesNotMatch(publicMarkup, /Add IceQ to your home screen/);

  const authenticatedMarkup = renderToStaticMarkup(
    React.createElement(
      StaticRouter,
      { location: "/app" },
      React.createElement(MainLayout, null, React.createElement("div", null, "authenticated")),
    ),
  );
  assert.match(authenticatedMarkup, /Add IceQ to your home screen/);
  stopCapture();
});
