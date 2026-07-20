export const INSTALL_PROMPT_DISMISS_KEY = "iceq_install_dismissed";
export const INSTALL_PROMPT_DISMISS_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
}

interface EventTargetLike {
  addEventListener(type: string, listener: EventListener): void;
  removeEventListener(type: string, listener: EventListener): void;
}

interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

interface InstallPromptLifecycleOptions {
  target?: EventTargetLike;
  storage?: StorageLike;
  now?: () => number;
  isStandalone?: () => boolean;
}

type InstallPromptSubscriber = (event: BeforeInstallPromptEvent | null) => void;

export interface InstallPromptLifecycle {
  start(): void;
  stop(): void;
  subscribe(subscriber: InstallPromptSubscriber): () => void;
  current(): BeforeInstallPromptEvent | null;
  prompt(): Promise<"accepted" | "dismissed" | null>;
  dismiss(): void;
}

export function createInstallPromptLifecycle(options: InstallPromptLifecycleOptions): InstallPromptLifecycle {
  const target = options.target;
  const storage = options.storage;
  const now = options.now ?? Date.now;
  const isStandalone = options.isStandalone ?? (() => false);
  const subscribers = new Set<InstallPromptSubscriber>();
  let deferredPrompt: BeforeInstallPromptEvent | null = null;
  let started = false;

  const isDismissed = (): boolean => {
    try {
      const value = storage?.getItem(INSTALL_PROMPT_DISMISS_KEY);
      if (!value) return false;
      const dismissedAt = Number(value);
      return Number.isFinite(dismissedAt) && now() - dismissedAt < INSTALL_PROMPT_DISMISS_TTL_MS;
    } catch {
      return false;
    }
  };

  const publish = (): void => {
    for (const subscriber of subscribers) subscriber(deferredPrompt);
  };

  const clear = (): void => {
    if (deferredPrompt === null) return;
    deferredPrompt = null;
    publish();
  };

  const rememberDismissal = (): void => {
    try { storage?.setItem(INSTALL_PROMPT_DISMISS_KEY, String(now())); } catch { /* restricted storage */ }
  };

  const onBeforeInstallPrompt: EventListener = (rawEvent) => {
    const event = rawEvent as BeforeInstallPromptEvent;
    event.preventDefault();
    if (isStandalone() || isDismissed()) {
      clear();
      return;
    }
    deferredPrompt = event;
    publish();
  };

  return {
    start(): void {
      if (started || !target) return;
      target.addEventListener("beforeinstallprompt", onBeforeInstallPrompt);
      started = true;
    },
    stop(): void {
      if (!started || !target) return;
      target.removeEventListener("beforeinstallprompt", onBeforeInstallPrompt);
      started = false;
    },
    subscribe(subscriber: InstallPromptSubscriber): () => void {
      subscribers.add(subscriber);
      subscriber(this.current());
      return () => subscribers.delete(subscriber);
    },
    current(): BeforeInstallPromptEvent | null {
      if (isStandalone() || isDismissed()) {
        deferredPrompt = null;
      }
      return deferredPrompt;
    },
    async prompt(): Promise<"accepted" | "dismissed" | null> {
      const event = this.current();
      if (!event) return null;
      try {
        await event.prompt();
        const { outcome } = await event.userChoice;
        if (outcome === "dismissed") rememberDismissal();
        return outcome;
      } finally {
        clear();
      }
    },
    dismiss(): void {
      rememberDismissal();
      clear();
    },
  };
}

function browserIsStandalone(): boolean {
  const navigatorStandalone = Boolean((navigator as Navigator & { standalone?: boolean }).standalone);
  return navigatorStandalone || window.matchMedia("(display-mode: standalone)").matches;
}

type LifecycleGlobal = typeof globalThis & {
  __iceqInstallPromptLifecycle?: InstallPromptLifecycle;
};

const lifecycleGlobal = globalThis as LifecycleGlobal;

export const installPromptLifecycle = lifecycleGlobal.__iceqInstallPromptLifecycle ??= createInstallPromptLifecycle({
  target: typeof window === "undefined" ? undefined : window,
  storage: typeof localStorage === "undefined" ? undefined : localStorage,
  isStandalone: typeof window === "undefined" ? () => false : browserIsStandalone,
});

export function initializeInstallPromptCapture(): () => void {
  installPromptLifecycle.start();
  return () => installPromptLifecycle.stop();
}
