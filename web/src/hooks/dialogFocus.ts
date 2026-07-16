export interface FocusTarget { focus(): void }

export interface DialogStack {
  push(): symbol;
  remove(token: symbol): void;
  isTop(token: symbol): boolean;
}

export function createDialogStack(): DialogStack {
  const entries: symbol[] = [];
  return {
    push(): symbol { const token = Symbol("dialog"); entries.push(token); return token; },
    remove(token: symbol): void { const index = entries.lastIndexOf(token); if (index >= 0) entries.splice(index, 1); },
    isTop(token: symbol): boolean { return entries.length > 0 && entries[entries.length - 1] === token; },
  };
}

export const dialogStack = createDialogStack();

export function focusInitialTarget(preferred: FocusTarget | null, fallback: FocusTarget | null): void {
  (preferred ?? fallback)?.focus();
}

export function handleDialogEscape(key: string, close: () => void): boolean {
  if (key !== "Escape") return false;
  close();
  return true;
}

export function restoreDialogFocus(target: FocusTarget | null): void { target?.focus(); }

export function cycleDialogFocus(items: readonly FocusTarget[], active: FocusTarget | null, backwards: boolean): boolean {
  if (items.length === 0) return false;
  const first = items[0];
  const last = items[items.length - 1];
  if (backwards && active === first) { last?.focus(); return true; }
  if (!backwards && active === last) { first?.focus(); return true; }
  return false;
}
