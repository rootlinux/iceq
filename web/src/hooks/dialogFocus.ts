export interface FocusTarget { focus(): void }

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
