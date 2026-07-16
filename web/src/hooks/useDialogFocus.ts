import { useEffect, useRef, type RefObject } from "react";
import { cycleDialogFocus, dialogStack, focusInitialTarget, handleDialogEscape, restoreDialogFocus } from "./dialogFocus";

const focusable = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function useDialogFocus(open: boolean, onClose: () => void, returnFocus: RefObject<HTMLElement>, initialFocus?: RefObject<HTMLElement>): RefObject<HTMLDivElement> {
  const dialogRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const stackToken = dialogStack.push();
    const dialog = dialogRef.current;
    const first = dialog?.querySelector<HTMLElement>(focusable);
    focusInitialTarget(initialFocus?.current ?? null, first ?? null);
    const onKeyDown = (event: KeyboardEvent): void => {
      if (!dialogStack.isTop(stackToken)) return;
      if (handleDialogEscape(event.key, onClose)) { event.preventDefault(); return; }
      if (event.key !== "Tab" || !dialog) return;
      const items = Array.from(dialog.querySelectorAll<HTMLElement>(focusable));
      if (items.length === 0) return;
      if (cycleDialogFocus(items, document.activeElement as HTMLElement | null, event.shiftKey)) event.preventDefault();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      const wasTop = dialogStack.isTop(stackToken);
      dialogStack.remove(stackToken);
      if (wasTop) restoreDialogFocus(returnFocus.current);
    };
  }, [initialFocus, onClose, open, returnFocus]);
  return dialogRef;
}
