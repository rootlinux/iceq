import { useCallback, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ApiError } from "../../api/client";
import { useAuthStore } from "../../store/authStore";
import { useContactStore } from "../../store/contactStore";
import { useDialogFocus } from "../../hooks/useDialogFocus";

function getAddContactErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 404 || error.code === "USER_NOT_FOUND") return "User not found";
    if (error.status === 409 || error.code === "CONTACT_EXISTS") return "Already added";
    if (error.code === "SELF_CONTACT_FORBIDDEN") return "You can't add yourself";
  }
  if (error instanceof Error && error.message.trim() !== "") return error.message;
  return "Could not send contact request";
}

export function AddContact(): JSX.Element {
  const selfUin = useAuthStore((s) => s.uin);
  const addContact = useContactStore((s) => s.addContact);
  const [open, setOpen] = useState(false);
  const [targetUIN, setTargetUIN] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const openerRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const closeModal = useCallback((): void => {
    setOpen(false);
    setTargetUIN("");
    setSubmitting(false);
    setError(null);
    setSuccess(null);
  }, []);
  const dialogRef = useDialogFocus(open, closeModal, openerRef, inputRef);

  async function onSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    const trimmed = targetUIN.trim();
    if (trimmed === "") {
      setError("Please enter a UIN");
      return;
    }

    const parsed = Number.parseInt(trimmed, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      setError("UIN must be a positive integer");
      return;
    }
    if (selfUin !== null && parsed === selfUin) {
      setError("You can't add yourself");
      return;
    }

    setSubmitting(true);
    try {
      await addContact(parsed);
      setSuccess("Contact request sent");
      setTargetUIN("");
    } catch (err) {
      setError(getAddContactErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <button
        type="button"
        ref={openerRef}
        className="iceq-btn-secondary m-2 w-[calc(100%-1rem)]"
        onClick={() => setOpen(true)}
      >
        + Add contact
      </button>

      {open && (
        <div
          className="iceq-modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="add-contact-title"
          onClick={closeModal}
        >
          <div className="iceq-modal" ref={dialogRef} onClick={(e) => e.stopPropagation()}>
            <div className="mb-4 flex items-start justify-between gap-4">
              <div>
                <h2 id="add-contact-title" className="text-lg font-semibold text-text">
                  Add contact
                </h2>
                <p className="mt-1 text-sm text-text-2">
                  Enter a UIN to send a contact request.
                </p>
              </div>
              <button
                type="button"
                className="iceq-btn-secondary"
                aria-label="Close add contact"
                onClick={closeModal}
                disabled={submitting}
              >
                ✕
              </button>
            </div>

            <form onSubmit={(e) => void onSubmit(e)} className="space-y-3">
              <div>
                <label htmlFor="add-contact-uin" className="mb-1 block text-xs text-text-2">
                  UIN
                </label>
                <input
                  id="add-contact-uin"
                  ref={inputRef}
                  type="number"
                  min="1"
                  inputMode="numeric"
                  autoComplete="off"
                  className="iceq-input"
                  value={targetUIN}
                  onChange={(e) => setTargetUIN(e.target.value)}
                  disabled={submitting}
                  placeholder="e.g. 10000042"
                  required
                />
              </div>

              {error && (
                <div role="alert" className="rounded-md border border-presence-dnd bg-surface p-2 text-sm">
                  {error}
                </div>
              )}

              {success && (
                <div
                  role="status"
                  className="rounded-md border border-presence-online bg-surface p-2 text-sm"
                >
                  {success}
                </div>
              )}

              <div className="iceq-modal-buttons">
                <button
                  type="button"
                  className="iceq-btn-secondary"
                  onClick={closeModal}
                  disabled={submitting}
                >
                  Cancel
                </button>
                <button type="submit" className="iceq-btn-primary" disabled={submitting}>
                  {submitting ? "Sending…" : "Send request"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}

export default AddContact;
