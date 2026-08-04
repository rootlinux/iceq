// src/components/Contacts/AddContact.tsx
//
// Add-contact modal — Arctic Signal design.

import { useCallback, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ApiError } from "../../api/client";
import { useAuthStore } from "../../store/authStore";
import { useContactStore } from "../../store/contactStore";
import { useDialogFocus } from "../../hooks/useDialogFocus";
import { useI18n } from "../../i18n";

function getAddContactErrorMessage(error: unknown, t: ReturnType<typeof useI18n>["t"]): string {
  if (error instanceof ApiError) {
    if (error.status === 404 || error.code === "USER_NOT_FOUND") return t("contacts.userNotFound");
    if (error.status === 409 || error.code === "CONTACT_EXISTS") return t("contacts.alreadyAdded");
    if (error.code === "SELF_CONTACT_FORBIDDEN") return t("contacts.noSelf");
  }
  if (error instanceof Error && error.message.trim() !== "") return error.message;
  return t("contacts.sendFailed");
}

export function AddContact(): JSX.Element {
  const i18n = useI18n();
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
    if (trimmed === "") { setError(i18n.t("contacts.enterUin")); return; }

    const parsed = Number.parseInt(trimmed, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      setError(i18n.t("contacts.positiveUin"));
      return;
    }
    if (selfUin !== null && parsed === selfUin) {
      setError(i18n.t("contacts.noSelf"));
      return;
    }

    setSubmitting(true);
    try {
      await addContact(parsed);
      setSuccess(i18n.t("contacts.sent"));
      setTargetUIN("");
    } catch (err) {
      setError(getAddContactErrorMessage(err, i18n.t));
    } finally { setSubmitting(false); }
  }

  return (
    <>
      <button
        type="button"
        ref={openerRef}
        className="iceq-btn-secondary mx-3 mt-3 w-[calc(100%-1.5rem)]"
        onClick={() => setOpen(true)}
      >
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" className="mr-2">
          <line x1="8" y1="2" x2="8" y2="14"/><line x1="2" y1="8" x2="14" y2="8"/>
        </svg>
        {i18n.t("contacts.add")}
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
                <h2 id="add-contact-title" className="text-lg font-semibold text-frozen">
                  {i18n.t("contacts.add")}
                </h2>
                <p className="mt-1 text-sm text-mist">{i18n.t("contacts.addHelp")}</p>
              </div>
              <button
                type="button"
                className="iceq-btn-icon"
                aria-label={i18n.t("contacts.closeAdd")}
                onClick={closeModal}
                disabled={submitting}
              >
                <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                  <line x1="4" y1="4" x2="14" y2="14"/><line x1="14" y1="4" x2="4" y2="14"/>
                </svg>
              </button>
            </div>

            <form onSubmit={(e) => void onSubmit(e)} className="space-y-3">
              <div>
                <label htmlFor="add-contact-uin" className="text-label text-mist">
                  {i18n.t("contacts.uin")}
                </label>
                <input
                  id="add-contact-uin"
                  ref={inputRef}
                  type="number"
                  min="1"
                  inputMode="numeric"
                  autoComplete="off"
                  className="iceq-input mt-1.5"
                  value={targetUIN}
                  onChange={(e) => setTargetUIN(e.target.value)}
                  disabled={submitting}
                  placeholder={i18n.t("contacts.uinExample")}
                  required
                />
              </div>

              {error && (
                <div role="alert" className="iceq-alert-error">{error}</div>
              )}

              {success && (
                <div role="status" className="iceq-alert-success">{success}</div>
              )}

              <div className="iceq-modal-buttons">
                <button
                  type="button"
                  className="iceq-btn-secondary"
                  onClick={closeModal}
                  disabled={submitting}
                >
                  {i18n.t("common.cancel")}
                </button>
                <button type="submit" className="iceq-btn-primary" disabled={submitting}>
                  {submitting ? i18n.t("contacts.sending") : i18n.t("contacts.sendRequest")}
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
