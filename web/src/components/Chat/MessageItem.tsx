// src/components/Chat/MessageItem.tsx
//
// A single message bubble — Encrypted Aurora material treatments.
//
// Outgoing: softly illuminated ice/cobalt material (electric ice glow)
// Incoming: darker translucent mineral surface
// Deliberate corner treatments with subtle edge light.
// Attachment cards read as encrypted objects, not plain download boxes.

import { useState } from "react";
import { downloadEncryptedFile } from "../../api/files";
import { assertSafeDownloadMetadata, isEncryptedFileManifest, withObjectUrl } from "../../lib/fileCrypto";
import type { Message, MessageAttachment } from "../../types/models";
import { useI18n } from "../../i18n";

interface MessageItemProps {
  message: Message;
}

const messageStateKeys = {
  sending: "message.state.sending",
  delivered: "message.state.delivered",
  read: "message.state.read",
  failed: "message.state.failed",
} as const;

function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

function parseAttachment(message: Message): MessageAttachment | null {
  if (message.attachment) {
    try {
      if (!isEncryptedFileManifest(message.attachment.manifest)) return null;
      assertSafeDownloadMetadata(message.attachment.object_key, message.attachment.name);
      return message.attachment;
    } catch { return null; }
  }
  const isFileMessage = message.content_type === "file";
  if (!isFileMessage || !message.plaintext) return null;
  try {
    const parsed = JSON.parse(message.plaintext) as {
      kind?: unknown;
      object_key?: unknown;
      manifest?: unknown;
    };
    if (parsed.kind !== "iceq.attachment.v1") return null;
    if (typeof parsed.object_key !== "string") return null;
    if (!isEncryptedFileManifest(parsed.manifest)) return null;
    return {
      object_key: parsed.object_key,
      manifest: parsed.manifest,
      name: parsed.manifest.name ?? "iceq-file",
      mime_type: parsed.manifest.mime_type,
      size: parsed.manifest.size,
    };
  } catch {
    return null;
  }
}

export function MessageItem({ message }: MessageItemProps): JSX.Element {
  const i18n = useI18n();
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const outgoing = message.is_outgoing;
  const attachment = parseAttachment(message);
  const invalidAttachment = message.content_type === "file" && !attachment;
  const text = attachment || invalidAttachment ? "" : message.plaintext;

  const onDownload = async (e: React.MouseEvent<HTMLAnchorElement>): Promise<void> => {
    e.preventDefault();
    if (!attachment || downloading) return;
    setDownloading(true);
    setDownloadError(null);
    try {
      assertSafeDownloadMetadata(attachment.object_key, attachment.name);
      const blob = await downloadEncryptedFile(attachment.object_key, attachment.manifest);
      await withObjectUrl(blob, (url) => {
        const a = document.createElement("a");
        a.href = url;
        a.download = attachment.name;
        document.body.appendChild(a);
        a.click();
        a.remove();
      });
    } catch {
      setDownloadError(i18n.t("chat.fileAuthFailed"));
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className={`flex ${outgoing ? "justify-end" : "justify-start"}`}>
      <div
        className={
          "max-w-chat-msg rounded-2xl px-4 py-2.5 text-sm leading-relaxed " +
          (outgoing
            ? "rounded-br-md"
            : "rounded-bl-md")
        }
        style={
          outgoing
            ? {
                background:
                  "linear-gradient(135deg, rgba(89,216,255,0.18) 0%, rgba(16,27,61,0.50) 100%)",
                border: "1px solid rgba(89,216,255,0.12)",
                color: "#F3F7FF",
                boxShadow: "0 0 12px rgba(89,216,255,0.06)",
              }
            : {
                background:
                  "linear-gradient(135deg, rgba(16,27,61,0.40) 0%, rgba(16,27,61,0.25) 100%)",
                border: "1px solid rgba(26,42,80,0.35)",
                color: "#F3F7FF",
              }
        }
      >
        {/* ── Attachment card ─────────────────────────────────────── */}
        {attachment ? (
          <div className="flex min-w-0 flex-col gap-2">
            {/* Encrypted file card — reads like an encrypted object */}
            <div
              className="flex flex-col gap-1.5 rounded-xl p-3"
              style={{
                background: outgoing
                  ? "rgba(5,7,19,0.25)"
                  : "rgba(10,16,36,0.5)",
                border: outgoing
                  ? "1px solid rgba(89,216,255,0.1)"
                  : "1px solid rgba(26,42,80,0.4)",
              }}
            >
              {/* File-type glyph + name */}
              <div className="flex items-center gap-2.5">
                {/* Encrypted file glyph */}
                <div
                  className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg"
                  style={{
                    background: outgoing
                      ? "rgba(89,216,255,0.12)"
                      : "rgba(139,108,255,0.10)",
                  }}
                >
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" className="opacity-70">
                    <path d="M9 1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V5z"/>
                    <path d="M9 1v4h4"/>
                    <path d="M6 8.5h4M6 11h2" strokeWidth="1" opacity="0.5"/>
                  </svg>
                </div>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-semibold text-frozen">
                    {attachment.name}
                  </div>
                  <div className="text-mono text-[10px] text-mist-dim">
                    {formatFileSize(attachment.size)}
                    {attachment.mime_type && <> · {attachment.mime_type}</>}
                  </div>
                </div>
              </div>

              {/* Encrypted state label */}
              <div
                className="flex items-center gap-1.5 self-start rounded-md px-2 py-0.5"
                style={{
                  background: "rgba(76,225,161,0.08)",
                  border: "1px solid rgba(76,225,161,0.15)",
                }}
              >
                <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="#4CE1A1" strokeWidth="1.5" strokeLinecap="round">
                  <rect x="2" y="3.5" width="6" height="5" rx="1" />
                  <path d="M5 1.5v2M3.5 6.5h3" />
                </svg>
                <span className="text-[10px] font-semibold uppercase tracking-wider text-secure-mint">
                  {i18n.t("chat.encrypted")}
                </span>
              </div>
            </div>

            {/* Download / decrypt action */}
            <a
              href="#"
              download={attachment.name}
              onClick={(e) => void onDownload(e)}
              className={
                "inline-flex w-fit items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-all " +
                (outgoing
                  ? "bg-abyss/30 text-frozen hover:bg-abyss/50"
                  : "text-frozen hover:bg-ice-border/30")
              }
              style={!outgoing ? { border: "1px solid rgba(26,42,80,0.4)" } : undefined}
            >
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                <path d="M6 1v7M3 5l3 3 3-3M1 9v1.5A.5.5 0 0 0 1.5 11h9a.5.5 0 0 0 .5-.5V9"/>
              </svg>
              {downloading ? i18n.t("chat.decrypting") : i18n.t("chat.download")}
            </a>

            {downloadError && (
              <div role="alert" className="text-xs text-destructive">{downloadError}</div>
            )}
          </div>
        ) : invalidAttachment ? (
          <div role="alert" className="text-xs text-destructive">
            {i18n.t("chat.attachmentUnavailable")}
          </div>
        ) : (
          <div className="whitespace-pre-wrap break-words">{text}</div>
        )}

        {/* ── Timestamp + delivery state ──────────────────────────── */}
        <div
          className="mt-1.5 flex items-center justify-end gap-1"
          style={{ fontSize: "10px" }}
        >
          <span className={outgoing ? "text-mist-dim" : "text-mist-dim"}>
            {formatTime(message.created_at)}
          </span>
          {outgoing && (
            <>
              <span aria-hidden="true" className={message.state === "read" ? "text-electric" : "text-mist-dim"}>
                {message.state === "sending" ? "…" : message.state === "failed" ? "✕" : "✓"}
                {message.state === "read" && "✓"}
              </span>
              <span className="message-state-text">
                {i18n.t(messageStateKeys[message.state])}
              </span>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default MessageItem;

function formatFileSize(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}
