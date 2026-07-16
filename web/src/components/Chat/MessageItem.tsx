// src/components/Chat/MessageItem.tsx
//
// A single message bubble. Outgoing messages render on the
// right with an accent-tinted background; incoming on the
// left with a neutral surface. Each bubble shows:
//
//   - the decrypted plaintext (NEVER the ciphertext)
//   - a small timestamp + read-receipt tick for outgoing
//
// We deliberately render the plaintext as text. A future
// extension to markdown / links is a parse-once, not a
// security boundary.

import { useState } from "react";
import { downloadEncryptedFile } from "../../api/files";
import { assertSafeDownloadMetadata, isEncryptedFileManifest, withObjectUrl } from "../../lib/fileCrypto";
import type { Message, MessageAttachment } from "../../types/models";

interface MessageItemProps {
  message: Message;
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  // HH:MM, 24h. The exact locale formatting is a future
  // tweak; the spec only requires a visible timestamp.
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
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const outgoing = message.is_outgoing;
  // Defense in depth: even if a future bug let a server-
  // supplied plaintext through, we explicitly never render
  // the ciphertext on the client.
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
      setDownloadError("File authentication failed. The file was not opened.");
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className={`flex ${outgoing ? "justify-end" : "justify-start"}`}>
      <div
        className={
          "max-w-[75%] rounded-2xl px-3 py-2 text-sm " +
          (outgoing
            ? "rounded-br-sm bg-accent text-bg"
            : "rounded-bl-sm bg-surface-2 text-text")
        }
      >
        {attachment ? (
          <div className="flex min-w-0 flex-col gap-1">
            <div className="truncate font-medium">{attachment.name}</div>
            <div className={outgoing ? "text-xs text-bg/70" : "text-xs text-text-2"}>
              {formatFileSize(attachment.size)}
            </div>
            <a
              href="#"
              download={attachment.name}
              onClick={(e) => void onDownload(e)}
              className={
                "mt-1 inline-flex w-fit rounded border px-2 py-1 text-xs " +
                (outgoing ? "border-bg/40 text-bg" : "border-border text-text")
              }
            >
              {downloading ? "Decrypting..." : "Download"}
            </a>
            {downloadError && <div role="alert" className="text-xs text-red-400">{downloadError}</div>}
          </div>
        ) : invalidAttachment ? (
          <div role="alert">Attachment unavailable — failed security validation.</div>
        ) : (
          <div className="whitespace-pre-wrap break-words">{text}</div>
        )}
        <div
          className={
            "mt-1 flex items-center justify-end gap-1 text-[10px] " +
            (outgoing ? "text-bg/70" : "text-text-2")
          }
        >
          <span>{formatTime(message.created_at)}</span>
          {outgoing && (
            <span aria-label={`State: ${message.state}`}>
              {message.state === "sending" ? "…" : message.state === "failed" ? "✕" : "✓"}
              {message.state === "read" && "✓"}
            </span>
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
