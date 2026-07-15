// src/api/files.ts
//
// File transfer. The client never PUTs/GETs file bytes through
// the file-service. The flow is:
//
//   1. POST /api/files/upload-url       → { object_key, upload_url }
//   2. PUT  <upload_url>   (directly to MinIO)
//   3. POST /api/files/download-url     → { download_url } (later)
//
// Avatars:
//
//   POST /api/files/avatar-upload-url  → { object_key, upload_url }
//
// The server-side wrappers return object_key + url; the client
// side does the actual HTTP transfer. The file-service never
// sees the bytes.

import { fetchJSON, fetchWithAuth } from "./client";
import {
  decryptFileBlob,
  encryptFileBlob,
  type EncryptedFileManifest,
} from "../lib/fileCrypto";

export interface UploadURLRequest {
  filename: string;
  content_type: string;
  size: number;
}

export interface UploadURLResponse {
  object_key: string;
  upload_url: string;
  expires_at: string;
}

export async function getUploadURL(req: UploadURLRequest): Promise<UploadURLResponse> {
  return fetchJSON<UploadURLResponse>("/api/files/upload-url", { method: "POST", body: req });
}

export interface DownloadURLRequest {
  object_key: string;
}

export interface DownloadURLResponse {
  object_key: string;
  download_url: string;
  expires_at: string;
}

export async function getDownloadURL(objectKey: string): Promise<DownloadURLResponse> {
  return fetchJSON<DownloadURLResponse>("/api/files/download-url", {
    method: "POST",
    body: { object_key: objectKey } satisfies DownloadURLRequest,
  });
}

export async function getAvatarUploadURL(): Promise<UploadURLResponse> {
  return fetchJSON<UploadURLResponse>("/api/files/avatar-upload-url", { method: "POST" });
}

export async function grantFileAccess(objectKey: string, granteeUin: number): Promise<void> {
  await fetchWithAuth("/api/files/grants", { method: "POST", body: { object_key: objectKey, grantee_uin: granteeUin } });
}

export async function revokeFileAccess(objectKey: string, granteeUin: number): Promise<void> {
  await fetchWithAuth("/api/files/grants", { method: "DELETE", body: { object_key: objectKey, grantee_uin: granteeUin } });
}

// ----------------------------------------------------------------------------
// Direct-to-MinIO helpers. These do NOT go through the file-service;
// they go straight to the presigned URL. The server-side wrapper
// returns the URL; the client just executes the HTTP request.
//
// Note: `Content-Type` MUST match the value passed to the URL-mint
// call, otherwise MinIO's signature check will reject the PUT.
// ----------------------------------------------------------------------------
export async function putToPresignedURL(url: string, body: Blob, contentType: string): Promise<void> {
  const resp = await fetch(url, {
    method: "PUT",
    headers: { "Content-Type": contentType },
    body,
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`upload failed: ${resp.status} ${text.slice(0, 200)}`);
  }
}

export async function getFromPresignedURL(url: string): Promise<Blob> {
  const resp = await fetch(url);
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`download failed: ${resp.status} ${text.slice(0, 200)}`);
  }
  return resp.blob();
}

export interface EncryptedUploadResult {
  object_key: string;
  manifest: EncryptedFileManifest;
  expires_at: string;
}

export async function uploadEncryptedFile(file: Blob, displayName?: string): Promise<EncryptedUploadResult> {
  const encrypted = await encryptFileBlob(file, displayName);
  const upload = await getUploadURL({
    filename: "encrypted.bin",
    content_type: encrypted.encryptedBlob.type,
    size: encrypted.encryptedBlob.size,
  });
  await putToPresignedURL(upload.upload_url, encrypted.encryptedBlob, encrypted.encryptedBlob.type);
  return {
    object_key: upload.object_key,
    manifest: encrypted.manifest,
    expires_at: upload.expires_at,
  };
}

export async function downloadEncryptedFile(
  objectKey: string,
  manifest: EncryptedFileManifest,
): Promise<Blob> {
  const download = await getDownloadURL(objectKey);
  const encrypted = await getFromPresignedURL(download.download_url);
  return decryptFileBlob(encrypted, manifest);
}
