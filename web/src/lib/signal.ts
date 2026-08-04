// src/lib/signal.ts
//
// Signal Protocol wrapper around
// @privacyresearch/libsignal-protocol-typescript (v0.0.16).
//
// This is the *only* module that imports the Signal library.
// Everything else in the app goes through this file's public
// surface: generate*, encryptMessage, decryptMessage, SignalError.
//
// Step 9 replaces the v0.94 native stub with a working browser
// implementation. The privacyresearch port is pure TypeScript:
// it runs in the browser without WASM, without a Node-Native
// .node binary, and without polyfills for node:buffer/node:crypto.
//
// Public surface (matches the spec):
//
//   generateIdentityKeyPair()      — fresh Curve25519 identity
//   generateRegistrationId()       — fresh 14-bit id
//   generatePreKeyBundle(...)      — bundle of prekeys to upload
//   encryptMessage(uin, plaintext) — X3DH + double-ratchet seal
//   decryptMessage(uin, ct, type)  — open a sealed message
//
// Privacy contract:
//   * The private key NEVER enters Zustand or localStorage.
//   * Session records are persisted to IndexedDB only.

import type {
  DeviceType,
  KeyPairType,
} from "@privacyresearch/libsignal-protocol-typescript";
import {
  fetchBundle,
  type OneTimePreKeyUpload,
  type RemotePreKeyBundle,
} from "../api/keys";
export { computeSafetyNumber, type SafetyIdentity } from "./safetyFingerprint";
import {
  getSignalStore,
  loadIdentity as idbLoadIdentity,
  saveIdentity,
  type StoredIdentity,
  type CryptoNamespace,
} from "./indexeddb";
import { assessPeerIdentity, isPeerSendAllowed } from "./identityTrust";
import { assertInboundIdentityTrusted } from "./indexeddb";
import { PreKeyWhisperMessage } from "@privacyresearch/libsignal-protocol-protobuf-ts";
import { padPlaintext, unpadPlaintext } from "./messagePadding";

// ============================================================================
// Library bootstrap.
//
// The privacyresearch port is pure TypeScript but it still needs
// WebCrypto + the Curve25519 implementation wired in before any
// KeyHelper call. We do this once, lazily, on first use.
//
// We also pull the local identity at the same time so subsequent
// encrypt/decrypt calls don't have to await it.
// ============================================================================

interface BootState {
  // boot() returns null for identity if the user hasn't
  // registered yet; we re-read on every encrypt/decrypt
  // call so that a fresh IDB write (e.g. after register
  // completes) is visible immediately. bootPromise is
  // cached for the curve + WebCrypto wiring only.
  curveReady: true;
  runtime: SignalRuntime;
  curve: InstanceType<SignalRuntime["AsyncCurve25519Wrapper"]>;
}

interface SignalRuntime {
  EncryptionResultMessageType: typeof import("@privacyresearch/libsignal-protocol-typescript").EncryptionResultMessageType;
  KeyHelper: typeof import("@privacyresearch/libsignal-protocol-typescript").KeyHelper;
  SessionBuilder: typeof import("@privacyresearch/libsignal-protocol-typescript").SessionBuilder;
  SessionCipher: typeof import("@privacyresearch/libsignal-protocol-typescript").SessionCipher;
  SignalProtocolAddress: typeof import("@privacyresearch/libsignal-protocol-typescript").SignalProtocolAddress;
  setCurve: typeof import("@privacyresearch/libsignal-protocol-typescript").setCurve;
  setWebCrypto: typeof import("@privacyresearch/libsignal-protocol-typescript").setWebCrypto;
  AsyncCurve25519Wrapper: typeof import("./vendor/curve25519").AsyncCurve25519Wrapper;
}

let bootPromise: Promise<BootState> | null = null;
let runtimePromise: Promise<SignalRuntime> | null = null;

export function resetSignalRuntime(): void {
  bootPromise = null;
  runtimePromise = null;
}

async function loadSignalRuntime(): Promise<SignalRuntime> {
  if (!runtimePromise) {
    runtimePromise = (async () => {
      const [signalLib, curveLib] = await Promise.all([
        import("@privacyresearch/libsignal-protocol-typescript"),
        import("./vendor/curve25519"),
      ]);
      return {
        EncryptionResultMessageType: signalLib.EncryptionResultMessageType,
        KeyHelper: signalLib.KeyHelper,
        SessionBuilder: signalLib.SessionBuilder,
        SessionCipher: signalLib.SessionCipher,
        SignalProtocolAddress: signalLib.SignalProtocolAddress,
        setCurve: signalLib.setCurve,
        setWebCrypto: signalLib.setWebCrypto,
        AsyncCurve25519Wrapper: curveLib.AsyncCurve25519Wrapper,
      };
    })();
  }
  return runtimePromise;
}

async function boot(): Promise<BootState> {
  const runtime = await loadSignalRuntime();
  // 1. Wire the async curve. We vendor the upstream asm.js
  //    wrapper locally so Vite does not ship a bogus 8-byte
  //    curveasm.wasm placeholder into production.
  const asyncCurve = new runtime.AsyncCurve25519Wrapper();
  await asyncCurve.curvePromise;
  runtime.setCurve(asyncCurve);
  // 2. Wire WebCrypto. The library's Crypto class reads
  //    from the global this.crypto.
  runtime.setWebCrypto(globalThis.crypto);
  return { curveReady: true, runtime, curve: asyncCurve };
}

async function ensureBoot(): Promise<BootState> {
  if (!bootPromise) bootPromise = boot();
  return bootPromise;
}

export async function preloadSignal(): Promise<void> {
  await ensureBoot();
}

// Read the local identity fresh on every encrypt/decrypt.
// The boot is cached but the identity is short-lived — we
// want the latest write to be visible immediately (e.g. after
// register() lands, or after 4403 wipe + re-register).
async function getLocalIdentity(namespace:CryptoNamespace): Promise<StoredIdentity | null> {
  await ensureBoot();
  return idbLoadIdentity(namespace);
}

// ============================================================================
// SignalError. Thrown on any cryptographic failure. The chat UI
// shows the message to the user; the message is marked "failed".
// ============================================================================

export class SignalError extends Error {
  public override readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "SignalError";
    this.cause = cause;
  }
}

// ============================================================================
// Re-exports — shape the rest of the app uses.
// ============================================================================

export type PublicKey = Uint8Array;
export type PrivateKey = Uint8Array;
export interface IdentityKeyPair {
  publicKey: PublicKey;
  privateKey: PrivateKey;
}

const SIGNAL_PUBLIC_KEY_PREFIX = 0x05;
const RAW_X25519_PUBLIC_KEY_LENGTH = 32;
const SIGNAL_PUBLIC_KEY_LENGTH = RAW_X25519_PUBLIC_KEY_LENGTH + 1;

// ============================================================================
// Base64url codec. We use this for the wire format on
// /api/keys/bundle and the message payload.
// ============================================================================

function arrayBufferToB64Url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64UrlToArrayBuffer(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out.buffer;
}

function uint8ToArrayBuffer(u: Uint8Array): ArrayBuffer {
  // Slice to a fresh ArrayBuffer (not a view into a larger buffer).
  const out = new Uint8Array(u.length);
  out.set(u);
  return out.buffer;
}

function toRawX25519PublicKeyBytes(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length === RAW_X25519_PUBLIC_KEY_LENGTH) {
    return new Uint8Array(publicKey);
  }
  if (publicKey.length === SIGNAL_PUBLIC_KEY_LENGTH && publicKey[0] === SIGNAL_PUBLIC_KEY_PREFIX) {
    return publicKey.slice(1);
  }
  throw new SignalError(
    `invalid identity public key length: expected ${RAW_X25519_PUBLIC_KEY_LENGTH} or ${SIGNAL_PUBLIC_KEY_LENGTH} bytes, got ${publicKey.length}`,
  );
}

function toSignalPublicKeyBuffer(publicKey: ArrayBuffer): ArrayBuffer {
  const bytes = new Uint8Array(publicKey);
  if (bytes.length === SIGNAL_PUBLIC_KEY_LENGTH) {
    return uint8ToArrayBuffer(bytes);
  }
  if (bytes.length !== RAW_X25519_PUBLIC_KEY_LENGTH) {
    throw new SignalError(
      `invalid stored identity public key length: expected ${RAW_X25519_PUBLIC_KEY_LENGTH} bytes, got ${bytes.length}`,
    );
  }
  const prefixed = new Uint8Array(SIGNAL_PUBLIC_KEY_LENGTH);
  prefixed[0] = SIGNAL_PUBLIC_KEY_PREFIX;
  prefixed.set(bytes, 1);
  return prefixed.buffer;
}

export function restoreSignalPublicKey(publicKey: string): ArrayBuffer {
  return toSignalPublicKeyBuffer(b64UrlToArrayBuffer(publicKey));
}

export function encodeIdentityKeyForWire(publicKey: Uint8Array): string {
  return arrayBufferToB64Url(uint8ToArrayBuffer(toRawX25519PublicKeyBytes(publicKey)));
}

export function encodePreKeyPublicKeyForWire(publicKey: Uint8Array): string {
  return arrayBufferToB64Url(uint8ToArrayBuffer(toRawX25519PublicKeyBytes(publicKey)));
}

export function assertValidIdentityKey(identityKey: string): void {
  const decoded = b64UrlToArrayBuffer(identityKey);
  if (decoded.byteLength !== RAW_X25519_PUBLIC_KEY_LENGTH) {
    throw new SignalError("identity_key must be a base64url-encoded 32-byte X25519 public key");
  }
}

export function restoreSignalIdentityPublicKey(publicKey: string): ArrayBuffer {
  return restoreSignalPublicKey(publicKey);
}

// The privacyresearch lib's SessionCipher.encrypt returns
// the body as a "binary string" — one char per byte, with
// the char's code point equal to the byte value. (This is
// the libsignal-protocol-javascript convention; modern
// libsignal-client returns Uint8Array.) For our wire format
// we need base64url, so we round-trip through bytes.
function binaryStringToArrayBuffer(s: string): ArrayBuffer {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out.buffer;
}

// ============================================================================
// Identity generation.
// ============================================================================

export async function generateIdentityKeyPair(): Promise<IdentityKeyPair> {
  const { runtime } = await ensureBoot();
  const kp: KeyPairType = await runtime.KeyHelper.generateIdentityKeyPair();
  return {
    // Keep the Signal-format 33-byte public key in memory.
    // libsignal expects the 0x05 prefix for identity operations.
    publicKey: new Uint8Array(kp.pubKey),
    privateKey: new Uint8Array(kp.privKey),
  };
}

export async function deriveIdentityPublicKey(privateKey: string): Promise<string> {
  const { curve } = await ensureBoot();
  const pair = await curve.keyPair(b64UrlToArrayBuffer(privateKey));
  return encodeIdentityKeyForWire(new Uint8Array(pair.pubKey));
}

export function generateRegistrationId(): number {
  const registrationId = new Uint16Array(1);
  globalThis.crypto.getRandomValues(registrationId);
  return registrationId[0]! & 0x3fff;
}

// ============================================================================
// PreKey bundle generation.
//
// Builds the full upload payload (identity + signed prekey + 20
// one-time prekeys) and persists the local prekeys to IndexedDB
// so we can find them when other people initiate a session with
// us.
//
// Why we save signed prekey + one-time prekeys: when Bob sends
// Alice a PreKeyWhisperMessage, Alice's prekey gets consumed on
// her side. The remote side (Bob) needs to look up his own
// prekey by id to decrypt — that's `loadPreKey` on his storage.
// ============================================================================

export interface PreKeyBundleUpload {
  identity_key: string;
  signed_pre_key: { id: number; public_key: string; signature: string };
  one_time_pre_keys: { id: number; public_key: string }[];
  registration_id: number;
}

export async function generatePreKeyBundle(
  identity: IdentityKeyPair,
  signedPreKeyId: number,
  oneTimePreKeyCount: number,
  registrationId: number,
  namespace: CryptoNamespace,
  signal?: AbortSignal,
): Promise<PreKeyBundleUpload> {
  throwIfAborted(signal);
  const { runtime } = await ensureBoot();
  throwIfAborted(signal);
  const store = getSignalStore(namespace);

  // The KeyHelper API takes a KeyPairType, not our wrapped
  // IdentityKeyPair. Convert the Buffer-style values.
  const identityForHelper: KeyPairType = {
    pubKey: uint8ToArrayBuffer(identity.publicKey),
    privKey: uint8ToArrayBuffer(identity.privateKey),
  };

  // 1. Signed prekey (long-lived, signed by identity privkey).
  const signed = await runtime.KeyHelper.generateSignedPreKey(identityForHelper, signedPreKeyId);
  throwIfAborted(signal);
  await store.storeSignedPreKey(signed.keyId, signed.keyPair);
  throwIfAborted(signal);

  // 2. One-time prekeys. Each is independent; we save each to
  //    the prekey store keyed by its id. The id range starts
  //    after the signed prekey id to avoid collisions.
  const oneTime: { id: number; public_key: string }[] = [];
  for (let i = 0; i < oneTimePreKeyCount; i++) {
    const id = signedPreKeyId + 1 + i;
    const otp = await runtime.KeyHelper.generatePreKey(id);
    throwIfAborted(signal);
    await store.storePreKey(otp.keyId, otp.keyPair);
    throwIfAborted(signal);
    oneTime.push({
      id: otp.keyId,
      public_key: encodePreKeyPublicKeyForWire(new Uint8Array(otp.keyPair.pubKey)),
    });
  }

  return {
    identity_key: encodeIdentityKeyForWire(identity.publicKey),
    signed_pre_key: {
      id: signed.keyId,
      public_key: encodePreKeyPublicKeyForWire(new Uint8Array(signed.keyPair.pubKey)),
      signature: arrayBufferToB64Url(signed.signature),
    },
    one_time_pre_keys: oneTime,
    registration_id: registrationId,
  };
}

export async function generateOneTimePreKeys(startId: number, count: number, namespace: CryptoNamespace, signal?: AbortSignal): Promise<OneTimePreKeyUpload[]> {
  throwIfAborted(signal);
  const { runtime } = await ensureBoot();
  throwIfAborted(signal);
  const store = getSignalStore(namespace);
  const prekeys: OneTimePreKeyUpload[] = [];

  for (let i = 0; i < count; i++) {
    const otp = await runtime.KeyHelper.generatePreKey(startId + i);
    throwIfAborted(signal);
    await store.storePreKey(otp.keyId, otp.keyPair);
    throwIfAborted(signal);
    prekeys.push({
      id: otp.keyId,
      public_key: encodePreKeyPublicKeyForWire(new Uint8Array(otp.keyPair.pubKey)),
    });
  }

  return prekeys;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  const error = new Error("The operation was aborted.");
  error.name = "AbortError";
  throw error;
}

// ============================================================================
// saveOwnIdentity — register-time helper.
//
// Persists the long-lived identity to IndexedDB. The PRIVATE
// half of the key lives here, in IndexedDB only. Zustand
// stores and localStorage are forbidden.
// ============================================================================

export async function saveOwnIdentity(
  id: IdentityKeyPair,
  registrationId: number,
  namespace: CryptoNamespace,
): Promise<void> {
  const stored: StoredIdentity = {
    publicKey: encodeIdentityKeyForWire(id.publicKey),
    privateKey: arrayBufferToB64Url(uint8ToArrayBuffer(id.privateKey)),
    registrationId,
  };
  await saveIdentity(namespace, stored);
}

export function restoreOwnIdentity(stored: StoredIdentity): IdentityKeyPair & { registrationId: number } {
  return {
    publicKey: new Uint8Array(restoreSignalIdentityPublicKey(stored.publicKey)),
    privateKey: new Uint8Array(b64UrlToArrayBuffer(stored.privateKey)),
    registrationId: stored.registrationId,
  };
}

// ============================================================================
// SealedMessage — the result type encryptMessage returns.
// ============================================================================

export interface SealedMessage {
  ciphertext: string; // base64url
  msgType: "prekey_message" | "signal_message";
}

// ============================================================================
// encryptMessage.
//
// 1. Look up a session for the recipient. If none exists, fetch
//    a PreKey bundle from the server and run X3DH to build one.
// 2. Run a Double-Ratchet step. The result is either a
//    PreKeyWhisperMessage (first message) or a WhisperMessage
//    (subsequent). The "type" field on the wire tells the
//    receiver which path to take.
// ============================================================================

export async function encryptMessage(
  recipientUin: number,
  plaintext: Uint8Array,
  operationNamespace:CryptoNamespace,
): Promise<SealedMessage> {
  const { runtime } = await ensureBoot();
  const identity = await getLocalIdentity(operationNamespace);
  if (!identity) throw new SignalError("no local identity — register first");
  if (!(await isPeerSendAllowed(recipientUin,operationNamespace))) {
    throw new SignalError("peer identity changed; sending is blocked until explicitly accepted or verified");
  }

  const store = getSignalStore(operationNamespace);
  const remoteAddress = new runtime.SignalProtocolAddress(String(recipientUin), 1);
  const encoded = remoteAddress.toString();

  try {
    // 1. Session bootstrap. If we have a stored session, the
    //    encrypt will run straight into the ratchet. If not,
    //    we need a fresh bundle from the server.
    const existing = await store.loadSession(encoded);
    if (!existing) {
      const remote = await fetchBundle(recipientUin);
      await seedSessionFromBundle(remote, remoteAddress, store);
    }

    // 2. Encrypt. The cipher writes the updated session back
    //    into the store via storeSession(), which our
    //    IndexedDB-backed StorageType handles. Plaintext is
    //    padded to a fixed bucket size first (see
    //    messagePadding.ts) so the resulting ciphertext length
    //    doesn't reveal the original message length — to a
    //    network observer watching encrypted traffic sizes, or
    //    to anyone reading the server's own stored ciphertext
    //    row size.
    const cipher = new runtime.SessionCipher(store, remoteAddress);
    const plainBuffer = uint8ToArrayBuffer(padPlaintext(plaintext));
    const result = await cipher.encrypt(plainBuffer);
    if (!result.body) {
      throw new SignalError("cipher returned empty body");
    }
    // 3. Pending-prekey cleanup. The privacyresearch port
    //    only deletes `session.pendingPreKey` on the
    //    DECRYPT side; the modern libsignal-client clears
    //    it on both sides. Without this patch, every
    //    outgoing message is wrapped in a PreKeyWhisperMessage
    //    even after the receiver has already consumed the
    //    prekey. We mutate the persisted session record
    //    directly to drop the flag.
    await clearPendingPreKey(encoded, store);
    const msgType: "prekey_message" | "signal_message" =
      result.type === runtime.EncryptionResultMessageType.PreKeyWhisperMessage
        ? "prekey_message"
        : "signal_message";
    return {
      ciphertext: arrayBufferToB64Url(binaryStringToArrayBuffer(result.body)),
      msgType,
    };
  } catch (e) {
    if (e instanceof SignalError) throw e;
    throw new SignalError(`encrypt failed for uin=${recipientUin}`, e);
  }
}

export async function verifySignedPreKeyBundle(remote: Pick<RemotePreKeyBundle, "identity_key" | "signed_pre_key">): Promise<true> {
  try {
    assertCanonicalB64Url(remote.identity_key, 32);
    assertCanonicalB64Url(remote.signed_pre_key.public_key, 32);
    assertCanonicalB64Url(remote.signed_pre_key.signature, 64);
  } catch (cause) { throw new SignalError("signed prekey verification failed", cause); }
  const { curve } = await ensureBoot();
  let valid = false;
  try {
    // curve25519-typescript's low-level `verify` mirrors the C return code:
    // false means valid, true means invalid. Keep the inversion explicit.
    valid = !(await curve.verify(
      // The low-level verifier consumes the raw 32-byte identity public key;
      // the signed message remains Signal's 33-byte prefixed prekey.
      b64UrlToArrayBuffer(remote.identity_key),
      restoreSignalPublicKey(remote.signed_pre_key.public_key),
      b64UrlToArrayBuffer(remote.signed_pre_key.signature),
    ));
  } catch (cause) {
    throw new SignalError("signed prekey verification failed", cause);
  }
  if (!valid) throw new SignalError("signed prekey verification failed");
  return true;
}

// ============================================================================
// decryptMessage.
//
// Inverse of encryptMessage. The msgType hint tells the cipher
// which path to take: PreKeyWhisperMessage seeds a new session,
// WhisperMessage continues an existing ratchet.
// ============================================================================

export async function decryptMessage(
  senderUin: number,
  ciphertextB64: string,
  msgType: "prekey_message" | "signal_message",
  operationNamespace:CryptoNamespace,
): Promise<Uint8Array> {
  const { runtime } = await ensureBoot();
  const identity = await getLocalIdentity(operationNamespace);
  if (!identity) throw new SignalError("no local identity — register first");

  const store = getSignalStore(operationNamespace);
  const remoteAddress = new runtime.SignalProtocolAddress(String(senderUin), 1);
  const cipher = new runtime.SessionCipher(store, remoteAddress);
  const bytes = b64UrlToArrayBuffer(ciphertextB64);

  try {
    let plain: ArrayBuffer;
    if (msgType === "prekey_message") {
      const wire = new Uint8Array(bytes);
      if (wire.length < 2 || wire[0] !== 0x33) throw new SignalError("invalid inbound prekey message");
      const proto = PreKeyWhisperMessage.decode(wire.slice(1));
      const inboundIdentity = uint8ToArrayBuffer(proto.identityKey);
      if (proto.identityKey.length !== SIGNAL_PUBLIC_KEY_LENGTH || proto.identityKey[0] !== SIGNAL_PUBLIC_KEY_PREFIX) {
        throw new SignalError("invalid inbound identity key");
      }
      await assertInboundIdentityTrusted(senderUin, inboundIdentity,operationNamespace);
      // First message from a peer. The SessionBuilder runs
      // X3DH against our stored prekey/signed-prekey and
      // sets up the ratchet state.
      plain = await cipher.decryptPreKeyWhisperMessage(bytes);
    } else {
      // Subsequent message. Pure ratchet step.
      plain = await cipher.decryptWhisperMessage(bytes);
    }
    return unpadPlaintext(new Uint8Array(plain));
  } catch (e) {
    if (e instanceof SignalError) throw e;
    if ((e as Error).message === "peer identity changed") throw new SignalError("peer identity changed; decrypt blocked", e);
    throw new SignalError(`decrypt failed from uin=${senderUin}`, e);
  }
}

function assertCanonicalB64Url(value: string, expectedBytes: number): void {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("non-canonical base64url");
  const decoded = b64UrlToArrayBuffer(value);
  if (decoded.byteLength !== expectedBytes || arrayBufferToB64Url(decoded) !== value) throw new Error("invalid base64url length or encoding");
}

// ============================================================================
// seedSessionFromBundle — X3DH initiation.
//
// Translates the server's bundle JSON shape into the
// DeviceType the SessionBuilder expects, then calls
// processPreKey to derive the initial ratchet state.
// ============================================================================

async function seedSessionFromBundle(
  remote: RemotePreKeyBundle,
  remoteAddress: InstanceType<SignalRuntime["SignalProtocolAddress"]>,
  store: ReturnType<typeof getSignalStore>,
): Promise<void> {
  const { runtime } = await ensureBoot();
  await verifySignedPreKeyBundle(remote);
  const peerUin = Number(remoteAddress.getName());
  const trust = await assessPeerIdentity(peerUin, remote.identity_key,store.namespace);
  if (!trust.sendAllowed) {
    throw new SignalError("peer identity changed; sending is blocked until explicitly accepted or verified");
  }
  const device: DeviceType = {
    identityKey: restoreSignalIdentityPublicKey(remote.identity_key),
    signedPreKey: {
      keyId: remote.signed_pre_key.id,
      publicKey: restoreSignalPublicKey(remote.signed_pre_key.public_key),
      signature: b64UrlToArrayBuffer(remote.signed_pre_key.signature),
    },
    preKey: remote.pre_key
      ? {
          keyId: remote.pre_key.id,
          publicKey: restoreSignalPublicKey(remote.pre_key.public_key),
        }
      : undefined,
    registrationId: remote.registration_id,
  };

  const builder = new runtime.SessionBuilder(store, remoteAddress);
  await builder.processPreKey(device);
}

// ============================================================================
// Re-exports for downstream callers.
//
// The SignalError type is imported by MessageInput to distinguish
// crypto failures from generic JS errors. The Direction enum
// is not used externally; the privacyresearch library needs it
// for the StorageType interface but the IndexedDB store handles
// that internally.
// ============================================================================


// ----------------------------------------------------------------------------
// clearPendingPreKey — work around a quirk in
// @privacyresearch/libsignal-protocol-typescript.
//
// The port deletes `session.pendingPreKey` only inside
// `decryptPreKeyWhisperMessage`. On the encrypt side the flag
// sticks across encrypts, so every subsequent outgoing
// message comes out as a PreKeyWhisperMessage even though
// the receiver has long since consumed the prekey. The
// modern @signalapp/libsignal-client v0.94 clears it on
// both sides. Until we upgrade, we patch the persisted
// session record here.
//
// The session record is JSON in the form
//   { version, sessions: { "<base64 baseKey>": <SessionType> }, ... }
// where the open session is the one with `indexInfo.closed === -1`.
// ----------------------------------------------------------------------------
async function clearPendingPreKey(
  encodedAddress: string,
  store: ReturnType<typeof getSignalStore>,
): Promise<void> {
  const raw = await store.loadSession(encodedAddress);
  if (!raw) return;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return;
  }
  if (!parsed || typeof parsed !== "object") return;
  const rec = parsed as { sessions?: Record<string, unknown> };
  if (!rec.sessions) return;
  let mutated = false;
  for (const k of Object.keys(rec.sessions)) {
    const s = rec.sessions[k] as { indexInfo?: { closed?: number }; pendingPreKey?: unknown } | undefined;
    if (s && s.pendingPreKey !== undefined) {
      delete s.pendingPreKey;
      mutated = true;
    }
  }
  if (mutated) {
    await store.storeSession(encodedAddress, JSON.stringify(rec));
  }
}
