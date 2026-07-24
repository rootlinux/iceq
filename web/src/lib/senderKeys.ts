import { AsyncCurve25519Wrapper } from "./vendor/curve25519";
import { padPlaintext, unpadPlaintext } from "./messagePadding";

export const SENDER_KEY_VERSION = 1 as const;
const INFO = new TextEncoder().encode("iceq.sender-keys.v1");

export interface SenderKeyDistribution {
  version: 1; distribution_id: string; group_id: string; epoch: number; sender_uin: number;
  chain_key: string; iteration: number; signing_public_key: string;
}
export interface SenderKeyCiphertext {
  version: 1; group_id: string; epoch: number; sender_uin: number; distribution_id: string;
  iteration: number; ciphertext: string; signature: string;
}
export interface SenderState extends SenderKeyDistribution { signing_private_key: string }
export interface ReceiverState extends SenderKeyDistribution {
  skipped: Record<string, string>; seen: Record<string, true>; max_skip: number;
}

const curve = new AsyncCurve25519Wrapper();
const enc = new TextEncoder();

export async function createSenderState(groupId: string, epoch: number, senderUin: number, chainSeed?: Uint8Array, signingPrivate?: Uint8Array): Promise<{ state: SenderState; distribution: SenderKeyDistribution }> {
  assertContext(groupId, epoch, senderUin);
  const chain = chainSeed ? new Uint8Array(chainSeed) : crypto.getRandomValues(new Uint8Array(32));
  const priv = signingPrivate ? new Uint8Array(signingPrivate) : crypto.getRandomValues(new Uint8Array(32));
  if (chain.length !== 32 || priv.length !== 32) throw new Error("sender key material must be 32 bytes");
  const pair = await curve.keyPair(toBuffer(priv));
  const publicBytes=new Uint8Array(pair.pubKey);const privateBytes=new Uint8Array(pair.privKey);
  const distribution: SenderKeyDistribution = {
    version: 1, distribution_id: randomId(), group_id: groupId, epoch, sender_uin: senderUin,
    chain_key: b64(chain), iteration: 0, signing_public_key: b64(publicBytes),
  };
  const encodedPrivate=b64(privateBytes);chain.fill(0);priv.fill(0);privateBytes.fill(0);
  return { state: { ...distribution, signing_private_key: encodedPrivate }, distribution };
}

export function createReceiverState(distribution: SenderKeyDistribution, maxSkip = 128): ReceiverState {
  validateDistribution(distribution);
  if (!Number.isSafeInteger(maxSkip) || maxSkip < 1 || maxSkip > 2048) throw new Error("invalid skipped-key window");
  return { ...structuredClone(distribution), skipped: {}, seen: {}, max_skip: maxSkip };
}

export async function encryptGroupMessage(state: SenderState, plaintext: Uint8Array): Promise<{ state: SenderState; envelope: SenderKeyCiphertext }> {
  validateSender(state);
  const current = unb64(state.chain_key, 32);
  const messageKey = await derive(current, "message");
  const next = await derive(current, "chain");
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const header = headerBytes(state, state.iteration);
  const aes = await crypto.subtle.importKey("raw", toBuffer(messageKey), "AES-GCM", false, ["encrypt"]);
  // Pad to a fixed bucket before sealing (see messagePadding.ts) so
  // the ciphertext length doesn't reveal the original message length.
  const padded = padPlaintext(plaintext);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: toBuffer(nonce), additionalData: toBuffer(header) }, aes, toBuffer(padded)));
  const combined = new Uint8Array(nonce.length + sealed.length); combined.set(nonce); combined.set(sealed, nonce.length);
  const unsigned: Omit<SenderKeyCiphertext, "signature"> = {
    version: 1, group_id: state.group_id, epoch: state.epoch, sender_uin: state.sender_uin,
    distribution_id: state.distribution_id, iteration: state.iteration, ciphertext: b64(combined),
  };
  const signingPrivate=unb64(state.signing_private_key,32);const signingInput=signingBytes(unsigned);
  const signature = new Uint8Array(await curve.sign(toBuffer(signingPrivate),toBuffer(signingInput)));
  const nextEncoded=b64(next);const signatureEncoded=b64(signature);current.fill(0);messageKey.fill(0);next.fill(0);nonce.fill(0);sealed.fill(0);combined.fill(0);header.fill(0);signingPrivate.fill(0);signingInput.fill(0);signature.fill(0);
  return { state: { ...state, chain_key: nextEncoded, iteration: state.iteration + 1 }, envelope: { ...unsigned, signature: signatureEncoded } };
}

export async function decryptGroupMessage(state: ReceiverState, envelope: SenderKeyCiphertext): Promise<Uint8Array> {
  validateCiphertext(envelope);
  if (envelope.group_id !== state.group_id || envelope.epoch !== state.epoch || envelope.sender_uin !== state.sender_uin || envelope.distribution_id !== state.distribution_id) throw new Error("sender-key context mismatch");
  if (state.seen[String(envelope.iteration)]) throw new Error("sender-key replay rejected");
  const unsigned = { ...envelope } as Partial<SenderKeyCiphertext>; delete unsigned.signature;
  const invalid = await curve.verify(toBuffer(unb64(state.signing_public_key, 32)), toBuffer(signingBytes(unsigned as Omit<SenderKeyCiphertext, "signature">)), toBuffer(unb64(envelope.signature, 64)));
  if (invalid) throw new Error("sender-key signature invalid");

  let messageKey: Uint8Array;
  if (envelope.iteration < state.iteration) {
    const cached = state.skipped[String(envelope.iteration)];
    if (!cached) throw new Error("sender-key old message rejected");
    messageKey = unb64(cached, 32); delete state.skipped[String(envelope.iteration)];
  } else {
    if (envelope.iteration - state.iteration > state.max_skip) throw new Error("sender-key skipped window exceeded");
    let chain = unb64(state.chain_key, 32);
    while (state.iteration < envelope.iteration) {
      const skipped = await derive(chain, "message"); state.skipped[String(state.iteration)] = b64(skipped);skipped.fill(0);
      const next = await derive(chain, "chain"); chain.fill(0); chain = next; state.iteration++;
    }
    messageKey = await derive(chain, "message");
    const next = await derive(chain, "chain"); chain.fill(0); state.chain_key = b64(next);next.fill(0); state.iteration++;
  }
  const combined = unb64(envelope.ciphertext); if (combined.length < 29) throw new Error("sender-key ciphertext invalid");
  const nonce=combined.slice(0,12);const body=combined.slice(12);
  const aes = await crypto.subtle.importKey("raw", toBuffer(messageKey), "AES-GCM", false, ["decrypt"]);
  const header=headerBytes(state,envelope.iteration);
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: toBuffer(nonce), additionalData: toBuffer(header) }, aes, toBuffer(body));
    state.seen[String(envelope.iteration)] = true;
    for(const key of Object.keys(state.seen)) if(Number(key)<state.iteration-state.max_skip) delete state.seen[key];
    return unpadPlaintext(new Uint8Array(plain));
  } catch { throw new Error("sender-key authentication failed"); }
  finally{messageKey.fill(0);combined.fill(0);nonce.fill(0);body.fill(0);header.fill(0);}
}

async function derive(chain: Uint8Array, label: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", toBuffer(chain), "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: toBuffer(new Uint8Array(32)), info: toBuffer(concat(INFO, enc.encode(label))) }, key, 256));
}
function headerBytes(v: Pick<SenderKeyDistribution, "version"|"group_id"|"epoch"|"sender_uin"|"distribution_id">, iteration: number): Uint8Array { return enc.encode(JSON.stringify([v.version,v.group_id,v.epoch,v.sender_uin,v.distribution_id,iteration])); }
function signingBytes(v: Omit<SenderKeyCiphertext,"signature">): Uint8Array { return concat(headerBytes(v,v.iteration), enc.encode("|"+v.ciphertext)); }
function concat(a: Uint8Array,b: Uint8Array): Uint8Array { const o=new Uint8Array(a.length+b.length);o.set(a);o.set(b,a.length);return o; }
function assertContext(g:string,e:number,u:number):void { if(!g||!Number.isSafeInteger(e)||e<1||!Number.isSafeInteger(u)||u<1) throw new Error("invalid sender-key context"); }
function validateDistribution(v:SenderKeyDistribution):void { assertContext(v.group_id,v.epoch,v.sender_uin);if(v.version!==1||!v.distribution_id)throw new Error("invalid sender-key distribution");unb64(v.chain_key,32);unb64(v.signing_public_key,32); }
function validateSender(v:SenderState):void { validateDistribution(v);unb64(v.signing_private_key,32); }
function validateCiphertext(v:SenderKeyCiphertext):void { assertContext(v.group_id,v.epoch,v.sender_uin);if(v.version!==1||!v.distribution_id||!Number.isSafeInteger(v.iteration)||v.iteration<0)throw new Error("invalid sender-key ciphertext");unb64(v.signature,64);unb64(v.ciphertext); }
function b64(v:Uint8Array):string { let s="";for(const x of v)s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); }
function unb64(s:string,len?:number):Uint8Array { if(!/^[A-Za-z0-9_-]+$/.test(s))throw new Error("invalid base64url");const p="=".repeat((4-s.length%4)%4);const raw=atob(s.replace(/-/g,"+").replace(/_/g,"/")+p);const out=Uint8Array.from(raw,c=>c.charCodeAt(0));if(len!==undefined&&out.length!==len)throw new Error("invalid key length");return out; }
function toBuffer(v:Uint8Array):ArrayBuffer { return v.buffer.slice(v.byteOffset,v.byteOffset+v.byteLength) as ArrayBuffer; }
function randomId():string { return typeof crypto.randomUUID === "function" ? crypto.randomUUID() : b64(crypto.getRandomValues(new Uint8Array(16))); }
