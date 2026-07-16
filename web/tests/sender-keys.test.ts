import assert from "node:assert/strict";
import test from "node:test";
import {
  createSenderState,
  createReceiverState,
  encryptGroupMessage,
  decryptGroupMessage,
  type SenderKeyCiphertext,
} from "../src/lib/senderKeys";

const seed = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const signing = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);

test("first and sequential messages decrypt and advance the chain", async () => {
  const sender = await createSenderState("g1", 7, 11, seed, signing);
  const receiver = createReceiverState(sender.distribution);
  const first = await encryptGroupMessage(sender.state, new TextEncoder().encode("one"));
  const second = await encryptGroupMessage(first.state, new TextEncoder().encode("two"));
  assert.equal(new TextDecoder().decode(await decryptGroupMessage(receiver, first.envelope)), "one");
  assert.equal(new TextDecoder().decode(await decryptGroupMessage(receiver, second.envelope)), "two");
});

test("bounded skipped keys allow out-of-order delivery and reject replay", async () => {
  const sender = await createSenderState("g1", 7, 11, seed, signing);
  let state = sender.state;
  const messages: SenderKeyCiphertext[] = [];
  for (const text of ["zero", "one", "two"]) {
    const encrypted = await encryptGroupMessage(state, new TextEncoder().encode(text));
    state = encrypted.state; messages.push(encrypted.envelope);
  }
  const receiver = createReceiverState(sender.distribution, 8);
  assert.equal(new TextDecoder().decode(await decryptGroupMessage(receiver, messages[2]!)), "two");
  assert.equal(new TextDecoder().decode(await decryptGroupMessage(receiver, messages[0]!)), "zero");
  await assert.rejects(() => decryptGroupMessage(receiver, messages[0]!), /replay/);
});

test("tamper, wrong group, wrong epoch, and invalid signature are rejected", async () => {
  const sender = await createSenderState("g1", 7, 11, seed, signing);
  const encrypted = await encryptGroupMessage(sender.state, new TextEncoder().encode("secret"));
  for (const changed of [
    { ...encrypted.envelope, group_id: "g2" },
    { ...encrypted.envelope, epoch: 8 },
    { ...encrypted.envelope, ciphertext: flipFirstByte(encrypted.envelope.ciphertext) },
    { ...encrypted.envelope, signature: flipFirstByte(encrypted.envelope.signature) },
  ]) {
    await assert.rejects(() => decryptGroupMessage(createReceiverState(sender.distribution), changed));
  }
});

function flipFirstByte(value: string): string {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  let raw = ""; for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

test("an advanced chain key cannot derive an earlier message key", async () => {
  const sender = await createSenderState("g1", 7, 11, seed, signing);
  const first = await encryptGroupMessage(sender.state, new TextEncoder().encode("secret"));
  const lateReceiver = createReceiverState({ ...sender.distribution, chain_key: first.state.chain_key, iteration: first.state.iteration });
  await assert.rejects(() => decryptGroupMessage(lateReceiver, first.envelope), /replay|old/);
});
