import test from "node:test";
import assert from "node:assert/strict";

import { padPlaintext, unpadPlaintext, randomSendJitterMs } from "../src/lib/messagePadding.js";

function bytesOf(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

test("padPlaintext round-trips a short message", () => {
  const original = bytesOf("hi");
  const padded = padPlaintext(original);
  const unpadded = unpadPlaintext(padded);
  assert.deepEqual(unpadded, original);
});

test("padPlaintext round-trips an empty message", () => {
  const original = new Uint8Array(0);
  const padded = padPlaintext(original);
  const unpadded = unpadPlaintext(padded);
  assert.equal(unpadded.length, 0);
});

test("padPlaintext round-trips a message near a bucket boundary", () => {
  const original = new Uint8Array(60); // 60 + 4-byte prefix = 64, exactly the first bucket
  original.fill(7);
  const padded = padPlaintext(original);
  assert.equal(padded.length, 64);
  const unpadded = unpadPlaintext(padded);
  assert.deepEqual(unpadded, original);
});

test("padPlaintext round-trips a message larger than the largest bucket", () => {
  const original = new Uint8Array(200_000);
  for (let i = 0; i < original.length; i++) original[i] = i % 256;
  const padded = padPlaintext(original);
  assert.equal(padded.length % 65536, 0, "large messages round up to a multiple of the largest bucket");
  const unpadded = unpadPlaintext(padded);
  assert.deepEqual(unpadded, original);
});

test("padPlaintext hides the exact length within a bucket: two different short messages produce the same padded size", () => {
  const short = padPlaintext(bytesOf("a"));
  const longer = padPlaintext(bytesOf("a much longer message than the previous one, but still short"));
  assert.equal(short.length, longer.length, "both fall in the same 64-byte bucket");
});

test("unpadPlaintext rejects a buffer shorter than the length prefix", () => {
  assert.throws(() => unpadPlaintext(new Uint8Array(2)));
});

test("unpadPlaintext rejects a corrupted length prefix pointing past the buffer", () => {
  const padded = padPlaintext(bytesOf("hello"));
  const view = new DataView(padded.buffer);
  view.setUint32(0, 999_999, false); // claim a length far larger than the buffer
  assert.throws(() => unpadPlaintext(padded));
});

test("randomSendJitterMs stays within the documented bounds", () => {
  for (let i = 0; i < 200; i++) {
    const ms = randomSendJitterMs();
    assert.ok(ms >= 20 && ms <= 180, `jitter ${ms} out of bounds`);
  }
});
