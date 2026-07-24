// Traffic-analysis resistance: pad plaintext to a fixed bucket size
// before encryption, and add a small random delay before sending.
// Padding happens on the PLAINTEXT (before encrypt), so the final
// ciphertext length also lands on a bucket boundary — this hides
// message length from anyone observing encrypted traffic size
// (a network-level observer between client and server/Tor) AND
// from anyone reading the server's own stored ciphertext row sizes
// (a subpoenaed Scylla dump), not just from content inspection.
//
// Wire format: [4-byte big-endian original length][original bytes][zero padding to bucket size].

const LENGTH_PREFIX_BYTES = 4;

// Bucket sizes chosen as a geometric-ish progression: fine-grained
// for short chat messages (the common case), coarser for large
// attachments' manifest payloads. A message larger than the largest
// bucket rounds up to the next multiple of that bucket instead of
// leaking its exact size.
const LARGEST_BUCKET = 65536;
const BUCKETS = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, LARGEST_BUCKET] as const;

function pickBucketSize(totalNeeded: number): number {
  for (const bucket of BUCKETS) {
    if (totalNeeded <= bucket) return bucket;
  }
  return Math.ceil(totalNeeded / LARGEST_BUCKET) * LARGEST_BUCKET;
}

export function padPlaintext(plaintext: Uint8Array): Uint8Array {
  const totalNeeded = plaintext.length + LENGTH_PREFIX_BYTES;
  const bucketSize = pickBucketSize(totalNeeded);
  const out = new Uint8Array(bucketSize); // zero-filled by default
  new DataView(out.buffer).setUint32(0, plaintext.length, false);
  out.set(plaintext, LENGTH_PREFIX_BYTES);
  return out;
}

export function unpadPlaintext(padded: Uint8Array): Uint8Array {
  if (padded.length < LENGTH_PREFIX_BYTES) {
    throw new Error("padded message shorter than the length prefix");
  }
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const originalLength = view.getUint32(0, false);
  if (originalLength + LENGTH_PREFIX_BYTES > padded.length) {
    throw new Error("padded message length prefix exceeds buffer size");
  }
  return padded.slice(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + originalLength);
}

// ----------------------------------------------------------------------------
// Timing jitter: a small random delay before a message actually hits
// the wire, so an observer watching connection activity can't
// precisely correlate "user pressed send" with a specific packet
// timestamp. Kept short so it doesn't make the UI feel laggy.
// ----------------------------------------------------------------------------

const MIN_JITTER_MS = 20;
const MAX_JITTER_MS = 180;

export function randomSendJitterMs(): number {
  return MIN_JITTER_MS + Math.floor(Math.random() * (MAX_JITTER_MS - MIN_JITTER_MS + 1));
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
