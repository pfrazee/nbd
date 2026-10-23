// Record encryption (core.md#content-encryption): Format 1 envelope,
// XChaCha20-Poly1305, the [payload, padding] frame with the shared default
// buckets, and record associated data. Blobs are out of scope for v1.

import { type Cbor, cbor, decodeCbor } from "./encoding";
import { type Rng, xopen, xseal } from "./crypto";
import type { Envelope } from "./types";

function h(x: number): number {
  return x < 24 ? 1 : x < 256 ? 2 : x < 65536 ? 3 : x < 2 ** 32 ? 5 : 9;
}

/** Zero-padding length for the smallest attainable power-of-two bucket. */
export function defaultPadding(n: number, limit = 1 << 20): number {
  for (let bucket = 256; bucket <= limit; bucket *= 2) {
    const base = bucket - 17 - h(n) - n;
    for (const hp of [1, 2, 3, 5, 9]) {
      const p = base - hp;
      if (p >= 0 && h(p) === hp) return p;
    }
  }
  return 0;
}

function recordAad(space: string, author: string, collection: string, rkey: string, keyId: string, blobs: Cbor[]): Uint8Array {
  return cbor(["peep/record", 1, space, author, collection, rkey, keyId, blobs]);
}

export function encryptRecord(opts: {
  key: Uint8Array; keyId: string; space: string; author: string; collection: string; rkey: string; content: Cbor; rng: Rng;
}): Envelope {
  const payload = cbor(opts.content);
  const frame = cbor([payload, new Uint8Array(defaultPadding(payload.length))]);
  const nonce = opts.rng.bytes(24);
  const ciphertext = xseal(opts.key, nonce, recordAad(opts.space, opts.author, opts.collection, opts.rkey, opts.keyId, []), frame);
  return { $type: "com.example.peep.envelope", format: 1, keyId: opts.keyId, nonce, ciphertext, blobs: [] };
}

export function decryptRecord(opts: {
  key: Uint8Array; envelope: Envelope; space: string; author: string; collection: string; rkey: string;
}): Cbor {
  const e = opts.envelope;
  if (e.$type !== "com.example.peep.envelope" || e.format !== 1 || e.nonce.length !== 24 || e.ciphertext.length < 19)
    throw new Error("envelope: malformed");
  const frame = decodeCbor(xopen(opts.key, e.nonce, recordAad(opts.space, opts.author, opts.collection, opts.rkey, e.keyId, e.blobs), e.ciphertext));
  if (!Array.isArray(frame) || frame.length !== 2 || !(frame[0] instanceof Uint8Array) || !(frame[1] instanceof Uint8Array))
    throw new Error("envelope: bad frame");
  if (frame[1].some((b) => b !== 0)) throw new Error("envelope: nonzero padding");
  return decodeCbor(frame[0]);
}
