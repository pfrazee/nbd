// Deterministic CBOR for hashing, signing, and payload framing.
//
// A subset of normalized DAG-CBOR: null, booleans, safe integers, text,
// byte strings, arrays, and maps with text keys, sorted by encoded length and
// then bytewise. No floats, tags, or CID links: the prototype references
// values by ref(), a hex SHA-256 of their encoding (spec: Ref, simplified).

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

export type Cbor = null | boolean | number | string | Uint8Array | Cbor[] | { [k: string]: Cbor };

const MAX_DEPTH = 64;

function head(major: number, n: number, out: number[]): void {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`cbor: bad length ${n}`);
  const m = major << 5;
  if (n < 24) out.push(m | n);
  else if (n < 0x100) out.push(m | 24, n);
  else if (n < 0x10000) out.push(m | 25, n >> 8, n & 0xff);
  else if (n < 0x100000000) out.push(m | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  else {
    const hi = Math.floor(n / 0x100000000);
    const lo = n >>> 0;
    out.push(m | 27, 0, 0, (hi >> 8) & 0xff, hi & 0xff, (lo >>> 24) & 0xff, (lo >> 16) & 0xff, (lo >> 8) & 0xff, lo & 0xff);
  }
}

function enc(x: Cbor, out: number[], depth: number): void {
  if (depth > MAX_DEPTH) throw new Error("cbor: too deep");
  if (x === null) out.push(0xf6);
  else if (x === true) out.push(0xf5);
  else if (x === false) out.push(0xf4);
  else if (typeof x === "number") {
    if (!Number.isSafeInteger(x)) throw new Error(`cbor: not a safe integer: ${x}`);
    if (x >= 0) head(0, x, out);
    else head(1, -1 - x, out);
  } else if (typeof x === "string") {
    const b = utf8ToBytes(x);
    head(3, b.length, out);
    for (const v of b) out.push(v);
  } else if (x instanceof Uint8Array) {
    head(2, x.length, out);
    for (const v of x) out.push(v);
  } else if (Array.isArray(x)) {
    head(4, x.length, out);
    for (const v of x) enc(v, out, depth + 1);
  } else if (typeof x === "object") {
    const keys = Object.keys(x).filter((k) => x[k] !== undefined);
    const encoded = keys.map((k) => ({ k, b: utf8ToBytes(k) }));
    encoded.sort((a, b) => a.b.length - b.b.length || compareBytes(a.b, b.b));
    head(5, encoded.length, out);
    for (const { k, b } of encoded) {
      head(3, b.length, out);
      for (const v of b) out.push(v);
      enc(x[k], out, depth + 1);
    }
  } else {
    throw new Error(`cbor: unsupported value ${String(x)}`);
  }
}

export function cbor(x: Cbor): Uint8Array {
  const out: number[] = [];
  enc(x, out, 0);
  return Uint8Array.from(out);
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/** Strict decoder: rejects non-normalized encodings and trailing bytes. */
export function decodeCbor(bytes: Uint8Array, maxBytes = 1 << 24): Cbor {
  if (bytes.length > maxBytes) throw new Error("cbor: input too large");
  let pos = 0;
  const td = new TextDecoder("utf-8", { fatal: true });

  function len(info: number): number {
    if (info < 24) return info;
    const width = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : -1;
    if (width < 0 || pos + width > bytes.length) throw new Error("cbor: bad length");
    let n = 0;
    for (let i = 0; i < width; i++) n = n * 256 + bytes[pos++];
    if (!Number.isSafeInteger(n)) throw new Error("cbor: length too large");
    const min = width === 1 ? 24 : width === 2 ? 0x100 : width === 4 ? 0x10000 : 0x100000000;
    if (n < min) throw new Error("cbor: non-minimal length");
    return n;
  }

  function take(n: number): Uint8Array {
    if (pos + n > bytes.length) throw new Error("cbor: truncated");
    const b = bytes.slice(pos, pos + n);
    pos += n;
    return b;
  }

  function dec(depth: number): Cbor {
    if (depth > MAX_DEPTH) throw new Error("cbor: too deep");
    if (pos >= bytes.length) throw new Error("cbor: truncated");
    const ib = bytes[pos++];
    const major = ib >> 5;
    const info = ib & 0x1f;
    switch (major) {
      case 0:
        return len(info);
      case 1:
        return -1 - len(info);
      case 2:
        return take(len(info));
      case 3:
        return td.decode(take(len(info)));
      case 4: {
        const n = len(info);
        const arr: Cbor[] = [];
        for (let i = 0; i < n; i++) arr.push(dec(depth + 1));
        return arr;
      }
      case 5: {
        const n = len(info);
        const obj: { [k: string]: Cbor } = {};
        let prev: Uint8Array | null = null;
        for (let i = 0; i < n; i++) {
          if (bytes[pos] >> 5 !== 3) throw new Error("cbor: non-text map key");
          const kb = take(len(bytes[pos++] & 0x1f));
          if (prev && (prev.length > kb.length || (prev.length === kb.length && compareBytes(prev, kb) >= 0)))
            throw new Error("cbor: unsorted or duplicate map key");
          prev = kb;
          obj[td.decode(kb)] = dec(depth + 1);
        }
        return obj;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new Error("cbor: unsupported simple value");
      default:
        throw new Error(`cbor: unsupported major type ${major}`);
    }
  }

  const v = dec(0);
  if (pos !== bytes.length) throw new Error("cbor: trailing bytes");
  return v;
}

/** Hex SHA-256 of a value's encoding: the prototype's content reference. */
export function ref(x: Cbor): string {
  return bytesToHex(sha256(cbor(x)));
}
