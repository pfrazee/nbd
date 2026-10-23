// Cryptographic profile (core.md#mandatory-grant-profile, #content-encryption).
//
// HPKE is RFC 9180 Base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// and ChaCha20Poly1305, composed from noble primitives and checked against
// the RFC's test vector for exactly that suite (test/crypto.test.ts).

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305, xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { cbor } from "./encoding";

export { bytesToHex, concatBytes, utf8ToBytes };

// ---- deterministic randomness ---------------------------------------------

/** A seeded byte source so simulations replay exactly. Prototype only: real
 * installations draw keys and nonces from the platform CSPRNG. */
export class Rng {
  private counter = 0;
  constructor(private readonly seed: Uint8Array) {}

  static fromLabel(label: string): Rng {
    return new Rng(sha256(utf8ToBytes(label)));
  }

  derive(label: string): Rng {
    return new Rng(sha256(concatBytes(this.seed, utf8ToBytes("/" + label))));
  }

  bytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const block = sha256(concatBytes(this.seed, i2osp(this.counter++, 8)));
      const k = Math.min(block.length, n - off);
      out.set(block.subarray(0, k), off);
      off += k;
    }
    return out;
  }

  /** Uniform float in [0, 1). */
  float(): number {
    const b = this.bytes(6);
    let n = 0;
    for (const v of b) n = n * 256 + v;
    return n / 2 ** 48;
  }

  int(maxExclusive: number): number {
    return Math.floor(this.float() * maxExclusive);
  }
}

export function i2osp(n: number, w: number): Uint8Array {
  const out = new Uint8Array(w);
  for (let i = w - 1; i >= 0; i--) {
    out[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  return out;
}

export function randomId(rng: Rng): string {
  return bytesToHex(rng.bytes(16));
}

// ---- signatures and key agreement -----------------------------------------

export type KeyPair = { secretKey: Uint8Array; publicKey: Uint8Array };

export function signingKeyPair(rng: Rng): KeyPair {
  return ed25519.keygen(rng.bytes(32));
}

export function encryptionKeyPair(rng: Rng): KeyPair {
  return x25519.keygen(rng.bytes(32));
}

/** Pure Ed25519 over a domain-separated CBOR array. */
export function sign(secretKey: Uint8Array, domain: unknown[]): Uint8Array {
  return ed25519.sign(cbor(domain as never), secretKey);
}

export function verify(sig: Uint8Array, domain: unknown[], publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, cbor(domain as never), publicKey);
  } catch {
    return false;
  }
}

export function fingerprint(algorithm: "X25519" | "Ed25519", publicKey: Uint8Array): string {
  return bytesToHex(sha256(cbor(["peep/public-key", 1, algorithm, publicKey])));
}

// ---- HPKE (RFC 9180) --------------------------------------------------------

const KEM_ID = 0x0020;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0003;
const HPKE_V1 = utf8ToBytes("HPKE-v1");
const KEM_SUITE = concatBytes(utf8ToBytes("KEM"), i2osp(KEM_ID, 2));
const HPKE_SUITE = concatBytes(utf8ToBytes("HPKE"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2));
const EMPTY = new Uint8Array(0);

function labeledExtract(suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  return extract(sha256, concatBytes(HPKE_V1, suite, utf8ToBytes(label), ikm), salt);
}

function labeledExpand(suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, L: number): Uint8Array {
  return expand(sha256, prk, concatBytes(i2osp(L, 2), HPKE_V1, suite, utf8ToBytes(label), info), L);
}

/** DeriveKeyPair for DHKEM(X25519): used by the test vector. */
export function hpkeDeriveKeyPair(ikm: Uint8Array): KeyPair {
  const prk = labeledExtract(KEM_SUITE, EMPTY, "dkp_prk", ikm);
  const secretKey = labeledExpand(KEM_SUITE, prk, "sk", EMPTY, 32);
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

function dh(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  const out = x25519.getSharedSecret(sk, pk);
  if (out.every((b) => b === 0)) throw new Error("hpke: all-zero shared secret");
  return out;
}

function extractAndExpand(dhOut: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const prk = labeledExtract(KEM_SUITE, EMPTY, "eae_prk", dhOut);
  return labeledExpand(KEM_SUITE, prk, "shared_secret", kemContext, 32);
}

export function hpkeKeySchedule(sharedSecret: Uint8Array, info: Uint8Array) {
  const pskIdHash = labeledExtract(HPKE_SUITE, EMPTY, "psk_id_hash", EMPTY);
  const infoHash = labeledExtract(HPKE_SUITE, EMPTY, "info_hash", info);
  const context = concatBytes(Uint8Array.of(0), pskIdHash, infoHash);
  const secret = labeledExtract(HPKE_SUITE, sharedSecret, "secret", EMPTY);
  return {
    key: labeledExpand(HPKE_SUITE, secret, "key", context, 32),
    baseNonce: labeledExpand(HPKE_SUITE, secret, "base_nonce", context, 12),
  };
}

/** Single-shot SealBase. `ephemeral` is injectable for test vectors. */
export function hpkeSealBase(
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
  ephemeral: KeyPair,
): { enc: Uint8Array; ciphertext: Uint8Array; sharedSecret: Uint8Array } {
  const enc = ephemeral.publicKey;
  const sharedSecret = extractAndExpand(dh(ephemeral.secretKey, recipientPublicKey), concatBytes(enc, recipientPublicKey));
  const { key, baseNonce } = hpkeKeySchedule(sharedSecret, info);
  return { enc, ciphertext: chacha20poly1305(key, baseNonce, aad).encrypt(plaintext), sharedSecret };
}

export function hpkeOpenBase(
  recipient: KeyPair,
  enc: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const sharedSecret = extractAndExpand(dh(recipient.secretKey, enc), concatBytes(enc, recipient.publicKey));
  const { key, baseNonce } = hpkeKeySchedule(sharedSecret, info);
  return chacha20poly1305(key, baseNonce, aad).decrypt(ciphertext);
}

// ---- content AEAD -----------------------------------------------------------

export function xseal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

export function xopen(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
}

export function digest(x: Uint8Array): Uint8Array {
  return sha256(x);
}
