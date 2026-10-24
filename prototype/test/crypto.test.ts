import { hexToBytes } from "@noble/hashes/utils.js";
import { cbor, decodeCbor, ref } from "../src/protocol/encoding";
import {
  Rng, bytesToHex, encryptionKeyPair, hpkeDeriveKeyPair, hpkeKeySchedule, hpkeOpenBase, hpkeSealBase,
  sign, signingKeyPair, verify,
} from "../src/protocol/crypto";

// RFC 9180 A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, Base mode.
const V = {
  info: "4f6465206f6e2061204772656369616e2055726e",
  ikmE: "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
  pkEm: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
  skEm: "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
  ikmR: "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
  pkRm: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
  skRm: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
  sharedSecret: "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
  key: "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
  baseNonce: "5c4d98150661b848853b547f",
  pt: "4265617574792069732074727574682c20747275746820626561757479",
  aad: "436f756e742d30",
  ct: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
};

describe("HPKE RFC 9180 A.2.1", () => {
  const e = hpkeDeriveKeyPair(hexToBytes(V.ikmE));
  const r = hpkeDeriveKeyPair(hexToBytes(V.ikmR));

  it("derives the vector's key pairs", () => {
    expect(bytesToHex(e.secretKey)).toBe(V.skEm);
    expect(bytesToHex(e.publicKey)).toBe(V.pkEm);
    expect(bytesToHex(r.secretKey)).toBe(V.skRm);
    expect(bytesToHex(r.publicKey)).toBe(V.pkRm);
  });

  it("matches shared secret, key schedule, and first ciphertext", () => {
    const sealed = hpkeSealBase(r.publicKey, hexToBytes(V.info), hexToBytes(V.aad), hexToBytes(V.pt), e);
    expect(bytesToHex(sealed.enc)).toBe(V.pkEm);
    expect(bytesToHex(sealed.sharedSecret)).toBe(V.sharedSecret);
    const ks = hpkeKeySchedule(sealed.sharedSecret, hexToBytes(V.info));
    expect(bytesToHex(ks.key)).toBe(V.key);
    expect(bytesToHex(ks.baseNonce)).toBe(V.baseNonce);
    expect(bytesToHex(sealed.ciphertext)).toBe(V.ct);
    const opened = hpkeOpenBase(r, sealed.enc, hexToBytes(V.info), hexToBytes(V.aad), sealed.ciphertext);
    expect(bytesToHex(opened)).toBe(V.pt);
  });

  it("rejects altered aad", () => {
    const sealed = hpkeSealBase(r.publicKey, hexToBytes(V.info), hexToBytes(V.aad), hexToBytes(V.pt), e);
    expect(() => hpkeOpenBase(r, sealed.enc, hexToBytes(V.info), new Uint8Array([1]), sealed.ciphertext)).toThrow();
  });
});

describe("encoding", () => {
  it("sorts map keys by length then bytes and round-trips", () => {
    const v = { bb: 1, a: [true, null, "x", new Uint8Array([1, 2])], ccc: { z: -5 } };
    const bytes = cbor(v);
    expect(Object.keys(decodeCbor(bytes) as object)).toEqual(["a", "bb", "ccc"]);
    expect(cbor(decodeCbor(bytes))).toEqual(bytes);
    expect(ref(v)).toBe(ref({ ccc: { z: -5 }, a: v.a, bb: 1 }));
  });

  it("rejects trailing bytes and non-minimal lengths", () => {
    expect(() => decodeCbor(Uint8Array.of(0x01, 0x00))).toThrow(/trailing/);
    expect(() => decodeCbor(Uint8Array.of(0x18, 0x05))).toThrow(/non-minimal/);
  });
});

describe("signatures and rng", () => {
  it("signs domain-separated values", () => {
    const k = signingKeyPair(Rng.fromLabel("t"));
    const sig = sign(k.secretKey, ["nbd/test", 1, "hello"]);
    expect(verify(sig, ["nbd/test", 1, "hello"], k.publicKey)).toBe(true);
    expect(verify(sig, ["nbd/test", 1, "hellp"], k.publicKey)).toBe(false);
  });

  it("replays from a seed", () => {
    expect(encryptionKeyPair(Rng.fromLabel("s")).publicKey).toEqual(encryptionKeyPair(Rng.fromLabel("s")).publicKey);
    expect(Rng.fromLabel("s").derive("a").bytes(8)).not.toEqual(Rng.fromLabel("s").derive("b").bytes(8));
  });
});
