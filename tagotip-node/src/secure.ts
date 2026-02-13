import { createHash, createHmac, createCipheriv, createDecipheriv } from "node:crypto";

const HEADER_SIZE = 21;
const AUTH_HASH_SIZE = 8;
const DEVICE_HASH_SIZE = 8;
const FLAGS_SIZE = 1;
const COUNTER_SIZE = 4;
const CCM_TAG_SIZE = 8;
const CCM_NONCE_SIZE = 13;
const MAX_INNER_FRAME_SIZE = 16_384;
const RESERVED_FLAGS_VALUE = 0x41;

const FLAGS_CIPHER_MASK = 0b1110_0000;
const FLAGS_CIPHER_SHIFT = 5;
const FLAGS_VERSION_MASK = 0b0001_1000;
const FLAGS_VERSION_SHIFT = 3;
const FLAGS_METHOD_MASK = 0b0000_0111;

export type CipherSuite = "aes-128-ccm";

export type EnvelopeMethod = "push" | "pull" | "ping" | "ack";

export interface EnvelopeHeader {
  flags: number;
  counter: number;
  authHash: Uint8Array;
  deviceHash: Uint8Array;
}

export class SecureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecureError";
  }
}

const METHOD_IDS: Record<EnvelopeMethod, number> = {
  push: 0,
  pull: 1,
  ping: 2,
  ack: 3,
};

const METHOD_FROM_ID: Record<number, EnvelopeMethod> = {
  0: "push",
  1: "pull",
  2: "ping",
  3: "ack",
};

function sha256(data: Uint8Array): Uint8Array {
  const hash = createHash("sha256");
  hash.update(data);
  return new Uint8Array(hash.digest());
}

export function deriveAuthHash(token: string): Uint8Array {
  const hexPart = token.startsWith("at") ? token.slice(2) : token;
  const digest = sha256(Buffer.from(hexPart, "utf-8"));
  return digest.slice(0, AUTH_HASH_SIZE);
}

export function deriveDeviceHash(serial: string): Uint8Array {
  const digest = sha256(Buffer.from(serial, "utf-8"));
  return digest.slice(0, DEVICE_HASH_SIZE);
}

export function deriveKey(token: string, serial: string, keyLen: 16 | 32 = 16): Uint8Array {
  const hexPart = token.startsWith("at") ? token.slice(2) : token;
  const hmac = createHmac("sha256", Buffer.from(hexPart, "utf-8"));
  hmac.update(Buffer.from(serial, "utf-8"));
  const fullKey = new Uint8Array(hmac.digest());
  return fullKey.slice(0, keyLen);
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new SecureError("hex string must have even length");
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new SecureError("hex string contains non-hex characters");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function encodeFlags(cipherSuiteId: number, version: number, methodId: number): number {
  const flags = (cipherSuiteId << FLAGS_CIPHER_SHIFT) | (version << FLAGS_VERSION_SHIFT) | methodId;
  if (flags === RESERVED_FLAGS_VALUE) {
    throw new SecureError("flags byte 0x41 is reserved");
  }
  return flags;
}

function decodeFlags(flags: number): { cipherId: number; version: number; methodId: number } {
  if (flags === RESERVED_FLAGS_VALUE) {
    throw new SecureError("flags byte 0x41 is reserved");
  }
  const cipherId = (flags & FLAGS_CIPHER_MASK) >> FLAGS_CIPHER_SHIFT;
  const version = (flags & FLAGS_VERSION_MASK) >> FLAGS_VERSION_SHIFT;
  const methodId = flags & FLAGS_METHOD_MASK;
  return { cipherId, version, methodId };
}

function buildHeader(flags: number, counter: number, authHash: Uint8Array, deviceHash: Uint8Array): Uint8Array {
  const header = new Uint8Array(HEADER_SIZE);
  header[0] = flags;
  const view = new DataView(header.buffer);
  view.setUint32(FLAGS_SIZE, counter, false);
  header.set(authHash.subarray(0, AUTH_HASH_SIZE), FLAGS_SIZE + COUNTER_SIZE);
  header.set(deviceHash.subarray(0, DEVICE_HASH_SIZE), FLAGS_SIZE + COUNTER_SIZE + AUTH_HASH_SIZE);
  return header;
}

function constructNonce(flags: number, deviceHash: Uint8Array, counter: number): Uint8Array {
  const nonce = new Uint8Array(CCM_NONCE_SIZE);
  nonce[0] = flags;
  // Zero padding at bytes 1-4 (already zeroed)
  // Device hash first 4 bytes at offset 5
  nonce.set(deviceHash.subarray(0, 4), CCM_NONCE_SIZE - 8);
  // Counter as big-endian u32 in last 4 bytes
  const view = new DataView(nonce.buffer);
  view.setUint32(CCM_NONCE_SIZE - 4, counter, false);
  return nonce;
}

function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const cipher = createCipheriv("aes-128-ccm", key, nonce, { authTagLength: CCM_TAG_SIZE });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const encrypted = cipher.update(plaintext);
  cipher.final();
  const tag = cipher.getAuthTag();
  const result = new Uint8Array(encrypted.length + tag.length);
  result.set(encrypted, 0);
  result.set(tag, encrypted.length);
  return result;
}

function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertextWithTag: Uint8Array,
): Uint8Array {
  if (ciphertextWithTag.length < CCM_TAG_SIZE) {
    throw new SecureError("ciphertext too short");
  }
  const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - CCM_TAG_SIZE);
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - CCM_TAG_SIZE);
  const decipher = createDecipheriv("aes-128-ccm", key, nonce, { authTagLength: CCM_TAG_SIZE });
  decipher.setAuthTag(tag);
  decipher.setAAD(aad, { plaintextLength: ciphertext.length });
  const decrypted = decipher.update(ciphertext);
  try {
    decipher.final();
  } catch {
    throw new SecureError("AEAD decryption failed");
  }
  return new Uint8Array(decrypted);
}

export function sealUplink(
  method: EnvelopeMethod,
  innerFrame: Uint8Array,
  counter: number,
  authHash: Uint8Array,
  deviceHash: Uint8Array,
  key: Uint8Array,
  _suite: CipherSuite = "aes-128-ccm",
): Uint8Array {
  if (innerFrame.length > MAX_INNER_FRAME_SIZE) {
    throw new SecureError("inner frame exceeds maximum size");
  }
  if (key.length !== 16) {
    throw new SecureError("invalid encryption key size");
  }

  const methodId = METHOD_IDS[method];
  if (methodId === undefined) {
    throw new SecureError(`invalid method: ${method}`);
  }
  const flags = encodeFlags(0, 0, methodId);
  const header = buildHeader(flags, counter, authHash, deviceHash);
  const nonce = constructNonce(flags, deviceHash, counter);
  const ciphertextWithTag = aeadEncrypt(key, nonce, header, innerFrame);

  const envelope = new Uint8Array(HEADER_SIZE + ciphertextWithTag.length);
  envelope.set(header, 0);
  envelope.set(ciphertextWithTag, HEADER_SIZE);
  return envelope;
}

export function openEnvelope(
  envelope: Uint8Array,
  key: Uint8Array,
): { header: EnvelopeHeader; method: EnvelopeMethod; plaintext: Uint8Array } {
  const header = parseEnvelopeHeader(envelope);
  const { cipherId, version, methodId } = decodeFlags(header.flags);

  if (version !== 0) {
    throw new SecureError("unsupported version");
  }
  if (cipherId !== 0) {
    throw new SecureError("unsupported cipher suite");
  }
  if (key.length !== 16) {
    throw new SecureError("invalid encryption key size");
  }

  const method = METHOD_FROM_ID[methodId];
  if (method === undefined) {
    throw new SecureError("invalid method");
  }

  const ciphertextWithTag = envelope.subarray(HEADER_SIZE);
  if (ciphertextWithTag.length < CCM_TAG_SIZE) {
    throw new SecureError("envelope too short");
  }

  const aad = envelope.subarray(0, HEADER_SIZE);
  const nonce = constructNonce(header.flags, header.deviceHash, header.counter);
  const plaintext = aeadDecrypt(key, nonce, aad, ciphertextWithTag);

  return { header, method, plaintext };
}

export function parseEnvelopeHeader(envelope: Uint8Array): EnvelopeHeader {
  if (envelope.length < HEADER_SIZE) {
    throw new SecureError("envelope too short");
  }

  const flags = envelope[0];
  decodeFlags(flags);

  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
  const counter = view.getUint32(FLAGS_SIZE, false);
  const authHash = envelope.slice(FLAGS_SIZE + COUNTER_SIZE, FLAGS_SIZE + COUNTER_SIZE + AUTH_HASH_SIZE);
  const deviceHash = envelope.slice(
    FLAGS_SIZE + COUNTER_SIZE + AUTH_HASH_SIZE,
    FLAGS_SIZE + COUNTER_SIZE + AUTH_HASH_SIZE + DEVICE_HASH_SIZE,
  );

  return { flags, counter, authHash, deviceHash };
}

export function isEnvelope(data: Uint8Array): boolean {
  if (data.length === 0) return false;
  return data[0] !== RESERVED_FLAGS_VALUE;
}
