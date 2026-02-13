import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import {
  deriveAuthHash,
  deriveDeviceHash,
  deriveKey,
  hexToBytes,
  bytesToHex,
  sealUplink,
  openEnvelope,
  parseEnvelopeHeader,
  isEnvelope,
  SecureError,
  Method,
  AckStatus,
  parseHeadless,
  buildHeadless,
  parseAckInner,
  buildAckInner,
} from "../src/index.ts";

const specToken = "ate2bd319014b24e0a8aca9f00aea4c0d0";
const specSerial = "sensor-01";
const specKey = new Uint8Array([
  0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee,
  0x12, 0xab, 0x56, 0xcd, 0x78, 0xef, 0x90, 0x12,
]);
const specAuthHash = new Uint8Array([0x4d, 0xee, 0xdd, 0x7b, 0xab, 0x88, 0x17, 0xec]);
const specDeviceHash = new Uint8Array([0xab, 0x77, 0x88, 0xd2, 0x2e, 0xb7, 0x37, 0x2f]);

const specEnvelope = new Uint8Array([
  0x00, 0x00, 0x00, 0x00, 0x2a, 0x4d, 0xee, 0xdd,
  0x7b, 0xab, 0x88, 0x17, 0xec, 0xab, 0x77, 0x88,
  0xd2, 0x2e, 0xb7, 0x37, 0x2f, 0xc8, 0xc5, 0xaa,
  0x56, 0xd7, 0x55, 0x58, 0x2b, 0xac, 0xea, 0x13,
  0xbb, 0x57, 0x24, 0x93, 0xbb, 0x8c, 0xb1, 0x08,
  0x03, 0xcf, 0x82, 0x6f, 0xdb, 0x83, 0x3b, 0x79,
  0xc6,
]);

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

describe("hash derivation", () => {
  it("derives auth hash from spec vector", () => {
    const hash = deriveAuthHash(specToken);
    assert.ok(arraysEqual(hash, specAuthHash));
  });

  it("derives auth hash without at prefix", () => {
    const hash = deriveAuthHash("e2bd319014b24e0a8aca9f00aea4c0d0");
    assert.ok(arraysEqual(hash, specAuthHash));
  });

  it("derives device hash from spec vector", () => {
    const hash = deriveDeviceHash(specSerial);
    assert.ok(arraysEqual(hash, specDeviceHash));
  });
});

describe("spec vector (section 11.1)", () => {
  it("seals to expected envelope", () => {
    const innerFrame = new TextEncoder().encode("sensor-01|[temp:=32]");
    const envelope = sealUplink("push", innerFrame, 42, specAuthHash, specDeviceHash, specKey);
    assert.equal(envelope.length, 49);
    assert.ok(arraysEqual(envelope, specEnvelope));
  });

  it("opens spec envelope", () => {
    const { header, method, plaintext } = openEnvelope(specEnvelope, specKey);
    assert.equal(method, "push");
    assert.equal(header.counter, 42);
    assert.ok(arraysEqual(header.authHash, specAuthHash));
    assert.ok(arraysEqual(header.deviceHash, specDeviceHash));
    assert.equal(new TextDecoder().decode(plaintext), "sensor-01|[temp:=32]");
  });
});

describe("seal/open round-trip", () => {
  it("round-trips PUSH frame", () => {
    const authHash = deriveAuthHash(specToken);
    const deviceHash = deriveDeviceHash(specSerial);
    const innerFrame = new TextEncoder().encode("sensor-01|[temperature:=32.5;humidity:=65]");
    const envelope = sealUplink("push", innerFrame, 1, authHash, deviceHash, specKey);
    const { method, plaintext } = openEnvelope(envelope, specKey);
    assert.equal(method, "push");
    assert.ok(arraysEqual(plaintext, innerFrame));
  });

  it("round-trips PING frame", () => {
    const authHash = deriveAuthHash(specToken);
    const deviceHash = deriveDeviceHash(specSerial);
    const innerFrame = new TextEncoder().encode("sensor-01");
    const envelope = sealUplink("ping", innerFrame, 100, authHash, deviceHash, specKey);
    const { method, plaintext } = openEnvelope(envelope, specKey);
    assert.equal(method, "ping");
    assert.equal(new TextDecoder().decode(plaintext), "sensor-01");
  });

  it("round-trips ACK frame", () => {
    const authHash = deriveAuthHash(specToken);
    const deviceHash = deriveDeviceHash(specSerial);
    const innerFrame = new TextEncoder().encode("OK|3");
    const envelope = sealUplink("ack", innerFrame, 1, authHash, deviceHash, specKey);
    const { method, plaintext } = openEnvelope(envelope, specKey);
    assert.equal(method, "ack");
    assert.equal(new TextDecoder().decode(plaintext), "OK|3");
  });
});

describe("error cases", () => {
  it("rejects wrong key", () => {
    const wrongKey = new Uint8Array(16);
    assert.throws(() => openEnvelope(specEnvelope, wrongKey), SecureError);
  });

  it("rejects too-short envelope", () => {
    assert.throws(() => openEnvelope(specEnvelope.subarray(0, 10), specKey), SecureError);
  });

  it("rejects tampered ciphertext", () => {
    const tampered = new Uint8Array(specEnvelope);
    tampered[25] ^= 0xff;
    assert.throws(() => openEnvelope(tampered, specKey), SecureError);
  });

  it("rejects tampered header", () => {
    const tampered = new Uint8Array(specEnvelope);
    tampered[5] ^= 0xff;
    assert.throws(() => openEnvelope(tampered, specKey), SecureError);
  });

  it("rejects invalid key size", () => {
    const shortKey = new Uint8Array(8);
    const innerFrame = new TextEncoder().encode("test");
    assert.throws(() => sealUplink("push", innerFrame, 1, specAuthHash, specDeviceHash, shortKey), SecureError);
  });
});

describe("isEnvelope", () => {
  it("returns true for non-0x41 first byte", () => {
    assert.ok(isEnvelope(new Uint8Array([0x00, 0x01, 0x02])));
  });

  it("returns false for 0x41 first byte (ACK)", () => {
    assert.ok(!isEnvelope(new Uint8Array([0x41, 0x43, 0x4b])));
  });

  it("returns false for empty", () => {
    assert.ok(!isEnvelope(new Uint8Array([])));
  });
});

describe("parseEnvelopeHeader", () => {
  it("parses spec envelope header", () => {
    const header = parseEnvelopeHeader(specEnvelope);
    assert.equal(header.flags, 0x00);
    assert.equal(header.counter, 42);
    assert.ok(arraysEqual(header.authHash, specAuthHash));
    assert.ok(arraysEqual(header.deviceHash, specDeviceHash));
  });
});

describe("deriveKey", () => {
  const expectedDerivedKey = new Uint8Array([
    0xe5, 0x05, 0xf0, 0x3c, 0xc9, 0xe9, 0x3f, 0xdb,
    0xcc, 0x38, 0x28, 0x44, 0xcc, 0xa3, 0xe1, 0x7f,
    0xdf, 0x0b, 0xb3, 0x13, 0x18, 0x58, 0x53, 0x95,
    0xce, 0xaa, 0xa3, 0x9a, 0x5d, 0x14, 0x19, 0x64,
  ]);

  it("derives key matching spec vector (32 bytes)", () => {
    const key = deriveKey(specToken, specSerial, 32);
    assert.ok(arraysEqual(key, expectedDerivedKey));
  });

  it("derives key matching spec vector (16 bytes)", () => {
    const key = deriveKey(specToken, specSerial, 16);
    assert.ok(arraysEqual(key, expectedDerivedKey.slice(0, 16)));
  });

  it("works without at prefix", () => {
    const keyWith = deriveKey(specToken, specSerial, 32);
    const keyWithout = deriveKey("e2bd319014b24e0a8aca9f00aea4c0d0", specSerial, 32);
    assert.ok(arraysEqual(keyWith, keyWithout));
  });

  it("seal/open round-trip with derived key", () => {
    const key = deriveKey(specToken, specSerial);
    const authHash = deriveAuthHash(specToken);
    const deviceHash = deriveDeviceHash(specSerial);
    const innerFrame = new TextEncoder().encode("sensor-01|[temp:=32]");
    const envelope = sealUplink("push", innerFrame, 1, authHash, deviceHash, key);
    const { method, plaintext } = openEnvelope(envelope, key);
    assert.equal(method, "push");
    assert.ok(arraysEqual(plaintext, innerFrame));
  });
});

describe("hex utilities", () => {
  it("hexToBytes decodes correctly", () => {
    const result = hexToBytes("fe09da81bc4400ee");
    const expected = new Uint8Array([0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee]);
    assert.ok(arraysEqual(result, expected));
  });

  it("bytesToHex encodes correctly", () => {
    const data = new Uint8Array([0xfe, 0x09, 0xda, 0x81]);
    assert.equal(bytesToHex(data), "fe09da81");
  });

  it("round-trips hex", () => {
    const original = new Uint8Array([0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee, 0x12, 0xab, 0x56, 0xcd, 0x78, 0xef, 0x90, 0x12]);
    const hex = bytesToHex(original);
    assert.equal(hex, "fe09da81bc4400ee12ab56cd78ef9012");
    const decoded = hexToBytes(hex);
    assert.ok(arraysEqual(decoded, original));
  });

  it("hexToBytes handles uppercase", () => {
    const result = hexToBytes("AABB");
    assert.ok(arraysEqual(result, new Uint8Array([0xaa, 0xbb])));
  });

  it("hexToBytes rejects odd length", () => {
    assert.throws(() => hexToBytes("abc"), SecureError);
  });

  it("hexToBytes rejects non-hex chars", () => {
    assert.throws(() => hexToBytes("zz00"), SecureError);
  });

  it("hexToBytes handles empty string", () => {
    const result = hexToBytes("");
    assert.equal(result.length, 0);
  });
});

describe("headless frame parse/build", () => {
  it("round-trips PUSH headless", () => {
    const input = "sensor_01|[temp:=32]";
    const frame = parseHeadless(Method.Push, input);
    assert.equal(frame.serial, "sensor_01");
    assert.ok(frame.pushBody);
    const output = buildHeadless(Method.Push, frame);
    assert.equal(output, input);
  });

  it("round-trips PULL headless", () => {
    const input = "sensor_01|[temperature;humidity]";
    const frame = parseHeadless(Method.Pull, input);
    assert.equal(frame.serial, "sensor_01");
    assert.ok(frame.pullBody);
    const output = buildHeadless(Method.Pull, frame);
    assert.equal(output, input);
  });

  it("round-trips PING headless", () => {
    const input = "sensor_01";
    const frame = parseHeadless(Method.Ping, input);
    assert.equal(frame.serial, "sensor_01");
    const output = buildHeadless(Method.Ping, frame);
    assert.equal(output, input);
  });
});

describe("ACK inner frame", () => {
  it("round-trips OK with count", () => {
    const frame = parseAckInner("OK|3");
    assert.equal(frame.status, AckStatus.Ok);
    assert.deepStrictEqual(frame.detail, { type: "count", count: 3 });
    assert.equal(buildAckInner(frame), "OK|3");
  });

  it("round-trips PONG", () => {
    const frame = parseAckInner("PONG");
    assert.equal(frame.status, AckStatus.Pong);
    assert.equal(buildAckInner(frame), "PONG");
  });

  it("round-trips CMD", () => {
    const frame = parseAckInner("CMD|reboot");
    assert.equal(frame.status, AckStatus.Cmd);
    assert.equal(buildAckInner(frame), "CMD|reboot");
  });

  it("round-trips ERR", () => {
    const frame = parseAckInner("ERR|auth_failed");
    assert.equal(frame.status, AckStatus.Err);
    assert.equal(buildAckInner(frame), "ERR|auth_failed");
  });
});
