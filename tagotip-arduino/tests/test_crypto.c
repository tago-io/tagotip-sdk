/**
 * test_crypto.c -- Standalone C test for TagoTiP/S crypto envelope.
 *
 * Compile:
 *   cc -std=c99 -Wall -Wextra -Werror -o test_crypto tests/test_crypto.c src/tagotips.c -I src && ./test_crypto
 */

#include <stdio.h>
#include <string.h>

#include "tagotips.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(a, b, msg) do { \
  if ((a) == (b)) { \
    tests_passed++; \
  } else { \
    tests_failed++; \
    printf("FAIL: %s (expected %d, got %d)\n", msg, (int)(b), (int)(a)); \
  } \
} while (0)

#define ASSERT_TRUE(expr, msg) do { \
  if ((expr)) { \
    tests_passed++; \
  } else { \
    tests_failed++; \
    printf("FAIL: %s\n", msg); \
  } \
} while (0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
  if (memcmp((a), (b), (len)) == 0) { \
    tests_passed++; \
  } else { \
    tests_failed++; \
    printf("FAIL: %s (memory mismatch at byte", msg); \
    for (size_t _i = 0; _i < (size_t)(len); _i++) { \
      if (((const uint8_t *)(a))[_i] != ((const uint8_t *)(b))[_i]) { \
        printf(" %zu: got 0x%02x expected 0x%02x", _i, \
               ((const uint8_t *)(a))[_i], ((const uint8_t *)(b))[_i]); \
        break; \
      } \
    } \
    printf(")\n"); \
  } \
} while (0)

/* =========================================================================
 * Spec section 11.1 test vectors
 * ========================================================================= */

static const char *SPEC_TOKEN = "ate2bd319014b24e0a8aca9f00aea4c0d0";
static const char *SPEC_SERIAL = "sensor-01";

static const uint8_t SPEC_KEY[16] = {
  0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee,
  0x12, 0xab, 0x56, 0xcd, 0x78, 0xef, 0x90, 0x12
};

static const uint32_t SPEC_COUNTER = 42;

static const uint8_t SPEC_AUTH_HASH[8] = {
  0x4d, 0xee, 0xdd, 0x7b, 0xab, 0x88, 0x17, 0xec
};

static const uint8_t SPEC_DEVICE_HASH[8] = {
  0xab, 0x77, 0x88, 0xd2, 0x2e, 0xb7, 0x37, 0x2f
};

static const uint8_t SPEC_INNER_FRAME[] = {
  0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x2d, 0x30, 0x31, 0x7c,
  0x5b, 0x74, 0x65, 0x6d, 0x70, 0x3a, 0x3d, 0x33, 0x32, 0x5d
};

static const uint8_t SPEC_AAD[21] = {
  0x00, 0x00, 0x00, 0x00, 0x2a, 0x4d, 0xee, 0xdd,
  0x7b, 0xab, 0x88, 0x17, 0xec, 0xab, 0x77, 0x88,
  0xd2, 0x2e, 0xb7, 0x37, 0x2f
};

static const uint8_t SPEC_CIPHERTEXT[20] = {
  0xc8, 0xc5, 0xaa, 0x56, 0xd7, 0x55, 0x58, 0x2b,
  0xac, 0xea, 0x13, 0xbb, 0x57, 0x24, 0x93, 0xbb,
  0x8c, 0xb1, 0x08, 0x03
};

static const uint8_t SPEC_AUTH_TAG[8] = {
  0xcf, 0x82, 0x6f, 0xdb, 0x83, 0x3b, 0x79, 0xc6
};

static const uint8_t SPEC_ENVELOPE[49] = {
  0x00, 0x00, 0x00, 0x00, 0x2a, 0x4d, 0xee, 0xdd,
  0x7b, 0xab, 0x88, 0x17, 0xec, 0xab, 0x77, 0x88,
  0xd2, 0x2e, 0xb7, 0x37, 0x2f, 0xc8, 0xc5, 0xaa,
  0x56, 0xd7, 0x55, 0x58, 0x2b, 0xac, 0xea, 0x13,
  0xbb, 0x57, 0x24, 0x93, 0xbb, 0x8c, 0xb1, 0x08,
  0x03, 0xcf, 0x82, 0x6f, 0xdb, 0x83, 0x3b, 0x79,
  0xc6
};

/* =========================================================================
 * SHA-256 tests
 * ========================================================================= */

void test_sha256_empty(void) {
  /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
  uint8_t expected[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
  };
  /* Use derive_device_hash as proxy for SHA-256 (it hashes serial then takes first 8 bytes) */
  /* Instead, test via auth hash derivation of known values */

  /* We verify SHA-256 indirectly through hash derivation tests below */
  /* This test verifies the empty-string constant is consistent */
  uint8_t hash[8];
  tagotips_derive_device_hash("", hash);
  ASSERT_MEM_EQ(hash, expected, 8, "SHA-256 empty string (first 8 bytes via device_hash)");
}

void test_sha256_abc(void) {
  /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
  uint8_t expected_first8[8] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea
  };
  uint8_t hash[8];
  tagotips_derive_device_hash("abc", hash);
  ASSERT_MEM_EQ(hash, expected_first8, 8, "SHA-256 'abc' (first 8 bytes via device_hash)");
}

/* =========================================================================
 * Hash derivation tests (spec section 11.1)
 * ========================================================================= */

void test_auth_hash_derivation(void) {
  uint8_t hash[8];
  tagotips_derive_auth_hash(SPEC_TOKEN, hash);
  ASSERT_MEM_EQ(hash, SPEC_AUTH_HASH, 8, "auth hash matches spec");
}

void test_auth_hash_without_prefix(void) {
  /* Token without "at" prefix should produce same result */
  uint8_t hash[8];
  tagotips_derive_auth_hash("e2bd319014b24e0a8aca9f00aea4c0d0", hash);
  ASSERT_MEM_EQ(hash, SPEC_AUTH_HASH, 8, "auth hash without 'at' prefix matches spec");
}

void test_device_hash_derivation(void) {
  uint8_t hash[8];
  tagotips_derive_device_hash(SPEC_SERIAL, hash);
  ASSERT_MEM_EQ(hash, SPEC_DEVICE_HASH, 8, "device hash matches spec");
}

/* =========================================================================
 * tagotips_seal -- spec vector
 * ========================================================================= */

void test_seal_spec_envelope(void) {
  uint8_t out[64];
  int32_t rc = tagotips_seal(
    SPEC_INNER_FRAME, sizeof(SPEC_INNER_FRAME),
    TAGOTIPS_METHOD_PUSH, SPEC_COUNTER,
    SPEC_AUTH_HASH, SPEC_DEVICE_HASH,
    SPEC_KEY, out, sizeof(out));

  ASSERT_EQ(rc, 49, "seal returns 49 bytes");
  ASSERT_MEM_EQ(out, SPEC_AAD, 21, "seal header (AAD) matches spec");
  ASSERT_MEM_EQ(out + 21, SPEC_CIPHERTEXT, 20, "seal ciphertext matches spec");
  ASSERT_MEM_EQ(out + 41, SPEC_AUTH_TAG, 8, "seal auth tag matches spec");
  ASSERT_MEM_EQ(out, SPEC_ENVELOPE, 49, "seal full envelope matches spec");
}

/* =========================================================================
 * tagotips_open -- spec vector
 * ========================================================================= */

void test_open_spec_envelope(void) {
  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[64];
  int32_t rc = tagotips_open(
    SPEC_ENVELOPE, sizeof(SPEC_ENVELOPE),
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));

  ASSERT_EQ(rc, 20, "open returns 20 bytes plaintext");
  ASSERT_EQ(hdr.flags, 0x00, "open header flags");
  ASSERT_EQ((int)hdr.counter, 42, "open header counter");
  ASSERT_MEM_EQ(hdr.auth_hash, SPEC_AUTH_HASH, 8, "open header auth_hash");
  ASSERT_MEM_EQ(hdr.device_hash, SPEC_DEVICE_HASH, 8, "open header device_hash");
  ASSERT_EQ(method, TAGOTIPS_METHOD_PUSH, "open method is PUSH");
  ASSERT_MEM_EQ(inner, SPEC_INNER_FRAME, 20, "open plaintext matches spec inner frame");
}

/* =========================================================================
 * Round-trip: seal then open
 * ========================================================================= */

void test_round_trip(void) {
  const uint8_t plaintext[] = "hello world from tagotips";
  size_t pt_len = sizeof(plaintext) - 1;

  uint8_t auth_hash[8], device_hash[8];
  tagotips_derive_auth_hash("atdeadbeef1234567890abcdef1234567890", auth_hash);
  tagotips_derive_device_hash("my-device-42", device_hash);

  uint8_t key[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

  uint8_t envelope[256];
  int32_t sealed_len = tagotips_seal(
    (const uint8_t *)plaintext, pt_len,
    TAGOTIPS_METHOD_PING, 1000,
    auth_hash, device_hash, key,
    envelope, sizeof(envelope));

  ASSERT_TRUE(sealed_len > 0, "round-trip seal succeeds");
  ASSERT_EQ(sealed_len, (int32_t)(TAGOTIPS_HEADER_SIZE + pt_len + TAGOTIPS_TAG_SIZE),
            "round-trip envelope size");

  TagotipsHeader hdr;
  uint8_t method;
  uint8_t recovered[256];
  int32_t opened_len = tagotips_open(
    envelope, (size_t)sealed_len,
    key, &hdr, &method, recovered, sizeof(recovered));

  ASSERT_EQ(opened_len, (int32_t)pt_len, "round-trip open length");
  ASSERT_EQ(method, TAGOTIPS_METHOD_PING, "round-trip method");
  ASSERT_EQ((int)hdr.counter, 1000, "round-trip counter");
  ASSERT_MEM_EQ(hdr.auth_hash, auth_hash, 8, "round-trip auth_hash");
  ASSERT_MEM_EQ(hdr.device_hash, device_hash, 8, "round-trip device_hash");
  ASSERT_TRUE(memcmp(recovered, plaintext, pt_len) == 0, "round-trip plaintext matches");
}

void test_round_trip_empty_plaintext(void) {
  uint8_t auth_hash[8], device_hash[8];
  tagotips_derive_auth_hash("atdeadbeef1234567890abcdef1234567890", auth_hash);
  tagotips_derive_device_hash("device-x", device_hash);

  uint8_t key[16] = { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
                       0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };

  uint8_t envelope[64];
  int32_t sealed_len = tagotips_seal(
    (const uint8_t *)"", 0,
    TAGOTIPS_METHOD_PULL, 0,
    auth_hash, device_hash, key,
    envelope, sizeof(envelope));

  ASSERT_EQ(sealed_len, (int32_t)(TAGOTIPS_HEADER_SIZE + TAGOTIPS_TAG_SIZE),
            "empty plaintext envelope size");

  TagotipsHeader hdr;
  uint8_t method;
  uint8_t recovered[64];
  int32_t opened_len = tagotips_open(
    envelope, (size_t)sealed_len,
    key, &hdr, &method, recovered, sizeof(recovered));

  ASSERT_EQ(opened_len, 0, "empty plaintext open returns 0");
  ASSERT_EQ(method, TAGOTIPS_METHOD_PULL, "empty plaintext method");
}

/* =========================================================================
 * tagotips_parse_header
 * ========================================================================= */

void test_parse_header(void) {
  TagotipsHeader hdr;
  int32_t rc = tagotips_parse_header(SPEC_ENVELOPE, sizeof(SPEC_ENVELOPE), &hdr);

  ASSERT_EQ(rc, TAGOTIPS_OK, "parse_header returns OK");
  ASSERT_EQ(hdr.flags, 0x00, "parse_header flags");
  ASSERT_EQ((int)hdr.counter, 42, "parse_header counter");
  ASSERT_MEM_EQ(hdr.auth_hash, SPEC_AUTH_HASH, 8, "parse_header auth_hash");
  ASSERT_MEM_EQ(hdr.device_hash, SPEC_DEVICE_HASH, 8, "parse_header device_hash");
}

/* =========================================================================
 * tagotips_is_envelope
 * ========================================================================= */

void test_is_envelope(void) {
  ASSERT_EQ(tagotips_is_envelope(SPEC_ENVELOPE, sizeof(SPEC_ENVELOPE)), 1,
            "spec envelope is envelope");
  ASSERT_EQ(tagotips_is_envelope((const uint8_t *)"ACK|OK", 6), 0,
            "ACK plaintext is not envelope");
  ASSERT_EQ(tagotips_is_envelope(NULL, 0), 0,
            "NULL is not envelope");
  ASSERT_EQ(tagotips_is_envelope((const uint8_t *)"", 0), 0,
            "empty is not envelope");
  ASSERT_EQ(tagotips_is_envelope((const uint8_t *)"\x00", 1), 1,
            "0x00 byte is envelope");
}

/* =========================================================================
 * Error cases
 * ========================================================================= */

void test_wrong_key(void) {
  uint8_t wrong_key[16] = { 0 };

  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[64];
  int32_t rc = tagotips_open(
    SPEC_ENVELOPE, sizeof(SPEC_ENVELOPE),
    wrong_key, &hdr, &method, inner, sizeof(inner));

  ASSERT_EQ(rc, TAGOTIPS_ERR_DECRYPTION_FAILED, "wrong key fails decryption");

  /* Verify plaintext was zeroed */
  int all_zero = 1;
  for (int i = 0; i < 20; i++) {
    if (inner[i] != 0) { all_zero = 0; break; }
  }
  ASSERT_TRUE(all_zero, "wrong key zeroes plaintext buffer");
}

void test_tampered_header(void) {
  uint8_t tampered[49];
  memcpy(tampered, SPEC_ENVELOPE, 49);
  tampered[5] ^= 0x01; /* Flip a bit in auth_hash (part of AAD) */

  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[64];
  int32_t rc = tagotips_open(
    tampered, sizeof(tampered),
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));

  ASSERT_EQ(rc, TAGOTIPS_ERR_DECRYPTION_FAILED, "tampered header fails decryption");
}

void test_tampered_ciphertext(void) {
  uint8_t tampered[49];
  memcpy(tampered, SPEC_ENVELOPE, 49);
  tampered[25] ^= 0x01; /* Flip a bit in ciphertext */

  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[64];
  int32_t rc = tagotips_open(
    tampered, sizeof(tampered),
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));

  ASSERT_EQ(rc, TAGOTIPS_ERR_DECRYPTION_FAILED, "tampered ciphertext fails decryption");
}

void test_tampered_tag(void) {
  uint8_t tampered[49];
  memcpy(tampered, SPEC_ENVELOPE, 49);
  tampered[45] ^= 0x01; /* Flip a bit in auth tag */

  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[64];
  int32_t rc = tagotips_open(
    tampered, sizeof(tampered),
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));

  ASSERT_EQ(rc, TAGOTIPS_ERR_DECRYPTION_FAILED, "tampered tag fails decryption");
}

void test_truncated_envelope(void) {
  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[64];

  /* Too short for header */
  int32_t rc = tagotips_open(
    SPEC_ENVELOPE, 10,
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));
  ASSERT_EQ(rc, TAGOTIPS_ERR_ENVELOPE_TOO_SHORT, "truncated envelope (10 bytes)");

  /* Header only, no ciphertext or tag */
  rc = tagotips_open(
    SPEC_ENVELOPE, 21,
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));
  ASSERT_EQ(rc, TAGOTIPS_ERR_ENVELOPE_TOO_SHORT, "truncated envelope (header only)");
}

void test_buffer_too_small(void) {
  /* Seal with too-small output buffer */
  uint8_t out[10];
  int32_t rc = tagotips_seal(
    SPEC_INNER_FRAME, sizeof(SPEC_INNER_FRAME),
    TAGOTIPS_METHOD_PUSH, SPEC_COUNTER,
    SPEC_AUTH_HASH, SPEC_DEVICE_HASH,
    SPEC_KEY, out, sizeof(out));
  ASSERT_EQ(rc, TAGOTIPS_ERR_BUFFER_TOO_SMALL, "seal buffer too small");

  /* Open with too-small inner buffer */
  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[5]; /* Too small for 20-byte plaintext */
  rc = tagotips_open(
    SPEC_ENVELOPE, sizeof(SPEC_ENVELOPE),
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));
  ASSERT_EQ(rc, TAGOTIPS_ERR_BUFFER_TOO_SMALL, "open buffer too small");
}

void test_null_pointers(void) {
  uint8_t out[64];
  int32_t rc = tagotips_seal(
    NULL, 0,
    TAGOTIPS_METHOD_PUSH, 0,
    SPEC_AUTH_HASH, SPEC_DEVICE_HASH,
    SPEC_KEY, out, sizeof(out));
  ASSERT_EQ(rc, TAGOTIPS_ERR_NULL_PTR, "seal null inner_frame");

  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[64];
  rc = tagotips_open(
    NULL, 49,
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));
  ASSERT_EQ(rc, TAGOTIPS_ERR_NULL_PTR, "open null envelope");

  rc = tagotips_parse_header(NULL, 49, &hdr);
  ASSERT_EQ(rc, TAGOTIPS_ERR_NULL_PTR, "parse_header null envelope");
}

void test_reserved_flags(void) {
  /* Create an envelope with reserved flags byte 0x41 */
  uint8_t tampered[49];
  memcpy(tampered, SPEC_ENVELOPE, 49);
  tampered[0] = 0x41; /* Reserved value */

  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[64];
  int32_t rc = tagotips_open(
    tampered, sizeof(tampered),
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));
  ASSERT_EQ(rc, TAGOTIPS_ERR_RESERVED_FLAGS, "reserved flags 0x41 rejected on open");

  rc = tagotips_parse_header(tampered, sizeof(tampered), &hdr);
  ASSERT_EQ(rc, TAGOTIPS_ERR_RESERVED_FLAGS, "reserved flags 0x41 rejected on parse_header");
}

void test_invalid_method_seal(void) {
  uint8_t out[64];
  int32_t rc = tagotips_seal(
    SPEC_INNER_FRAME, sizeof(SPEC_INNER_FRAME),
    5, /* Invalid method */
    SPEC_COUNTER,
    SPEC_AUTH_HASH, SPEC_DEVICE_HASH,
    SPEC_KEY, out, sizeof(out));
  ASSERT_EQ(rc, TAGOTIPS_ERR_INVALID_METHOD, "seal invalid method");
}

void test_unsupported_cipher_on_open(void) {
  /* Forge an envelope with cipher suite 1 (AES-128-GCM, not supported by this lib) */
  uint8_t forged[49];
  memcpy(forged, SPEC_ENVELOPE, 49);
  /* flags = (1 << 5) | (0 << 3) | 0 = 0x20 */
  forged[0] = 0x20;

  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[64];
  int32_t rc = tagotips_open(
    forged, sizeof(forged),
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));
  ASSERT_EQ(rc, TAGOTIPS_ERR_UNSUPPORTED_CIPHER, "unsupported cipher on open");
}

void test_unsupported_version_on_open(void) {
  /* Forge an envelope with version 1 */
  uint8_t forged[49];
  memcpy(forged, SPEC_ENVELOPE, 49);
  /* flags = (0 << 5) | (1 << 3) | 0 = 0x08 */
  forged[0] = 0x08;

  TagotipsHeader hdr;
  uint8_t method;
  uint8_t inner[64];
  int32_t rc = tagotips_open(
    forged, sizeof(forged),
    SPEC_KEY, &hdr, &method, inner, sizeof(inner));
  ASSERT_EQ(rc, TAGOTIPS_ERR_UNSUPPORTED_VERSION, "unsupported version on open");
}

void test_inner_too_large(void) {
  uint8_t big_inner[TAGOTIPS_MAX_INNER_FRAME + 1];
  memset(big_inner, 'A', sizeof(big_inner));

  uint8_t out[TAGOTIPS_MAX_ENVELOPE + 64];
  int32_t rc = tagotips_seal(
    big_inner, sizeof(big_inner),
    TAGOTIPS_METHOD_PUSH, 1,
    SPEC_AUTH_HASH, SPEC_DEVICE_HASH,
    SPEC_KEY, out, sizeof(out));
  ASSERT_EQ(rc, TAGOTIPS_ERR_INNER_TOO_LARGE, "inner too large");
}

/* =========================================================================
 * Constants
 * ========================================================================= */

void test_constants(void) {
  ASSERT_EQ(TAGOTIPS_HEADER_SIZE, 21, "HEADER_SIZE");
  ASSERT_EQ(TAGOTIPS_HASH_SIZE, 8, "HASH_SIZE");
  ASSERT_EQ(TAGOTIPS_KEY_SIZE, 16, "KEY_SIZE");
  ASSERT_EQ(TAGOTIPS_TAG_SIZE, 8, "TAG_SIZE");
  ASSERT_EQ(TAGOTIPS_NONCE_SIZE, 13, "NONCE_SIZE");
  ASSERT_EQ(TAGOTIPS_MAX_INNER_FRAME, 16384, "MAX_INNER_FRAME");
  ASSERT_EQ(TAGOTIPS_MAX_ENVELOPE, 16413, "MAX_ENVELOPE");
}

void test_error_code_values(void) {
  ASSERT_EQ(TAGOTIPS_OK, 0, "OK");
  ASSERT_EQ(TAGOTIPS_ERR_NULL_PTR, -1, "ERR_NULL_PTR");
  ASSERT_EQ(TAGOTIPS_ERR_BUFFER_TOO_SMALL, -2, "ERR_BUFFER_TOO_SMALL");
  ASSERT_EQ(TAGOTIPS_ERR_ENVELOPE_TOO_SHORT, -3, "ERR_ENVELOPE_TOO_SHORT");
  ASSERT_EQ(TAGOTIPS_ERR_DECRYPTION_FAILED, -5, "ERR_DECRYPTION_FAILED");
  ASSERT_EQ(TAGOTIPS_ERR_UNSUPPORTED_CIPHER, -6, "ERR_UNSUPPORTED_CIPHER");
  ASSERT_EQ(TAGOTIPS_ERR_UNSUPPORTED_VERSION, -7, "ERR_UNSUPPORTED_VERSION");
  ASSERT_EQ(TAGOTIPS_ERR_INVALID_METHOD, -8, "ERR_INVALID_METHOD");
  ASSERT_EQ(TAGOTIPS_ERR_INNER_TOO_LARGE, -9, "ERR_INNER_TOO_LARGE");
  ASSERT_EQ(TAGOTIPS_ERR_RESERVED_FLAGS, -10, "ERR_RESERVED_FLAGS");
}

void test_method_values(void) {
  ASSERT_EQ(TAGOTIPS_METHOD_PUSH, 0, "METHOD_PUSH");
  ASSERT_EQ(TAGOTIPS_METHOD_PULL, 1, "METHOD_PULL");
  ASSERT_EQ(TAGOTIPS_METHOD_PING, 2, "METHOD_PING");
  ASSERT_EQ(TAGOTIPS_METHOD_ACK, 3, "METHOD_ACK");
}

/* =========================================================================
 * All methods round-trip
 * ========================================================================= */

void test_all_methods_round_trip(void) {
  uint8_t auth_hash[8], device_hash[8];
  tagotips_derive_auth_hash("atcafe0123456789abcdef0123456789ab", auth_hash);
  tagotips_derive_device_hash("dev-01", device_hash);

  uint8_t key[16] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                       0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00 };

  const char *payloads[] = { "push-data", "pull-data", "ping", "ack-data" };
  uint8_t methods[] = { TAGOTIPS_METHOD_PUSH, TAGOTIPS_METHOD_PULL,
                         TAGOTIPS_METHOD_PING, TAGOTIPS_METHOD_ACK };

  for (int i = 0; i < 4; i++) {
    size_t pt_len = strlen(payloads[i]);
    uint8_t envelope[128];

    int32_t sealed = tagotips_seal(
      (const uint8_t *)payloads[i], pt_len,
      methods[i], (uint32_t)(i + 1),
      auth_hash, device_hash, key,
      envelope, sizeof(envelope));

    char msg[64];
    snprintf(msg, sizeof(msg), "method %d seal succeeds", methods[i]);
    ASSERT_TRUE(sealed > 0, msg);

    TagotipsHeader hdr;
    uint8_t method;
    uint8_t inner[128];
    int32_t opened = tagotips_open(
      envelope, (size_t)sealed,
      key, &hdr, &method, inner, sizeof(inner));

    snprintf(msg, sizeof(msg), "method %d open length", methods[i]);
    ASSERT_EQ(opened, (int32_t)pt_len, msg);

    snprintf(msg, sizeof(msg), "method %d round-trip method", methods[i]);
    ASSERT_EQ(method, methods[i], msg);

    snprintf(msg, sizeof(msg), "method %d round-trip data", methods[i]);
    ASSERT_TRUE(memcmp(inner, payloads[i], pt_len) == 0, msg);
  }
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void) {
  printf("Running TagoTiP/S crypto tests...\n\n");

  /* SHA-256 */
  test_sha256_empty();
  test_sha256_abc();

  /* Hash derivation */
  test_auth_hash_derivation();
  test_auth_hash_without_prefix();
  test_device_hash_derivation();

  /* Seal (spec vector) */
  test_seal_spec_envelope();

  /* Open (spec vector) */
  test_open_spec_envelope();

  /* Round-trip */
  test_round_trip();
  test_round_trip_empty_plaintext();
  test_all_methods_round_trip();

  /* Parse header */
  test_parse_header();

  /* Disambiguation */
  test_is_envelope();

  /* Error cases */
  test_wrong_key();
  test_tampered_header();
  test_tampered_ciphertext();
  test_tampered_tag();
  test_truncated_envelope();
  test_buffer_too_small();
  test_null_pointers();
  test_reserved_flags();
  test_invalid_method_seal();
  test_unsupported_cipher_on_open();
  test_unsupported_version_on_open();
  test_inner_too_large();

  /* Constants */
  test_constants();
  test_error_code_values();
  test_method_values();

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
