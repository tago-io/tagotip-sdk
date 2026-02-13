/**
 * tagotips.h -- Pure C TagoTiP/S crypto envelope for Arduino/embedded.
 *
 * Standalone AES-128-CCM implementation with zero external dependencies.
 * Client-only: devices seal uplink frames and open downlink ACK envelopes.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TAGOTIPS_H
#define TAGOTIPS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------- */

#define TAGOTIPS_HEADER_SIZE       21
#define TAGOTIPS_HASH_SIZE          8
#define TAGOTIPS_KEY_SIZE          16
#define TAGOTIPS_TAG_SIZE           8
#define TAGOTIPS_NONCE_SIZE        13
#define TAGOTIPS_MAX_INNER_FRAME 16384
#define TAGOTIPS_MAX_ENVELOPE    16413  /* HEADER + MAX_INNER + TAG */

/* -----------------------------------------------------------------------
 * Error codes
 * ----------------------------------------------------------------------- */

#define TAGOTIPS_OK                        0
#define TAGOTIPS_ERR_NULL_PTR             -1
#define TAGOTIPS_ERR_BUFFER_TOO_SMALL     -2
#define TAGOTIPS_ERR_ENVELOPE_TOO_SHORT   -3
#define TAGOTIPS_ERR_DECRYPTION_FAILED    -5
#define TAGOTIPS_ERR_UNSUPPORTED_CIPHER   -6
#define TAGOTIPS_ERR_UNSUPPORTED_VERSION  -7
#define TAGOTIPS_ERR_INVALID_METHOD       -8
#define TAGOTIPS_ERR_INNER_TOO_LARGE      -9
#define TAGOTIPS_ERR_RESERVED_FLAGS       -10
#define TAGOTIPS_ERR_INVALID_HEX         -11

/* -----------------------------------------------------------------------
 * Envelope methods
 * ----------------------------------------------------------------------- */

#define TAGOTIPS_METHOD_PUSH  0
#define TAGOTIPS_METHOD_PULL  1
#define TAGOTIPS_METHOD_PING  2
#define TAGOTIPS_METHOD_ACK   3

/* -----------------------------------------------------------------------
 * Types
 * ----------------------------------------------------------------------- */

typedef struct {
  uint8_t  flags;
  uint32_t counter;
  uint8_t  auth_hash[8];
  uint8_t  device_hash[8];
} TagotipsHeader;

/* -----------------------------------------------------------------------
 * Hash derivation
 * ----------------------------------------------------------------------- */

/**
 * Derive the 8-byte authorization hash from a token string.
 * The "at" prefix is stripped if present. SHA-256 of the hex part,
 * truncated to 8 bytes.
 */
void tagotips_derive_auth_hash(const char *token, uint8_t out[8]);

/**
 * Derive the 8-byte device hash from a serial string.
 * SHA-256 of the serial, truncated to 8 bytes.
 */
void tagotips_derive_device_hash(const char *serial, uint8_t out[8]);

/* -----------------------------------------------------------------------
 * Seal (encrypt uplink)
 * ----------------------------------------------------------------------- */

/**
 * Encrypt an inner frame into a TagoTiP/S envelope.
 *
 * Returns bytes written to out_buf on success, or a negative error code.
 */
int32_t tagotips_seal(
  const uint8_t *inner_frame, size_t inner_len,
  uint8_t method, uint32_t counter,
  const uint8_t auth_hash[8], const uint8_t device_hash[8],
  const uint8_t key[16],
  uint8_t *out_buf, size_t out_buf_len);

/* -----------------------------------------------------------------------
 * Open (decrypt envelope)
 * ----------------------------------------------------------------------- */

/**
 * Decrypt a TagoTiP/S envelope.
 *
 * Returns inner frame length on success, or a negative error code.
 * On authentication failure the output buffer is zeroed.
 */
int32_t tagotips_open(
  const uint8_t *envelope, size_t envelope_len,
  const uint8_t key[16],
  TagotipsHeader *out_header, uint8_t *out_method,
  uint8_t *out_inner, size_t out_inner_len);

/* -----------------------------------------------------------------------
 * Parse header (no decryption)
 * ----------------------------------------------------------------------- */

/**
 * Parse just the 21-byte envelope header for routing (pre-decryption).
 * Returns 0 on success, or a negative error code.
 */
int32_t tagotips_parse_header(
  const uint8_t *envelope, size_t envelope_len,
  TagotipsHeader *out);

/* -----------------------------------------------------------------------
 * Disambiguation
 * ----------------------------------------------------------------------- */

/**
 * Returns 1 if data looks like a TagoTiP/S envelope, 0 if plaintext
 * ACK (starts with 'A' = 0x41) or empty.
 */
int tagotips_is_envelope(const uint8_t *data, size_t len);

/* -----------------------------------------------------------------------
 * Key derivation (HMAC-SHA256)
 * ----------------------------------------------------------------------- */

/**
 * Derive an encryption key from a token and serial using HMAC-SHA256.
 * The "at" prefix is stripped from the token. The remaining hex string
 * (UTF-8) is the HMAC key; the serial (UTF-8) is the HMAC message.
 * Returns 0 on success, or a negative error code.
 */
int32_t tagotips_derive_key(const char *token, const char *serial,
                            uint8_t *out_key, size_t key_len);

/* -----------------------------------------------------------------------
 * Hex utilities
 * ----------------------------------------------------------------------- */

/**
 * Decode a hex string into bytes.
 * hex_len must be even. Returns 0 on success, TAGOTIPS_ERR_INVALID_HEX
 * if the string has odd length or contains non-hex characters.
 */
int32_t tagotips_hex_to_bytes(const char *hex, size_t hex_len,
                              uint8_t *out_buf, size_t out_buf_len);

/**
 * Encode bytes as a lowercase hex string (null-terminated).
 * out_buf must have room for data_len * 2 + 1 bytes.
 * Returns 0 on success, or TAGOTIPS_ERR_BUFFER_TOO_SMALL.
 */
int32_t tagotips_bytes_to_hex(const uint8_t *data, size_t data_len,
                              char *out_buf, size_t out_buf_len);

#ifdef __cplusplus
}
#endif

#endif /* TAGOTIPS_H */
