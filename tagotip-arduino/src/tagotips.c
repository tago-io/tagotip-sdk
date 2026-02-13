/**
 * tagotips.c -- Pure C TagoTiP/S crypto envelope for Arduino/embedded.
 *
 * Self-contained SHA-256, AES-128, and AES-128-CCM implementation.
 * Zero external dependencies, zero heap allocation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tagotips.h"
#include <string.h>

/* =========================================================================
 * Utilities
 * ========================================================================= */

static void xor_block(uint8_t *dst, const uint8_t *src, size_t len) {
  for (size_t i = 0; i < len; i++) {
    dst[i] ^= src[i];
  }
}

static int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

static void secure_zero(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  for (size_t i = 0; i < len; i++) {
    p[i] = 0;
  }
}

/* =========================================================================
 * SHA-256 (FIPS 180-4)
 * ========================================================================= */

static const uint32_t SHA256_K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR32(x, n)  ((x) >> (n))

#define SHA256_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_SIGMA0(x)    (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define SHA256_SIGMA1(x)    (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SHA256_sigma0(x)    (ROTR32(x,  7) ^ ROTR32(x, 18) ^ SHR32(x,  3))
#define SHA256_sigma1(x)    (ROTR32(x, 17) ^ ROTR32(x, 19) ^ SHR32(x, 10))

typedef struct {
  uint32_t state[8];
  uint8_t  buf[64];
  uint64_t total;
} sha256_ctx;

static void sha256_init(sha256_ctx *ctx) {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->total = 0;
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64]) {
  uint32_t w[16];
  uint32_t a, b, c, d, e, f, g, h;

  a = ctx->state[0]; b = ctx->state[1];
  c = ctx->state[2]; d = ctx->state[3];
  e = ctx->state[4]; f = ctx->state[5];
  g = ctx->state[6]; h = ctx->state[7];

  for (int i = 0; i < 64; i++) {
    uint32_t w_i;
    if (i < 16) {
      w_i = ((uint32_t)block[i * 4] << 24)
          | ((uint32_t)block[i * 4 + 1] << 16)
          | ((uint32_t)block[i * 4 + 2] << 8)
          | ((uint32_t)block[i * 4 + 3]);
      w[i] = w_i;
    } else {
      w_i = SHA256_sigma1(w[(i - 2) & 15])
          + w[(i - 7) & 15]
          + SHA256_sigma0(w[(i - 15) & 15])
          + w[(i - 16) & 15];
      w[i & 15] = w_i;
    }

    uint32_t t1 = h + SHA256_SIGMA1(e) + SHA256_CH(e, f, g) + SHA256_K[i] + w_i;
    uint32_t t2 = SHA256_SIGMA0(a) + SHA256_MAJ(a, b, c);
    h = g; g = f; f = e;
    e = d + t1;
    d = c; c = b; b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a; ctx->state[1] += b;
  ctx->state[2] += c; ctx->state[3] += d;
  ctx->state[4] += e; ctx->state[5] += f;
  ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
  size_t buffered = (size_t)(ctx->total & 63);
  ctx->total += len;

  if (buffered > 0) {
    size_t fill = 64 - buffered;
    if (len < fill) {
      memcpy(ctx->buf + buffered, data, len);
      return;
    }
    memcpy(ctx->buf + buffered, data, fill);
    sha256_transform(ctx, ctx->buf);
    data += fill;
    len -= fill;
  }

  while (len >= 64) {
    sha256_transform(ctx, data);
    data += 64;
    len -= 64;
  }

  if (len > 0) {
    memcpy(ctx->buf, data, len);
  }
}

static void sha256_final(sha256_ctx *ctx, uint8_t digest[32]) {
  uint64_t total_bits = ctx->total * 8;
  size_t buffered = (size_t)(ctx->total & 63);

  ctx->buf[buffered++] = 0x80;

  if (buffered > 56) {
    memset(ctx->buf + buffered, 0, 64 - buffered);
    sha256_transform(ctx, ctx->buf);
    buffered = 0;
  }

  memset(ctx->buf + buffered, 0, 56 - buffered);

  ctx->buf[56] = (uint8_t)(total_bits >> 56);
  ctx->buf[57] = (uint8_t)(total_bits >> 48);
  ctx->buf[58] = (uint8_t)(total_bits >> 40);
  ctx->buf[59] = (uint8_t)(total_bits >> 32);
  ctx->buf[60] = (uint8_t)(total_bits >> 24);
  ctx->buf[61] = (uint8_t)(total_bits >> 16);
  ctx->buf[62] = (uint8_t)(total_bits >> 8);
  ctx->buf[63] = (uint8_t)(total_bits);

  sha256_transform(ctx, ctx->buf);

  for (int i = 0; i < 8; i++) {
    digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
    digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
    digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
    digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
  }
}

static void sha256(const uint8_t *data, size_t len, uint8_t digest[32]) {
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, digest);
}

/* =========================================================================
 * AES-128 Encrypt (FIPS 197) -- S-box only, forward cipher
 * ========================================================================= */

static const uint8_t AES_SBOX[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t AES_RCON[10] = {
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void aes128_key_expansion(const uint8_t key[16], uint8_t round_keys[176]) {
  memcpy(round_keys, key, 16);

  for (int i = 4; i < 44; i++) {
    uint8_t tmp[4];
    memcpy(tmp, round_keys + (i - 1) * 4, 4);

    if (i % 4 == 0) {
      /* RotWord */
      uint8_t t = tmp[0];
      tmp[0] = tmp[1];
      tmp[1] = tmp[2];
      tmp[2] = tmp[3];
      tmp[3] = t;
      /* SubWord */
      tmp[0] = AES_SBOX[tmp[0]];
      tmp[1] = AES_SBOX[tmp[1]];
      tmp[2] = AES_SBOX[tmp[2]];
      tmp[3] = AES_SBOX[tmp[3]];
      /* XOR Rcon */
      tmp[0] ^= AES_RCON[(i / 4) - 1];
    }

    round_keys[i * 4 + 0] = round_keys[(i - 4) * 4 + 0] ^ tmp[0];
    round_keys[i * 4 + 1] = round_keys[(i - 4) * 4 + 1] ^ tmp[1];
    round_keys[i * 4 + 2] = round_keys[(i - 4) * 4 + 2] ^ tmp[2];
    round_keys[i * 4 + 3] = round_keys[(i - 4) * 4 + 3] ^ tmp[3];
  }
}

static void aes128_encrypt_block(const uint8_t round_keys[176], const uint8_t in[16], uint8_t out[16]) {
  uint8_t s[16];
  memcpy(s, in, 16);

  /* AddRoundKey (round 0) */
  xor_block(s, round_keys, 16);

  for (int round = 1; round <= 10; round++) {
    /* SubBytes */
    for (int i = 0; i < 16; i++) {
      s[i] = AES_SBOX[s[i]];
    }

    /* ShiftRows */
    uint8_t t;
    /* Row 1: shift left 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    /* Row 2: shift left 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* Row 3: shift left 3 */
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

    /* MixColumns (skip on last round) */
    if (round < 10) {
      for (int c = 0; c < 4; c++) {
        int base = c * 4;
        uint8_t a0 = s[base], a1 = s[base + 1], a2 = s[base + 2], a3 = s[base + 3];
        uint8_t x0 = xtime(a0), x1 = xtime(a1), x2 = xtime(a2), x3 = xtime(a3);
        s[base]     = x0 ^ a1 ^ x1 ^ a2 ^ a3;
        s[base + 1] = a0 ^ x1 ^ a2 ^ x2 ^ a3;
        s[base + 2] = a0 ^ a1 ^ x2 ^ a3 ^ x3;
        s[base + 3] = a0 ^ x0 ^ a1 ^ a2 ^ x3;
      }
    }

    /* AddRoundKey */
    xor_block(s, round_keys + round * 16, 16);
  }

  memcpy(out, s, 16);
}

/* =========================================================================
 * AES-128-CCM (NIST SP 800-38C)
 *
 * Parameters: tag=8B, L=2, nonce=13B, max plaintext=65535B
 * ========================================================================= */

/*
 * Format B0 block for CBC-MAC.
 * B0 = [flags] [nonce:13B] [plaintext_len:2B BE]
 * flags = 0x59 = Adata(1) | ((t-2)/2)<<3 | (q-1)
 *       = 0x40 | 0x18 | 0x01
 */
static void ccm_format_b0(const uint8_t nonce[13], size_t plaintext_len, uint8_t b0[16]) {
  b0[0] = 0x59;
  memcpy(b0 + 1, nonce, 13);
  b0[14] = (uint8_t)(plaintext_len >> 8);
  b0[15] = (uint8_t)(plaintext_len);
}

/*
 * Format counter block Ai for CTR mode.
 * Ai = [flags=0x01] [nonce:13B] [counter:2B BE]
 */
static void ccm_format_ctr(const uint8_t nonce[13], uint16_t ctr_val, uint8_t ai[16]) {
  ai[0] = 0x01;
  memcpy(ai + 1, nonce, 13);
  ai[14] = (uint8_t)(ctr_val >> 8);
  ai[15] = (uint8_t)(ctr_val);
}

/*
 * CBC-MAC over B0, AAD, and plaintext.
 * Returns the 16-byte CBC-MAC value (tag is first 8 bytes).
 */
static void ccm_cbc_mac(
  const uint8_t round_keys[176],
  const uint8_t nonce[13],
  const uint8_t *aad, size_t aad_len,
  const uint8_t *plaintext, size_t pt_len,
  uint8_t mac[16]
) {
  uint8_t block[16];

  /* B0 */
  ccm_format_b0(nonce, pt_len, block);
  uint8_t y[16];
  aes128_encrypt_block(round_keys, block, y);

  /* AAD: [aad_len:2B BE] [aad] [zero-pad to 16B boundary] */
  if (aad_len > 0) {
    memset(block, 0, 16);
    block[0] = (uint8_t)(aad_len >> 8);
    block[1] = (uint8_t)(aad_len);

    /* Fill first block with up to 14 bytes of AAD */
    size_t first_chunk = aad_len < 14 ? aad_len : 14;
    memcpy(block + 2, aad, first_chunk);

    xor_block(y, block, 16);
    aes128_encrypt_block(round_keys, y, y);

    /* Remaining AAD in full 16-byte blocks */
    size_t aad_offset = first_chunk;
    while (aad_offset < aad_len) {
      memset(block, 0, 16);
      size_t chunk = aad_len - aad_offset;
      if (chunk > 16) chunk = 16;
      memcpy(block, aad + aad_offset, chunk);

      xor_block(y, block, 16);
      aes128_encrypt_block(round_keys, y, y);

      aad_offset += chunk;
    }
  }

  /* Plaintext in 16-byte blocks (zero-padded) */
  size_t pt_offset = 0;
  while (pt_offset < pt_len) {
    memset(block, 0, 16);
    size_t chunk = pt_len - pt_offset;
    if (chunk > 16) chunk = 16;
    memcpy(block, plaintext + pt_offset, chunk);

    xor_block(y, block, 16);
    aes128_encrypt_block(round_keys, y, y);

    pt_offset += chunk;
  }

  memcpy(mac, y, 16);
}

/*
 * AES-128-CCM encrypt.
 * Input:  plaintext (pt_len bytes)
 * Output: ciphertext || tag (pt_len + 8 bytes)
 */
static void aes128_ccm_encrypt(
  const uint8_t round_keys[176],
  const uint8_t nonce[13],
  const uint8_t *aad, size_t aad_len,
  const uint8_t *plaintext, size_t pt_len,
  uint8_t *output
) {
  /* Step 1: CBC-MAC */
  uint8_t mac[16];
  ccm_cbc_mac(round_keys, nonce, aad, aad_len, plaintext, pt_len, mac);

  /* Step 2: CTR encryption */
  uint8_t ai[16], si[16];

  /* Encrypt tag with A0 */
  ccm_format_ctr(nonce, 0, ai);
  aes128_encrypt_block(round_keys, ai, si);
  uint8_t encrypted_tag[8];
  for (int i = 0; i < 8; i++) {
    encrypted_tag[i] = mac[i] ^ si[i];
  }

  /* Encrypt plaintext with A1, A2, ... */
  size_t offset = 0;
  uint16_t ctr = 1;
  while (offset < pt_len) {
    ccm_format_ctr(nonce, ctr, ai);
    aes128_encrypt_block(round_keys, ai, si);

    size_t chunk = pt_len - offset;
    if (chunk > 16) chunk = 16;
    for (size_t i = 0; i < chunk; i++) {
      output[offset + i] = plaintext[offset + i] ^ si[i];
    }

    offset += chunk;
    ctr++;
  }

  /* Append encrypted tag */
  memcpy(output + pt_len, encrypted_tag, 8);
}

/*
 * AES-128-CCM decrypt.
 * Input:  ciphertext || tag (ct_len bytes, where ct_len includes 8-byte tag)
 * Output: plaintext (ct_len - 8 bytes)
 * Returns 0 on success, -1 on authentication failure (plaintext is zeroed).
 */
static int aes128_ccm_decrypt(
  const uint8_t round_keys[176],
  const uint8_t nonce[13],
  const uint8_t *aad, size_t aad_len,
  const uint8_t *input, size_t input_len,
  uint8_t *plaintext
) {
  if (input_len < 8) return -1;
  size_t pt_len = input_len - 8;

  uint8_t ai[16], si[16];

  /* Recover tag: decrypt with A0 */
  ccm_format_ctr(nonce, 0, ai);
  aes128_encrypt_block(round_keys, ai, si);
  uint8_t recovered_tag[8];
  for (int i = 0; i < 8; i++) {
    recovered_tag[i] = input[pt_len + i] ^ si[i];
  }

  /* CTR decrypt plaintext with A1, A2, ... */
  size_t offset = 0;
  uint16_t ctr = 1;
  while (offset < pt_len) {
    ccm_format_ctr(nonce, ctr, ai);
    aes128_encrypt_block(round_keys, ai, si);

    size_t chunk = pt_len - offset;
    if (chunk > 16) chunk = 16;
    for (size_t i = 0; i < chunk; i++) {
      plaintext[offset + i] = input[offset + i] ^ si[i];
    }

    offset += chunk;
    ctr++;
  }

  /* Verify: CBC-MAC over AAD + decrypted plaintext */
  uint8_t mac[16];
  ccm_cbc_mac(round_keys, nonce, aad, aad_len, plaintext, pt_len, mac);

  if (!constant_time_compare(mac, recovered_tag, 8)) {
    secure_zero(plaintext, pt_len);
    return -1;
  }

  return 0;
}

/* =========================================================================
 * Envelope helpers
 * ========================================================================= */

#define FLAGS_CIPHER_SHIFT  5
#define FLAGS_CIPHER_MASK   0xE0
#define FLAGS_VERSION_SHIFT 3
#define FLAGS_VERSION_MASK  0x18
#define FLAGS_METHOD_MASK   0x07
#define RESERVED_FLAGS      0x41

static int32_t flags_encode(uint8_t cipher, uint8_t version, uint8_t method, uint8_t *out) {
  if (cipher > 4) return TAGOTIPS_ERR_UNSUPPORTED_CIPHER;
  if (version > 3) return TAGOTIPS_ERR_UNSUPPORTED_VERSION;
  if (method > 3) return TAGOTIPS_ERR_INVALID_METHOD;

  uint8_t byte = (cipher << FLAGS_CIPHER_SHIFT) | (version << FLAGS_VERSION_SHIFT) | method;
  if (byte == RESERVED_FLAGS) return TAGOTIPS_ERR_RESERVED_FLAGS;
  *out = byte;
  return TAGOTIPS_OK;
}

static int32_t flags_decode(uint8_t byte, uint8_t *cipher, uint8_t *version, uint8_t *method) {
  if (byte == RESERVED_FLAGS) return TAGOTIPS_ERR_RESERVED_FLAGS;

  uint8_t c = (byte & FLAGS_CIPHER_MASK) >> FLAGS_CIPHER_SHIFT;
  uint8_t v = (byte & FLAGS_VERSION_MASK) >> FLAGS_VERSION_SHIFT;
  uint8_t m = byte & FLAGS_METHOD_MASK;

  if (c > 4) return TAGOTIPS_ERR_UNSUPPORTED_CIPHER;
  if (m > 3) return TAGOTIPS_ERR_INVALID_METHOD;

  *cipher = c;
  *version = v;
  *method = m;
  return TAGOTIPS_OK;
}

static void header_to_bytes(const TagotipsHeader *hdr, uint8_t out[21]) {
  out[0] = hdr->flags;
  out[1] = (uint8_t)(hdr->counter >> 24);
  out[2] = (uint8_t)(hdr->counter >> 16);
  out[3] = (uint8_t)(hdr->counter >> 8);
  out[4] = (uint8_t)(hdr->counter);
  memcpy(out + 5, hdr->auth_hash, 8);
  memcpy(out + 13, hdr->device_hash, 8);
}

static int32_t header_from_bytes(const uint8_t *data, size_t len, TagotipsHeader *hdr) {
  if (len < TAGOTIPS_HEADER_SIZE) return TAGOTIPS_ERR_ENVELOPE_TOO_SHORT;

  hdr->flags = data[0];
  hdr->counter = ((uint32_t)data[1] << 24)
               | ((uint32_t)data[2] << 16)
               | ((uint32_t)data[3] << 8)
               | ((uint32_t)data[4]);
  memcpy(hdr->auth_hash, data + 5, 8);
  memcpy(hdr->device_hash, data + 13, 8);
  return TAGOTIPS_OK;
}

/*
 * Construct 13-byte CCM nonce:
 * [Flags:1] [00 00 00 00] [DevHash[:4]:4] [Counter:4 BE]
 */
static void construct_nonce(uint8_t flags, const uint8_t device_hash[8], uint32_t counter, uint8_t nonce[13]) {
  nonce[0] = flags;
  nonce[1] = 0; nonce[2] = 0; nonce[3] = 0; nonce[4] = 0;
  memcpy(nonce + 5, device_hash, 4);
  nonce[9]  = (uint8_t)(counter >> 24);
  nonce[10] = (uint8_t)(counter >> 16);
  nonce[11] = (uint8_t)(counter >> 8);
  nonce[12] = (uint8_t)(counter);
}

/* =========================================================================
 * Public API
 * ========================================================================= */

void tagotips_derive_auth_hash(const char *token, uint8_t out[8]) {
  const char *hex_part = token;
  if (token[0] == 'a' && token[1] == 't') {
    hex_part = token + 2;
  }

  uint8_t digest[32];
  sha256((const uint8_t *)hex_part, strlen(hex_part), digest);
  memcpy(out, digest, 8);
  secure_zero(digest, 32);
}

void tagotips_derive_device_hash(const char *serial, uint8_t out[8]) {
  uint8_t digest[32];
  sha256((const uint8_t *)serial, strlen(serial), digest);
  memcpy(out, digest, 8);
  secure_zero(digest, 32);
}

int32_t tagotips_seal(
  const uint8_t *inner_frame, size_t inner_len,
  uint8_t method, uint32_t counter,
  const uint8_t auth_hash[8], const uint8_t device_hash[8],
  const uint8_t key[16],
  uint8_t *out_buf, size_t out_buf_len
) {
  if (!inner_frame || !auth_hash || !device_hash || !key || !out_buf) {
    return TAGOTIPS_ERR_NULL_PTR;
  }
  if (inner_len > TAGOTIPS_MAX_INNER_FRAME) {
    return TAGOTIPS_ERR_INNER_TOO_LARGE;
  }

  size_t envelope_len = TAGOTIPS_HEADER_SIZE + inner_len + TAGOTIPS_TAG_SIZE;
  if (out_buf_len < envelope_len) {
    return TAGOTIPS_ERR_BUFFER_TOO_SMALL;
  }

  /* Encode flags (cipher=0 AES-128-CCM, version=0) */
  uint8_t flags;
  int32_t rc = flags_encode(0, 0, method, &flags);
  if (rc != TAGOTIPS_OK) return rc;

  /* Build header */
  TagotipsHeader hdr;
  hdr.flags = flags;
  hdr.counter = counter;
  memcpy(hdr.auth_hash, auth_hash, 8);
  memcpy(hdr.device_hash, device_hash, 8);

  uint8_t aad[TAGOTIPS_HEADER_SIZE];
  header_to_bytes(&hdr, aad);

  /* Construct nonce */
  uint8_t nonce[TAGOTIPS_NONCE_SIZE];
  construct_nonce(flags, device_hash, counter, nonce);

  /* Key expansion */
  uint8_t round_keys[176];
  aes128_key_expansion(key, round_keys);

  /* Write header to output */
  memcpy(out_buf, aad, TAGOTIPS_HEADER_SIZE);

  /* CCM encrypt (writes ciphertext + tag after header) */
  aes128_ccm_encrypt(round_keys, nonce, aad, TAGOTIPS_HEADER_SIZE,
                     inner_frame, inner_len, out_buf + TAGOTIPS_HEADER_SIZE);

  secure_zero(round_keys, 176);

  return (int32_t)envelope_len;
}

int32_t tagotips_open(
  const uint8_t *envelope, size_t envelope_len,
  const uint8_t key[16],
  TagotipsHeader *out_header, uint8_t *out_method,
  uint8_t *out_inner, size_t out_inner_len
) {
  if (!envelope || !key || !out_header || !out_method || !out_inner) {
    return TAGOTIPS_ERR_NULL_PTR;
  }
  if (envelope_len < TAGOTIPS_HEADER_SIZE + TAGOTIPS_TAG_SIZE) {
    return TAGOTIPS_ERR_ENVELOPE_TOO_SHORT;
  }

  /* Parse header */
  int32_t rc = header_from_bytes(envelope, envelope_len, out_header);
  if (rc != TAGOTIPS_OK) return rc;

  /* Decode flags */
  uint8_t cipher, version, method;
  rc = flags_decode(out_header->flags, &cipher, &version, &method);
  if (rc != TAGOTIPS_OK) return rc;

  if (version != 0) return TAGOTIPS_ERR_UNSUPPORTED_VERSION;
  if (cipher != 0) return TAGOTIPS_ERR_UNSUPPORTED_CIPHER;

  *out_method = method;

  /* Ciphertext + tag */
  const uint8_t *ct_with_tag = envelope + TAGOTIPS_HEADER_SIZE;
  size_t ct_with_tag_len = envelope_len - TAGOTIPS_HEADER_SIZE;

  if (ct_with_tag_len < TAGOTIPS_TAG_SIZE) {
    return TAGOTIPS_ERR_ENVELOPE_TOO_SHORT;
  }

  size_t pt_len = ct_with_tag_len - TAGOTIPS_TAG_SIZE;
  if (out_inner_len < pt_len) {
    return TAGOTIPS_ERR_BUFFER_TOO_SMALL;
  }

  /* Construct nonce */
  uint8_t nonce[TAGOTIPS_NONCE_SIZE];
  construct_nonce(out_header->flags, out_header->device_hash, out_header->counter, nonce);

  /* Key expansion */
  uint8_t round_keys[176];
  aes128_key_expansion(key, round_keys);

  /* AAD is the header bytes */
  const uint8_t *aad = envelope;

  /* CCM decrypt */
  int decrypt_ok = aes128_ccm_decrypt(round_keys, nonce, aad, TAGOTIPS_HEADER_SIZE,
                                      ct_with_tag, ct_with_tag_len, out_inner);

  secure_zero(round_keys, 176);

  if (decrypt_ok != 0) {
    return TAGOTIPS_ERR_DECRYPTION_FAILED;
  }

  return (int32_t)pt_len;
}

int32_t tagotips_parse_header(
  const uint8_t *envelope, size_t envelope_len,
  TagotipsHeader *out
) {
  if (!envelope || !out) return TAGOTIPS_ERR_NULL_PTR;

  int32_t rc = header_from_bytes(envelope, envelope_len, out);
  if (rc != TAGOTIPS_OK) return rc;

  /* Validate flags */
  uint8_t cipher, version, method;
  return flags_decode(out->flags, &cipher, &version, &method);
}

int tagotips_is_envelope(const uint8_t *data, size_t len) {
  if (!data || len == 0) return 0;
  return data[0] != RESERVED_FLAGS ? 1 : 0;
}
