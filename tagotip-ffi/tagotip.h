/**
 * tagotip.h — C header for tagotip-ffi
 *
 * This header declares all public types and functions exposed by the
 * tagotip-ffi shared/static library. All language bindings include
 * this header (directly or via their FFI loader).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TAGOTIP_H
#define TAGOTIP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Constants
 * ----------------------------------------------------------------------- */

#define TAGOTIP_MAX_VARIABLES    100
#define TAGOTIP_MAX_META_PAIRS   32
#define TAGOTIP_MAX_TOTAL_META   512
#define TAGOTIP_MAX_FRAME_SIZE   16384
#define TAGOTIP_AUTH_HASH_LEN    16

/* -----------------------------------------------------------------------
 * Error codes (return values)
 * ----------------------------------------------------------------------- */

#define TAGOTIP_OK                       0
#define TAGOTIP_ERR_EMPTY_FRAME         -1
#define TAGOTIP_ERR_NUL_BYTE            -2
#define TAGOTIP_ERR_INVALID_METHOD      -3
#define TAGOTIP_ERR_INVALID_SEQ         -4
#define TAGOTIP_ERR_INVALID_AUTH        -5
#define TAGOTIP_ERR_INVALID_SERIAL      -6
#define TAGOTIP_ERR_MISSING_BODY        -7
#define TAGOTIP_ERR_INVALID_MODIFIER    -8
#define TAGOTIP_ERR_INVALID_VARIABLE_BLOCK -9
#define TAGOTIP_ERR_INVALID_VARIABLE    -10
#define TAGOTIP_ERR_INVALID_PASSTHROUGH -11
#define TAGOTIP_ERR_INVALID_METADATA    -12
#define TAGOTIP_ERR_INVALID_FIELD       -13
#define TAGOTIP_ERR_INVALID_ACK         -14
#define TAGOTIP_ERR_TOO_MANY_ITEMS      -15
#define TAGOTIP_ERR_FRAME_TOO_LARGE     -16
#define TAGOTIP_ERR_BUFFER_TOO_SMALL    -17
#define TAGOTIP_ERR_INVALID_INPUT       -18

/* -----------------------------------------------------------------------
 * Enums
 * ----------------------------------------------------------------------- */

typedef enum {
    TAGOTIP_METHOD_PUSH = 0,
    TAGOTIP_METHOD_PULL = 1,
    TAGOTIP_METHOD_PING = 2,
} TagotipMethod;

typedef enum {
    TAGOTIP_OPERATOR_NUMBER   = 0,
    TAGOTIP_OPERATOR_STRING   = 1,
    TAGOTIP_OPERATOR_BOOLEAN  = 2,
    TAGOTIP_OPERATOR_LOCATION = 3,
} TagotipOperator;

typedef enum {
    TAGOTIP_VALUE_NUMBER   = 0,
    TAGOTIP_VALUE_STRING   = 1,
    TAGOTIP_VALUE_BOOLEAN  = 2,
    TAGOTIP_VALUE_LOCATION = 3,
} TagotipValueTag;

typedef enum {
    TAGOTIP_ACK_STATUS_OK   = 0,
    TAGOTIP_ACK_STATUS_PONG = 1,
    TAGOTIP_ACK_STATUS_CMD  = 2,
    TAGOTIP_ACK_STATUS_ERR  = 3,
} TagotipAckStatus;

typedef enum {
    TAGOTIP_ACK_DETAIL_NONE      = 0,
    TAGOTIP_ACK_DETAIL_COUNT     = 1,
    TAGOTIP_ACK_DETAIL_VARIABLES = 2,
    TAGOTIP_ACK_DETAIL_COMMAND   = 3,
    TAGOTIP_ACK_DETAIL_ERROR     = 4,
    TAGOTIP_ACK_DETAIL_RAW       = 5,
} TagotipAckDetailTag;

typedef enum {
    TAGOTIP_ERROR_CODE_INVALID_TOKEN        = 0,
    TAGOTIP_ERROR_CODE_INVALID_METHOD       = 1,
    TAGOTIP_ERROR_CODE_INVALID_PAYLOAD      = 2,
    TAGOTIP_ERROR_CODE_INVALID_SEQ          = 3,
    TAGOTIP_ERROR_CODE_DEVICE_NOT_FOUND     = 4,
    TAGOTIP_ERROR_CODE_VARIABLE_NOT_FOUND   = 5,
    TAGOTIP_ERROR_CODE_RATE_LIMITED         = 6,
    TAGOTIP_ERROR_CODE_AUTH_FAILED          = 7,
    TAGOTIP_ERROR_CODE_UNSUPPORTED_VERSION  = 8,
    TAGOTIP_ERROR_CODE_PAYLOAD_TOO_LARGE    = 9,
    TAGOTIP_ERROR_CODE_SERVER_ERROR         = 10,
    TAGOTIP_ERROR_CODE_UNKNOWN              = 11,
} TagotipErrorCode;

typedef enum {
    TAGOTIP_PASSTHROUGH_HEX    = 0,
    TAGOTIP_PASSTHROUGH_BASE64 = 1,
} TagotipPassthroughEncoding;

typedef enum {
    TAGOTIP_PUSH_BODY_NONE        = 0,
    TAGOTIP_PUSH_BODY_STRUCTURED  = 1,
    TAGOTIP_PUSH_BODY_PASSTHROUGH = 2,
} TagotipPushBodyTag;

/* -----------------------------------------------------------------------
 * Structs
 * ----------------------------------------------------------------------- */

/** Borrowed string slice (pointer + length, NOT null-terminated). */
typedef struct {
    const uint8_t *ptr;
    size_t len;
} TagotipStr;

typedef struct {
    TagotipStr key;
    TagotipStr value;
} TagotipMetaPair;

typedef struct {
    TagotipValueTag tag;
    TagotipStr str_val;     /* Number or String value */
    uint8_t bool_val;       /* Boolean: 0 or 1 */
    TagotipStr lat;         /* Location latitude */
    TagotipStr lng;         /* Location longitude */
    TagotipStr alt;         /* Location altitude (optional, len=0 if absent) */
} TagotipValue;

typedef struct {
    TagotipStr name;
    TagotipOperator operator_;
    TagotipValue value;
    TagotipStr unit;
    TagotipStr timestamp;
    TagotipStr group;
    uint16_t meta_start;
    uint16_t meta_len;
} TagotipVariable;

typedef struct {
    TagotipPassthroughEncoding encoding;
    TagotipStr data;
} TagotipPassthroughBody;

typedef struct {
    TagotipMethod method;
    uint8_t has_seq;
    uint32_t seq;
    TagotipStr auth;
    TagotipStr serial;

    /* Push body */
    TagotipPushBodyTag push_body_tag;

    /* Structured push body */
    TagotipStr body_group;
    TagotipStr body_timestamp;
    uint16_t body_meta_start;
    uint16_t body_meta_len;
    uint16_t variables_len;
    TagotipVariable variables[TAGOTIP_MAX_VARIABLES];
    uint16_t meta_pool_len;
    TagotipMetaPair meta_pool[TAGOTIP_MAX_TOTAL_META];

    /* Passthrough push body */
    TagotipPassthroughBody passthrough;

    /* Pull body */
    uint8_t has_pull_body;
    uint16_t pull_variables_len;
    TagotipStr pull_variables[TAGOTIP_MAX_VARIABLES];
} TagotipUplinkFrame;

typedef struct {
    TagotipAckDetailTag tag;
    uint32_t count;
    TagotipStr text;
    TagotipErrorCode error_code;
} TagotipAckDetail;

typedef struct {
    uint8_t has_seq;
    uint32_t seq;
    TagotipAckStatus status;
    TagotipAckDetail detail;
} TagotipAckFrame;

/* -----------------------------------------------------------------------
 * Functions
 * ----------------------------------------------------------------------- */

/**
 * Parse an uplink frame.
 *
 * @param input_ptr  Pointer to UTF-8 input bytes.
 * @param input_len  Length of input in bytes.
 * @param out        Pointer to output frame struct (caller-allocated).
 * @return           0 on success, negative error code on failure.
 */
int32_t tagotip_parse_uplink(const uint8_t *input_ptr, size_t input_len,
                             TagotipUplinkFrame *out);

/**
 * Build an uplink frame into a buffer.
 *
 * @param frame    Pointer to a populated frame struct.
 * @param buf_ptr  Pointer to output buffer.
 * @param buf_len  Size of output buffer in bytes.
 * @return         Bytes written on success, negative error code on failure.
 */
int32_t tagotip_build_uplink(const TagotipUplinkFrame *frame,
                             uint8_t *buf_ptr, size_t buf_len);

/**
 * Parse an ACK (downlink) frame.
 *
 * @param input_ptr  Pointer to UTF-8 input bytes.
 * @param input_len  Length of input in bytes.
 * @param out        Pointer to output frame struct (caller-allocated).
 * @return           0 on success, negative error code on failure.
 */
int32_t tagotip_parse_ack(const uint8_t *input_ptr, size_t input_len,
                          TagotipAckFrame *out);

/**
 * Build an ACK frame into a buffer.
 *
 * @param frame    Pointer to a populated frame struct.
 * @param buf_ptr  Pointer to output buffer.
 * @param buf_len  Size of output buffer in bytes.
 * @return         Bytes written on success, negative error code on failure.
 */
int32_t tagotip_build_ack(const TagotipAckFrame *frame,
                          uint8_t *buf_ptr, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* TAGOTIP_H */
