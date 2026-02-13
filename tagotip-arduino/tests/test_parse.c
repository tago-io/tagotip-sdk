/**
 * test_parse.c — Standalone C test for TagoTiP codec.
 *
 * Compile:
 *   cc -o test_parse tests/test_parse.c -I src
 *
 * This test verifies that the C header compiles correctly and that
 * all types and constants are accessible. It does NOT link against
 * the FFI library (that requires building the Rust crate first).
 */

#include <stdio.h>
#include <string.h>

#include "tagotip.h"

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

/* =========================================================================
 * Constants
 * ========================================================================= */

void test_constants(void) {
    ASSERT_EQ(TAGOTIP_MAX_VARIABLES, 100, "MAX_VARIABLES");
    ASSERT_EQ(TAGOTIP_MAX_META_PAIRS, 32, "MAX_META_PAIRS");
    ASSERT_EQ(TAGOTIP_MAX_TOTAL_META, 512, "MAX_TOTAL_META");
    ASSERT_EQ(TAGOTIP_MAX_FRAME_SIZE, 16384, "MAX_FRAME_SIZE");
}

/* =========================================================================
 * Error codes (all 18 + OK)
 * ========================================================================= */

void test_error_codes(void) {
    ASSERT_EQ(TAGOTIP_OK, 0, "TAGOTIP_OK");
    ASSERT_EQ(TAGOTIP_ERR_EMPTY_FRAME, -1, "ERR_EMPTY_FRAME");
    ASSERT_EQ(TAGOTIP_ERR_NUL_BYTE, -2, "ERR_NUL_BYTE");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_METHOD, -3, "ERR_INVALID_METHOD");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_SEQ, -4, "ERR_INVALID_SEQ");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_AUTH, -5, "ERR_INVALID_AUTH");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_SERIAL, -6, "ERR_INVALID_SERIAL");
    ASSERT_EQ(TAGOTIP_ERR_MISSING_BODY, -7, "ERR_MISSING_BODY");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_MODIFIER, -8, "ERR_INVALID_MODIFIER");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_VARIABLE_BLOCK, -9, "ERR_INVALID_VARIABLE_BLOCK");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_VARIABLE, -10, "ERR_INVALID_VARIABLE");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_PASSTHROUGH, -11, "ERR_INVALID_PASSTHROUGH");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_METADATA, -12, "ERR_INVALID_METADATA");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_FIELD, -13, "ERR_INVALID_FIELD");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_ACK, -14, "ERR_INVALID_ACK");
    ASSERT_EQ(TAGOTIP_ERR_TOO_MANY_ITEMS, -15, "ERR_TOO_MANY_ITEMS");
    ASSERT_EQ(TAGOTIP_ERR_FRAME_TOO_LARGE, -16, "ERR_FRAME_TOO_LARGE");
    ASSERT_EQ(TAGOTIP_ERR_BUFFER_TOO_SMALL, -17, "ERR_BUFFER_TOO_SMALL");
    ASSERT_EQ(TAGOTIP_ERR_INVALID_INPUT, -18, "ERR_INVALID_INPUT");
}

/* =========================================================================
 * All method values
 * ========================================================================= */

void test_all_method_values(void) {
    ASSERT_EQ(TAGOTIP_METHOD_PUSH, 0, "METHOD_PUSH");
    ASSERT_EQ(TAGOTIP_METHOD_PULL, 1, "METHOD_PULL");
    ASSERT_EQ(TAGOTIP_METHOD_PING, 2, "METHOD_PING");
}

/* =========================================================================
 * All operator values
 * ========================================================================= */

void test_all_operator_values(void) {
    ASSERT_EQ(TAGOTIP_OPERATOR_NUMBER, 0, "OPERATOR_NUMBER");
    ASSERT_EQ(TAGOTIP_OPERATOR_STRING, 1, "OPERATOR_STRING");
    ASSERT_EQ(TAGOTIP_OPERATOR_BOOLEAN, 2, "OPERATOR_BOOLEAN");
    ASSERT_EQ(TAGOTIP_OPERATOR_LOCATION, 3, "OPERATOR_LOCATION");
}

/* =========================================================================
 * All value tag values
 * ========================================================================= */

void test_all_value_tag_values(void) {
    ASSERT_EQ(TAGOTIP_VALUE_NUMBER, 0, "VALUE_NUMBER");
    ASSERT_EQ(TAGOTIP_VALUE_STRING, 1, "VALUE_STRING");
    ASSERT_EQ(TAGOTIP_VALUE_BOOLEAN, 2, "VALUE_BOOLEAN");
    ASSERT_EQ(TAGOTIP_VALUE_LOCATION, 3, "VALUE_LOCATION");
}

/* =========================================================================
 * All ACK status values
 * ========================================================================= */

void test_all_ack_status_values(void) {
    ASSERT_EQ(TAGOTIP_ACK_STATUS_OK, 0, "ACK_STATUS_OK");
    ASSERT_EQ(TAGOTIP_ACK_STATUS_PONG, 1, "ACK_STATUS_PONG");
    ASSERT_EQ(TAGOTIP_ACK_STATUS_CMD, 2, "ACK_STATUS_CMD");
    ASSERT_EQ(TAGOTIP_ACK_STATUS_ERR, 3, "ACK_STATUS_ERR");
}

/* =========================================================================
 * All ACK detail tag values
 * ========================================================================= */

void test_all_ack_detail_tag_values(void) {
    ASSERT_EQ(TAGOTIP_ACK_DETAIL_NONE, 0, "ACK_DETAIL_NONE");
    ASSERT_EQ(TAGOTIP_ACK_DETAIL_COUNT, 1, "ACK_DETAIL_COUNT");
    ASSERT_EQ(TAGOTIP_ACK_DETAIL_VARIABLES, 2, "ACK_DETAIL_VARIABLES");
    ASSERT_EQ(TAGOTIP_ACK_DETAIL_COMMAND, 3, "ACK_DETAIL_COMMAND");
    ASSERT_EQ(TAGOTIP_ACK_DETAIL_ERROR, 4, "ACK_DETAIL_ERROR");
    ASSERT_EQ(TAGOTIP_ACK_DETAIL_RAW, 5, "ACK_DETAIL_RAW");
}

/* =========================================================================
 * All error code values (12 codes)
 * ========================================================================= */

void test_all_error_code_values(void) {
    ASSERT_EQ(TAGOTIP_ERROR_CODE_INVALID_TOKEN, 0, "ERROR_CODE_INVALID_TOKEN");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_INVALID_METHOD, 1, "ERROR_CODE_INVALID_METHOD");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_INVALID_PAYLOAD, 2, "ERROR_CODE_INVALID_PAYLOAD");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_INVALID_SEQ, 3, "ERROR_CODE_INVALID_SEQ");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_DEVICE_NOT_FOUND, 4, "ERROR_CODE_DEVICE_NOT_FOUND");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_VARIABLE_NOT_FOUND, 5, "ERROR_CODE_VARIABLE_NOT_FOUND");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_RATE_LIMITED, 6, "ERROR_CODE_RATE_LIMITED");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_AUTH_FAILED, 7, "ERROR_CODE_AUTH_FAILED");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_UNSUPPORTED_VERSION, 8, "ERROR_CODE_UNSUPPORTED_VERSION");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_PAYLOAD_TOO_LARGE, 9, "ERROR_CODE_PAYLOAD_TOO_LARGE");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_SERVER_ERROR, 10, "ERROR_CODE_SERVER_ERROR");
    ASSERT_EQ(TAGOTIP_ERROR_CODE_UNKNOWN, 11, "ERROR_CODE_UNKNOWN");
}

/* =========================================================================
 * Passthrough encoding values
 * ========================================================================= */

void test_passthrough_encoding_values(void) {
    ASSERT_EQ(TAGOTIP_PASSTHROUGH_HEX, 0, "PASSTHROUGH_HEX");
    ASSERT_EQ(TAGOTIP_PASSTHROUGH_BASE64, 1, "PASSTHROUGH_BASE64");
}

/* =========================================================================
 * Push body tag values
 * ========================================================================= */

void test_push_body_tag_values(void) {
    ASSERT_EQ(TAGOTIP_PUSH_BODY_NONE, 0, "PUSH_BODY_NONE");
    ASSERT_EQ(TAGOTIP_PUSH_BODY_STRUCTURED, 1, "PUSH_BODY_STRUCTURED");
    ASSERT_EQ(TAGOTIP_PUSH_BODY_PASSTHROUGH, 2, "PUSH_BODY_PASSTHROUGH");
}

/* =========================================================================
 * Struct sizes — verify key structs have non-zero size
 * ========================================================================= */

void test_struct_sizes(void) {
    ASSERT_TRUE(sizeof(TagotipStr) > 0, "sizeof(TagotipStr) > 0");
    ASSERT_TRUE(sizeof(TagotipMetaPair) > 0, "sizeof(TagotipMetaPair) > 0");
    ASSERT_TRUE(sizeof(TagotipValue) > 0, "sizeof(TagotipValue) > 0");
    ASSERT_TRUE(sizeof(TagotipVariable) > 0, "sizeof(TagotipVariable) > 0");
    ASSERT_TRUE(sizeof(TagotipPassthroughBody) > 0, "sizeof(TagotipPassthroughBody) > 0");
    ASSERT_TRUE(sizeof(TagotipUplinkFrame) > 0, "sizeof(TagotipUplinkFrame) > 0");
    ASSERT_TRUE(sizeof(TagotipAckDetail) > 0, "sizeof(TagotipAckDetail) > 0");
    ASSERT_TRUE(sizeof(TagotipAckFrame) > 0, "sizeof(TagotipAckFrame) > 0");

    /* TagotipStr should contain a pointer + size_t */
    ASSERT_TRUE(sizeof(TagotipStr) >= sizeof(void *) + sizeof(size_t),
                "TagotipStr holds ptr + len");
}

/* =========================================================================
 * Variable struct layout — initialize and read back all fields
 * ========================================================================= */

void test_variable_struct_layout(void) {
    TagotipVariable var;
    memset(&var, 0, sizeof(var));

    const char *name = "temperature";
    var.name.ptr = (const uint8_t *)name;
    var.name.len = strlen(name);
    var.operator_ = TAGOTIP_OPERATOR_NUMBER;
    var.value.tag = TAGOTIP_VALUE_NUMBER;
    const char *val = "32.5";
    var.value.str_val.ptr = (const uint8_t *)val;
    var.value.str_val.len = strlen(val);
    const char *unit = "C";
    var.unit.ptr = (const uint8_t *)unit;
    var.unit.len = strlen(unit);
    const char *ts = "1694567890000";
    var.timestamp.ptr = (const uint8_t *)ts;
    var.timestamp.len = strlen(ts);
    const char *grp = "batch_01";
    var.group.ptr = (const uint8_t *)grp;
    var.group.len = strlen(grp);
    var.meta_start = 0;
    var.meta_len = 2;

    ASSERT_EQ((int)var.name.len, 11, "Variable.name.len");
    ASSERT_EQ(var.operator_, TAGOTIP_OPERATOR_NUMBER, "Variable.operator");
    ASSERT_EQ(var.value.tag, TAGOTIP_VALUE_NUMBER, "Variable.value.tag");
    ASSERT_EQ((int)var.value.str_val.len, 4, "Variable.value.str_val.len");
    ASSERT_EQ((int)var.unit.len, 1, "Variable.unit.len");
    ASSERT_EQ((int)var.timestamp.len, 13, "Variable.timestamp.len");
    ASSERT_EQ((int)var.group.len, 8, "Variable.group.len");
    ASSERT_EQ(var.meta_start, 0, "Variable.meta_start");
    ASSERT_EQ(var.meta_len, 2, "Variable.meta_len");
}

/* =========================================================================
 * UplinkFrame layout — initialize push frame and read back
 * ========================================================================= */

void test_uplink_frame_layout(void) {
    TagotipUplinkFrame frame;
    memset(&frame, 0, sizeof(frame));

    frame.method = TAGOTIP_METHOD_PUSH;
    frame.has_seq = 1;
    frame.seq = 42;
    const char *auth = "ate2bd319014b24e0a8aca9f00aea4c0d0";
    frame.auth.ptr = (const uint8_t *)auth;
    frame.auth.len = strlen(auth);
    const char *serial = "sensor_01";
    frame.serial.ptr = (const uint8_t *)serial;
    frame.serial.len = strlen(serial);
    frame.push_body_tag = TAGOTIP_PUSH_BODY_STRUCTURED;
    frame.variables_len = 1;

    const char *vname = "temp";
    frame.variables[0].name.ptr = (const uint8_t *)vname;
    frame.variables[0].name.len = strlen(vname);
    frame.variables[0].operator_ = TAGOTIP_OPERATOR_NUMBER;

    ASSERT_EQ(frame.method, TAGOTIP_METHOD_PUSH, "UplinkFrame.method");
    ASSERT_EQ(frame.has_seq, 1, "UplinkFrame.has_seq");
    ASSERT_EQ((int)frame.seq, 42, "UplinkFrame.seq");
    ASSERT_EQ((int)frame.auth.len, 34, "UplinkFrame.auth.len");
    ASSERT_EQ((int)frame.serial.len, 9, "UplinkFrame.serial.len");
    ASSERT_EQ(frame.push_body_tag, TAGOTIP_PUSH_BODY_STRUCTURED, "UplinkFrame.push_body_tag");
    ASSERT_EQ(frame.variables_len, 1, "UplinkFrame.variables_len");
    ASSERT_EQ((int)frame.variables[0].name.len, 4, "UplinkFrame.variables[0].name.len");
    ASSERT_EQ(frame.variables[0].operator_, TAGOTIP_OPERATOR_NUMBER, "UplinkFrame.variables[0].operator");
}

/* =========================================================================
 * AckFrame layout — initialize and read back
 * ========================================================================= */

void test_ack_frame_layout(void) {
    TagotipAckFrame ack;
    memset(&ack, 0, sizeof(ack));

    ack.has_seq = 1;
    ack.seq = 7;
    ack.status = TAGOTIP_ACK_STATUS_OK;
    ack.detail.tag = TAGOTIP_ACK_DETAIL_COUNT;
    ack.detail.count = 5;

    ASSERT_EQ(ack.has_seq, 1, "AckFrame.has_seq");
    ASSERT_EQ((int)ack.seq, 7, "AckFrame.seq");
    ASSERT_EQ(ack.status, TAGOTIP_ACK_STATUS_OK, "AckFrame.status");
    ASSERT_EQ(ack.detail.tag, TAGOTIP_ACK_DETAIL_COUNT, "AckFrame.detail.tag");
    ASSERT_EQ((int)ack.detail.count, 5, "AckFrame.detail.count");

    /* Error detail variant */
    TagotipAckFrame ack_err;
    memset(&ack_err, 0, sizeof(ack_err));
    ack_err.status = TAGOTIP_ACK_STATUS_ERR;
    ack_err.detail.tag = TAGOTIP_ACK_DETAIL_ERROR;
    ack_err.detail.error_code = TAGOTIP_ERROR_CODE_INVALID_TOKEN;
    const char *text = "invalid_token";
    ack_err.detail.text.ptr = (const uint8_t *)text;
    ack_err.detail.text.len = strlen(text);

    ASSERT_EQ(ack_err.status, TAGOTIP_ACK_STATUS_ERR, "AckFrame_err.status");
    ASSERT_EQ(ack_err.detail.tag, TAGOTIP_ACK_DETAIL_ERROR, "AckFrame_err.detail.tag");
    ASSERT_EQ(ack_err.detail.error_code, TAGOTIP_ERROR_CODE_INVALID_TOKEN, "AckFrame_err.detail.error_code");
    ASSERT_EQ((int)ack_err.detail.text.len, 13, "AckFrame_err.detail.text.len");
}

/* =========================================================================
 * PassthroughBody layout — initialize and read back
 * ========================================================================= */

void test_passthrough_body_layout(void) {
    TagotipPassthroughBody pt;
    memset(&pt, 0, sizeof(pt));

    pt.encoding = TAGOTIP_PASSTHROUGH_HEX;
    const char *data = "DEADBEEF";
    pt.data.ptr = (const uint8_t *)data;
    pt.data.len = strlen(data);

    ASSERT_EQ(pt.encoding, TAGOTIP_PASSTHROUGH_HEX, "PassthroughBody.encoding (hex)");
    ASSERT_EQ((int)pt.data.len, 8, "PassthroughBody.data.len (hex)");

    /* Base64 variant */
    TagotipPassthroughBody pt64;
    memset(&pt64, 0, sizeof(pt64));
    pt64.encoding = TAGOTIP_PASSTHROUGH_BASE64;
    const char *b64data = "3q2+7wECAwQ=";
    pt64.data.ptr = (const uint8_t *)b64data;
    pt64.data.len = strlen(b64data);

    ASSERT_EQ(pt64.encoding, TAGOTIP_PASSTHROUGH_BASE64, "PassthroughBody.encoding (base64)");
    ASSERT_EQ((int)pt64.data.len, 12, "PassthroughBody.data.len (base64)");
}

/* =========================================================================
 * LocationValue layout — initialize and read back
 * ========================================================================= */

void test_location_value_layout(void) {
    TagotipValue loc;
    memset(&loc, 0, sizeof(loc));

    loc.tag = TAGOTIP_VALUE_LOCATION;
    const char *lat = "39.74";
    const char *lng = "-104.99";
    const char *alt = "305";
    loc.lat.ptr = (const uint8_t *)lat;
    loc.lat.len = strlen(lat);
    loc.lng.ptr = (const uint8_t *)lng;
    loc.lng.len = strlen(lng);
    loc.alt.ptr = (const uint8_t *)alt;
    loc.alt.len = strlen(alt);

    ASSERT_EQ(loc.tag, TAGOTIP_VALUE_LOCATION, "LocationValue.tag");
    ASSERT_EQ((int)loc.lat.len, 5, "LocationValue.lat.len");
    ASSERT_EQ((int)loc.lng.len, 7, "LocationValue.lng.len");
    ASSERT_EQ((int)loc.alt.len, 3, "LocationValue.alt.len");

    /* Without altitude */
    TagotipValue loc_no_alt;
    memset(&loc_no_alt, 0, sizeof(loc_no_alt));
    loc_no_alt.tag = TAGOTIP_VALUE_LOCATION;
    loc_no_alt.lat.ptr = (const uint8_t *)"0";
    loc_no_alt.lat.len = 1;
    loc_no_alt.lng.ptr = (const uint8_t *)"0";
    loc_no_alt.lng.len = 1;

    ASSERT_EQ((int)loc_no_alt.alt.len, 0, "LocationValue_noalt.alt.len");
    ASSERT_TRUE(loc_no_alt.alt.ptr == NULL, "LocationValue_noalt.alt.ptr is NULL");
}

/* =========================================================================
 * Pull frame layout
 * ========================================================================= */

void test_pull_frame_layout(void) {
    TagotipUplinkFrame frame;
    memset(&frame, 0, sizeof(frame));

    frame.method = TAGOTIP_METHOD_PULL;
    frame.has_pull_body = 1;
    frame.pull_variables_len = 2;

    const char *v1 = "temperature";
    const char *v2 = "humidity";
    frame.pull_variables[0].ptr = (const uint8_t *)v1;
    frame.pull_variables[0].len = strlen(v1);
    frame.pull_variables[1].ptr = (const uint8_t *)v2;
    frame.pull_variables[1].len = strlen(v2);

    ASSERT_EQ(frame.method, TAGOTIP_METHOD_PULL, "PullFrame.method");
    ASSERT_EQ(frame.has_pull_body, 1, "PullFrame.has_pull_body");
    ASSERT_EQ(frame.pull_variables_len, 2, "PullFrame.pull_variables_len");
    ASSERT_EQ((int)frame.pull_variables[0].len, 11, "PullFrame.pull_variables[0].len");
    ASSERT_EQ((int)frame.pull_variables[1].len, 8, "PullFrame.pull_variables[1].len");
}

/* =========================================================================
 * Ping frame layout
 * ========================================================================= */

void test_ping_frame_layout(void) {
    TagotipUplinkFrame frame;
    memset(&frame, 0, sizeof(frame));

    frame.method = TAGOTIP_METHOD_PING;
    const char *auth = "ate2bd319014b24e0a8aca9f00aea4c0d0";
    frame.auth.ptr = (const uint8_t *)auth;
    frame.auth.len = strlen(auth);
    const char *serial = "sensor_01";
    frame.serial.ptr = (const uint8_t *)serial;
    frame.serial.len = strlen(serial);

    ASSERT_EQ(frame.method, TAGOTIP_METHOD_PING, "PingFrame.method");
    ASSERT_EQ(frame.push_body_tag, TAGOTIP_PUSH_BODY_NONE, "PingFrame.push_body_tag");
    ASSERT_EQ(frame.has_pull_body, 0, "PingFrame.has_pull_body");
    ASSERT_EQ(frame.variables_len, 0, "PingFrame.variables_len");
}

/* =========================================================================
 * Arduino-specific defaults
 * ========================================================================= */

void test_arduino_defaults(void) {
    ASSERT_EQ(TAGOTIP_ARDUINO_MAX_VARIABLES, 16, "ARDUINO_MAX_VARIABLES");
    ASSERT_EQ(TAGOTIP_ARDUINO_MAX_META_PAIRS, 8, "ARDUINO_MAX_META_PAIRS");
    ASSERT_EQ(TAGOTIP_ARDUINO_BUF_SIZE, 1024, "ARDUINO_BUF_SIZE");
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void) {
    printf("Running TagoTiP C header tests...\n\n");

    test_constants();
    test_error_codes();
    test_all_method_values();
    test_all_operator_values();
    test_all_value_tag_values();
    test_all_ack_status_values();
    test_all_ack_detail_tag_values();
    test_all_error_code_values();
    test_passthrough_encoding_values();
    test_push_body_tag_values();
    test_struct_sizes();
    test_variable_struct_layout();
    test_uplink_frame_layout();
    test_ack_frame_layout();
    test_passthrough_body_layout();
    test_location_value_layout();
    test_pull_frame_layout();
    test_ping_frame_layout();
    test_arduino_defaults();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
