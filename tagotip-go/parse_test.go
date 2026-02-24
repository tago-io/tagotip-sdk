package tagotip

import (
	"errors"
	"strings"
	"testing"
)

const testAuth = "at0123456789abcdef0123456789abcdef"

func assertParseError(t *testing.T, err error, expectedKind ParseErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %s, got nil", expectedKind)
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected ParseError, got %T: %v", err, err)
	}
	if pe.Kind != expectedKind {
		t.Fatalf("expected error kind %s, got %s", expectedKind, pe.Kind)
	}
}

// =========================================================================
// ParseUplink — happy path
// =========================================================================

func TestParseSimplePush(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|my-device|[temperature:=32.5;humidity:=65]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Method != MethodPush {
		t.Errorf("expected PUSH, got %d", frame.Method)
	}
	if frame.Auth != testAuth {
		t.Errorf("wrong auth")
	}
	if frame.Serial != "my-device" {
		t.Errorf("wrong serial: %s", frame.Serial)
	}
	if frame.PushBody == nil || frame.PushBody.Structured == nil {
		t.Fatal("expected structured push body")
	}
	vars := frame.PushBody.Structured.Variables
	if len(vars) != 2 {
		t.Fatalf("expected 2 vars, got %d", len(vars))
	}
	if vars[0].Name != "temperature" {
		t.Errorf("wrong name: %s", vars[0].Name)
	}
	if vars[0].Operator != OperatorNumber {
		t.Errorf("wrong operator")
	}
	if vars[0].Value.Str != "32.5" {
		t.Errorf("wrong value: %s", vars[0].Value.Str)
	}
	if vars[1].Name != "humidity" || vars[1].Value.Str != "65" {
		t.Errorf("wrong second var")
	}
}

func TestParsePushWithSeq(t *testing.T) {
	frame, err := ParseUplink("PUSH|!42|" + testAuth + "|dev|[x:=1]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Seq == nil || *frame.Seq != 42 {
		t.Errorf("expected seq=42")
	}
}

func TestParsePushNumber(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[temp:=32.5#C]")
	if err != nil {
		t.Fatal(err)
	}
	v := frame.PushBody.Structured.Variables[0]
	if v.Operator != OperatorNumber {
		t.Errorf("expected number operator")
	}
	if v.Value.Str != "32.5" {
		t.Errorf("wrong value: %s", v.Value.Str)
	}
	if v.Unit == nil || *v.Unit != "C" {
		t.Errorf("wrong unit")
	}
}

func TestParsePushString(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[status=online]")
	if err != nil {
		t.Fatal(err)
	}
	v := frame.PushBody.Structured.Variables[0]
	if v.Operator != OperatorString {
		t.Errorf("expected string operator")
	}
	if v.Value.Str != "online" {
		t.Errorf("wrong value: %s", v.Value.Str)
	}
}

func TestParsePushBoolTrue(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[active?=true]")
	if err != nil {
		t.Fatal(err)
	}
	v := frame.PushBody.Structured.Variables[0]
	if v.Operator != OperatorBoolean {
		t.Errorf("expected boolean operator")
	}
	if !v.Value.Bool {
		t.Errorf("expected true")
	}
}

func TestParsePushBoolFalse(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[active?=false]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.PushBody.Structured.Variables[0].Value.Bool {
		t.Errorf("expected false")
	}
}

func TestParsePushLocationNoAlt(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[pos@=39.74,-104.99]")
	if err != nil {
		t.Fatal(err)
	}
	v := frame.PushBody.Structured.Variables[0]
	if v.Operator != OperatorLocation {
		t.Errorf("expected location operator")
	}
	loc := v.Value.Location
	if loc == nil {
		t.Fatal("expected location value")
	}
	if loc.Lat != "39.74" || loc.Lng != "-104.99" {
		t.Errorf("wrong lat/lng: %s %s", loc.Lat, loc.Lng)
	}
	if loc.Alt != nil {
		t.Errorf("expected no alt")
	}
}

func TestParsePushLocationWithAlt(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[pos@=39.74,-104.99,305]")
	if err != nil {
		t.Fatal(err)
	}
	loc := frame.PushBody.Structured.Variables[0].Value.Location
	if loc.Alt == nil || *loc.Alt != "305" {
		t.Errorf("expected alt=305")
	}
}

func TestParsePushNegativeNumber(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[temp:=-12.3]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.PushBody.Structured.Variables[0].Value.Str != "-12.3" {
		t.Errorf("wrong value")
	}
}

func TestParsePushMetadata(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[temp:=32{source=dht22,quality=high}]")
	if err != nil {
		t.Fatal(err)
	}
	v := frame.PushBody.Structured.Variables[0]
	if len(v.Meta) != 2 {
		t.Fatalf("expected 2 meta pairs, got %d", len(v.Meta))
	}
	if v.Meta[0].Key != "source" || v.Meta[0].Value != "dht22" {
		t.Errorf("wrong meta[0]")
	}
	if v.Meta[1].Key != "quality" || v.Meta[1].Value != "high" {
		t.Errorf("wrong meta[1]")
	}
}

func TestParsePushBodyModifiers(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|@1694567890000^batch{source=dht22}[temp:=32]")
	if err != nil {
		t.Fatal(err)
	}
	sb := frame.PushBody.Structured
	if sb.Group == nil || *sb.Group != "batch" {
		t.Errorf("wrong body group")
	}
	if sb.Timestamp == nil || *sb.Timestamp != "1694567890000" {
		t.Errorf("wrong body timestamp")
	}
	if len(sb.Meta) != 1 || sb.Meta[0].Key != "source" {
		t.Errorf("wrong body meta")
	}
}

func TestParsePushAllSuffixes(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[temp:=32#C@1694567890000^batch{source=dht22}]")
	if err != nil {
		t.Fatal(err)
	}
	v := frame.PushBody.Structured.Variables[0]
	if v.Unit == nil || *v.Unit != "C" {
		t.Errorf("wrong unit")
	}
	if v.Timestamp == nil || *v.Timestamp != "1694567890000" {
		t.Errorf("wrong timestamp")
	}
	if v.Group == nil || *v.Group != "batch" {
		t.Errorf("wrong group")
	}
	if len(v.Meta) != 1 {
		t.Errorf("wrong meta count")
	}
}

func TestParsePushPassthroughHex(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|>xDEADBEEF")
	if err != nil {
		t.Fatal(err)
	}
	if !frame.PushBody.IsPassthrough {
		t.Errorf("expected passthrough")
	}
	pt := frame.PushBody.Passthrough
	if pt.Encoding != PassthroughEncodingHex {
		t.Errorf("expected hex encoding")
	}
	if pt.Data != "DEADBEEF" {
		t.Errorf("wrong data: %s", pt.Data)
	}
}

func TestParsePushPassthroughBase64(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|>b3q2+7wECAwQ=")
	if err != nil {
		t.Fatal(err)
	}
	if frame.PushBody.Passthrough.Encoding != PassthroughEncodingBase64 {
		t.Errorf("expected base64 encoding")
	}
}

func TestParsePushDatalogger(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[temp:=20@100;temp:=21@200;temp:=22@300]")
	if err != nil {
		t.Fatal(err)
	}
	if len(frame.PushBody.Structured.Variables) != 3 {
		t.Errorf("expected 3 vars")
	}
}

func TestParsePullSingle(t *testing.T) {
	frame, err := ParseUplink("PULL|" + testAuth + "|dev|[temperature]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Method != MethodPull {
		t.Errorf("expected PULL")
	}
	if frame.PullBody == nil {
		t.Fatal("expected pull body")
	}
	if len(frame.PullBody.Variables) != 1 || frame.PullBody.Variables[0] != "temperature" {
		t.Errorf("wrong pull variables")
	}
}

func TestParsePullMultiple(t *testing.T) {
	frame, err := ParseUplink("PULL|" + testAuth + "|dev|[temperature;humidity]")
	if err != nil {
		t.Fatal(err)
	}
	if len(frame.PullBody.Variables) != 2 {
		t.Errorf("expected 2 pull variables")
	}
}

func TestParsePing(t *testing.T) {
	frame, err := ParseUplink("PING|" + testAuth + "|dev")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Method != MethodPing {
		t.Errorf("expected PING")
	}
	if frame.PushBody != nil || frame.PullBody != nil {
		t.Errorf("expected no body for PING")
	}
}

func TestParseTrailingNewline(t *testing.T) {
	frame, err := ParseUplink("PING|" + testAuth + "|dev\n")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Method != MethodPing {
		t.Errorf("expected PING")
	}
}

// =========================================================================
// ParseUplink — error cases
// =========================================================================

func TestRejectEmptyString(t *testing.T) {
	_, err := ParseUplink("")
	assertParseError(t, err, ErrEmptyFrame)
}

func TestRejectInvalidMethod(t *testing.T) {
	_, err := ParseUplink("INVALID|" + testAuth + "|dev")
	assertParseError(t, err, ErrInvalidMethod)
}

func TestRejectInvalidAuth(t *testing.T) {
	_, err := ParseUplink("PING|invalidtoken|dev")
	assertParseError(t, err, ErrInvalidAuth)
}

func TestRejectMissingSerial(t *testing.T) {
	_, err := ParseUplink("PING|" + testAuth)
	assertParseError(t, err, ErrInvalidSerial)
}

func TestRejectMissingBodyPush(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev")
	assertParseError(t, err, ErrMissingBody)
}

func TestRejectMissingBodyPull(t *testing.T) {
	_, err := ParseUplink("PULL|" + testAuth + "|dev")
	assertParseError(t, err, ErrMissingBody)
}

func TestRejectEmptyVarBlock(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[]")
	assertParseError(t, err, ErrInvalidVarBlock)
}

func TestRejectInvalidBoolean(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x?=maybe]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectLeadingZeroNumber(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=01]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectOddHexPassthrough(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|>xDEA")
	assertParseError(t, err, ErrInvalidPassthru)
}

func TestRejectFrameTooLarge(t *testing.T) {
	large := "PUSH|" + testAuth + "|dev|[x=" + strings.Repeat("a", MaxFrameSize) + "]"
	_, err := ParseUplink(large)
	assertParseError(t, err, ErrFrameTooLarge)
}

func TestRejectNulByte(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|\x00dev|[x:=1]")
	assertParseError(t, err, ErrNulByte)
}

func TestRejectEmptyStringValue(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x=]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectTrailingDot(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=1.]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectDotOnly(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=.]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectLocationWithUnit(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[pos@=39.74,-104.99#m]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectEmptyMetadata(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=1{}]")
	assertParseError(t, err, ErrInvalidMetadata)
}

func TestRejectMetaMissingEquals(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=1{badmeta}]")
	assertParseError(t, err, ErrInvalidMetadata)
}

func TestRejectBodyGroupAfterTimestamp(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|^group@123[x:=1]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectLocation4Components(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[pos@=1,2,3,4]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectSeqLeadingZeros(t *testing.T) {
	_, err := ParseUplink("PUSH|!01|" + testAuth + "|dev|[x:=1]")
	assertParseError(t, err, ErrInvalidSeq)
}

func TestRejectEmptySeq(t *testing.T) {
	_, err := ParseUplink("PUSH|!|" + testAuth + "|dev|[x:=1]")
	assertParseError(t, err, ErrInvalidSeq)
}

func TestRejectNegativeSeq(t *testing.T) {
	_, err := ParseUplink("PUSH|!-1|" + testAuth + "|dev|[x:=1]")
	assertParseError(t, err, ErrInvalidSeq)
}

func TestRejectAuthTooShort(t *testing.T) {
	_, err := ParseUplink("PING|at1234|dev")
	assertParseError(t, err, ErrInvalidAuth)
}

func TestRejectAuthWrongPrefix(t *testing.T) {
	_, err := ParseUplink("PING|xx0123456789abcdef0123456789abcdef|dev")
	assertParseError(t, err, ErrInvalidAuth)
}

func TestRejectEmptyNumberValue(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectAlphaNumberValue(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=abc]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectLocationEmptyLat(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[pos@=,-104.99]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectLocationEmptyLng(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[pos@=39.74,]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectLocationEmptyAlt(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[pos@=39.74,-104.99,]")
	assertParseError(t, err, ErrInvalidVariable)
}

// =========================================================================
// ParseAck
// =========================================================================

func TestParseAckOkCount(t *testing.T) {
	frame, err := ParseAck("ACK|OK|3")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Status != AckStatusOk {
		t.Errorf("wrong status")
	}
	if frame.Detail == nil {
		t.Fatal("expected detail")
	}
	if frame.Detail.Type != "count" || frame.Detail.Count != 3 {
		t.Errorf("wrong detail: %+v", frame.Detail)
	}
}

func TestParseAckOkZeroCount(t *testing.T) {
	frame, err := ParseAck("ACK|OK|0")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Detail.Type != "count" || frame.Detail.Count != 0 {
		t.Errorf("wrong count")
	}
}

func TestParseAckOkVariables(t *testing.T) {
	frame, err := ParseAck("ACK|OK|[temp:=32]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Detail.Type != "variables" {
		t.Errorf("expected variables detail")
	}
}

func TestParseAckOkNoDetail(t *testing.T) {
	frame, err := ParseAck("ACK|OK")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Detail != nil {
		t.Errorf("expected no detail")
	}
}

func TestParseAckPong(t *testing.T) {
	frame, err := ParseAck("ACK|PONG")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Status != AckStatusPong {
		t.Errorf("wrong status")
	}
}

func TestParseAckCmd(t *testing.T) {
	frame, err := ParseAck("ACK|CMD|reboot")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Status != AckStatusCmd {
		t.Errorf("wrong status")
	}
	if frame.Detail == nil || frame.Detail.Type != "command" || frame.Detail.Text != "reboot" {
		t.Errorf("wrong detail")
	}
}

func TestParseAckCmdNoDetail(t *testing.T) {
	frame, err := ParseAck("ACK|CMD")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Detail != nil {
		t.Errorf("expected no detail")
	}
}

func TestParseAckErr(t *testing.T) {
	frame, err := ParseAck("ACK|ERR|invalid_token")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Status != AckStatusErr {
		t.Errorf("wrong status")
	}
	if frame.Detail.Type != "error" {
		t.Errorf("expected error detail")
	}
	if frame.Detail.ErrorCode != ErrorCodeInvalidToken {
		t.Errorf("wrong error code")
	}
}

func TestParseAckAllErrorCodes(t *testing.T) {
	codes := map[string]ErrorCode{
		"invalid_token":        ErrorCodeInvalidToken,
		"invalid_method":       ErrorCodeInvalidMethod,
		"invalid_payload":      ErrorCodeInvalidPayload,
		"invalid_seq":          ErrorCodeInvalidSeq,
		"device_not_found":     ErrorCodeDeviceNotFound,
		"variable_not_found":   ErrorCodeVariableNotFound,
		"rate_limited":         ErrorCodeRateLimited,
		"auth_failed":          ErrorCodeAuthFailed,
		"unsupported_version":  ErrorCodeUnsupportedVersion,
		"payload_too_large":    ErrorCodePayloadTooLarge,
		"server_error":         ErrorCodeServerError,
	}
	for text, expected := range codes {
		frame, err := ParseAck("ACK|ERR|" + text)
		if err != nil {
			t.Fatalf("error parsing %s: %v", text, err)
		}
		if frame.Detail.ErrorCode != expected {
			t.Errorf("for %s: expected %d, got %d", text, expected, frame.Detail.ErrorCode)
		}
	}
}

func TestParseAckUnknownError(t *testing.T) {
	frame, err := ParseAck("ACK|ERR|custom_error")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Detail.ErrorCode != ErrorCodeUnknown {
		t.Errorf("expected unknown error code")
	}
}

func TestParseAckWithSeq(t *testing.T) {
	frame, err := ParseAck("ACK|!5|OK|3")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Seq == nil || *frame.Seq != 5 {
		t.Errorf("expected seq=5")
	}
}

func TestParseAckTrailingNewline(t *testing.T) {
	frame, err := ParseAck("ACK|OK|3\n")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Detail.Count != 3 {
		t.Errorf("wrong count")
	}
}

func TestParseAckLargeCount(t *testing.T) {
	frame, err := ParseAck("ACK|OK|4294967295")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Detail.Count != 4294967295 {
		t.Errorf("wrong count: %d", frame.Detail.Count)
	}
}

func TestRejectEmptyAck(t *testing.T) {
	_, err := ParseAck("")
	assertParseError(t, err, ErrInvalidAck)
}

func TestRejectInvalidAckStatus(t *testing.T) {
	_, err := ParseAck("ACK|INVALID")
	assertParseError(t, err, ErrInvalidAck)
}

// =========================================================================
// Number edge cases
// =========================================================================

func TestNumberZero(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=0]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.PushBody.Structured.Variables[0].Value.Str != "0" {
		t.Errorf("wrong value")
	}
}

func TestNumberNegativeZero(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=-0]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.PushBody.Structured.Variables[0].Value.Str != "-0" {
		t.Errorf("wrong value")
	}
}

func TestNumberDecimal(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=123.456]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.PushBody.Structured.Variables[0].Value.Str != "123.456" {
		t.Errorf("wrong value")
	}
}

func TestNumberHalf(t *testing.T) {
	frame, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=0.5]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.PushBody.Structured.Variables[0].Value.Str != "0.5" {
		t.Errorf("wrong value")
	}
}

func TestNumberLargeInt(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=99999999999999999]")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRejectNegativeLeadingZero(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=-01]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectDoubleNegative(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[x:=--1]")
	assertParseError(t, err, ErrInvalidVariable)
}

// =========================================================================
// Seq edge cases
// =========================================================================

func TestSeqZero(t *testing.T) {
	frame, err := ParseUplink("PUSH|!0|" + testAuth + "|dev|[x:=1]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Seq == nil || *frame.Seq != 0 {
		t.Errorf("expected seq=0")
	}
}

func TestSeqMaxU32(t *testing.T) {
	frame, err := ParseUplink("PUSH|!4294967295|" + testAuth + "|dev|[x:=1]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Seq == nil || *frame.Seq != 4294967295 {
		t.Errorf("expected max u32")
	}
}

func TestSeqOverflow(t *testing.T) {
	_, err := ParseUplink("PUSH|!4294967296|" + testAuth + "|dev|[x:=1]")
	assertParseError(t, err, ErrInvalidSeq)
}

// =========================================================================
// Spec §11 examples
// =========================================================================

func TestSpec11_1(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|sensor_01|[temperature:=32;humidity:=65]")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSpec11_2(t *testing.T) {
	frame, err := ParseUplink("PUSH|!1|" + testAuth + "|sensor_01|[temperature:=32;humidity:=65]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Seq == nil || *frame.Seq != 1 {
		t.Errorf("expected seq=1")
	}
}

func TestSpec11_3(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|sensor_01|[temperature:=32.5#C;status=online;active?=true]")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSpec11_4(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|sensor_01|[position@=39.74,-104.99,305]")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSpec11_5(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|sensor_01|[temperature:=32.5{source=dht22}]")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSpec11_6(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|sensor_01|@1694567890000^batch_01[temperature:=32;humidity:=65]")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSpec11_7(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|sensor_01|[temperature:=20@1694567890000;temperature:=21@1694567891000;temperature:=22@1694567892000]")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSpec11_8(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|sensor_01|>xDEADBEEF0102")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSpec11_9(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|sensor_01|>b3q2+7wECAwQ=")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSpec11_10(t *testing.T) {
	_, err := ParseUplink("PULL|" + testAuth + "|sensor_01|[temperature;humidity]")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSpec11_12(t *testing.T) {
	_, err := ParseUplink("PING|" + testAuth + "|sensor_01")
	if err != nil {
		t.Fatal(err)
	}
}
