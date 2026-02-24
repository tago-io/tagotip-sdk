package tagotip

import "testing"

func strPtr(s string) *string { return &s }
func u32Ptr(n uint32) *uint32 { return &n }

// =========================================================================
// BuildUplink + round-trip
// =========================================================================

func TestBuildRoundTripSimplePush(t *testing.T) {
	input := "PUSH|" + testAuth + "|dev|[temperature:=32.5;humidity:=65]"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripPushWithSeq(t *testing.T) {
	input := "PUSH|!42|" + testAuth + "|dev|[x:=1]"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripPushWithUnit(t *testing.T) {
	input := "PUSH|" + testAuth + "|dev|[temp:=32.5#C]"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripPushAllSuffixes(t *testing.T) {
	input := "PUSH|" + testAuth + "|dev|[temp:=32#C@1694567890000^batch{source=dht22}]"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripPushBoolean(t *testing.T) {
	input := "PUSH|" + testAuth + "|dev|[active?=true;ready?=false]"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripPushLocationNoAlt(t *testing.T) {
	input := "PUSH|" + testAuth + "|dev|[pos@=39.74,-104.99]"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripPushLocationWithAlt(t *testing.T) {
	input := "PUSH|" + testAuth + "|dev|[pos@=39.74,-104.99,305]"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripPassthroughHex(t *testing.T) {
	input := "PUSH|" + testAuth + "|dev|>xDEADBEEF"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripPassthroughBase64(t *testing.T) {
	input := "PUSH|" + testAuth + "|dev|>b3q2+7wECAwQ="
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripBodyModifiers(t *testing.T) {
	input := "PUSH|" + testAuth + "|dev|@1694567890000^batch{source=dht22}[temp:=32]"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripPull(t *testing.T) {
	input := "PULL|" + testAuth + "|dev|[temperature;humidity]"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripPing(t *testing.T) {
	input := "PING|" + testAuth + "|dev"
	frame, err := ParseUplink(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

// =========================================================================
// BuildAck + round-trip
// =========================================================================

func TestBuildRoundTripAckOkCount(t *testing.T) {
	input := "ACK|OK|3"
	frame, err := ParseAck(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildAck(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripAckWithSeq(t *testing.T) {
	input := "ACK|!5|OK|3"
	frame, err := ParseAck(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildAck(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripAckPong(t *testing.T) {
	input := "ACK|PONG"
	frame, err := ParseAck(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildAck(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripAckCmd(t *testing.T) {
	input := "ACK|CMD|reboot"
	frame, err := ParseAck(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := BuildAck(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
	}
}

func TestBuildRoundTripAckErrAllCodes(t *testing.T) {
	codes := []string{
		"invalid_token", "invalid_method", "invalid_payload",
		"invalid_seq", "device_not_found", "variable_not_found",
		"rate_limited", "auth_failed", "unsupported_version",
		"payload_too_large", "server_error",
	}
	for _, code := range codes {
		input := "ACK|ERR|" + code
		frame, err := ParseAck(input)
		if err != nil {
			t.Fatalf("error parsing %s: %v", code, err)
		}
		output, err := BuildAck(frame)
		if err != nil {
			t.Fatalf("error building %s: %v", code, err)
		}
		if output != input {
			t.Errorf("round-trip mismatch for %s:\n  want: %s\n  got:  %s", code, input, output)
		}
	}
}

// =========================================================================
// Build from constructed frames
// =========================================================================

func TestBuildConstructedPush(t *testing.T) {
	frame := &UplinkFrame{
		Method: MethodPush,
		Auth:   testAuth,
		Serial: "dev",
		PushBody: &PushBody{
			Structured: &StructuredBody{
				Variables: []Variable{
					{
						Name:     "temp",
						Operator: OperatorNumber,
						Value:    Value{Type: OperatorNumber, Str: "32"},
						Unit:     strPtr("C"),
					},
				},
			},
		},
	}
	output, err := BuildUplink(frame)
	if err != nil {
		t.Fatal(err)
	}
	expected := "PUSH|" + testAuth + "|dev|[temp:=32#C]"
	if output != expected {
		t.Errorf("want: %s\ngot:  %s", expected, output)
	}
}

func TestBuildConstructedAck(t *testing.T) {
	frame := &AckFrame{
		Seq:    u32Ptr(10),
		Status: AckStatusOk,
		Detail: &AckDetail{
			Type:  "count",
			Count: 5,
		},
	}
	output, err := BuildAck(frame)
	if err != nil {
		t.Fatal(err)
	}
	if output != "ACK|!10|OK|5" {
		t.Errorf("wrong output: %s", output)
	}
}
