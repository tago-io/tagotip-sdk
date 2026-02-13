package tagotip

import (
	"bytes"
	"testing"
)

// Spec test vector from TagoTiPs.md section 11.1
var specToken = "ate2bd319014b24e0a8aca9f00aea4c0d0"
var specSerial = "sensor-01"
var specKey = []byte{0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee, 0x12, 0xab, 0x56, 0xcd, 0x78, 0xef, 0x90, 0x12}
var specAuthHash = [8]byte{0x4d, 0xee, 0xdd, 0x7b, 0xab, 0x88, 0x17, 0xec}
var specDeviceHash = [8]byte{0xab, 0x77, 0x88, 0xd2, 0x2e, 0xb7, 0x37, 0x2f}

var specEnvelope = []byte{
	0x00, 0x00, 0x00, 0x00, 0x2a, 0x4d, 0xee, 0xdd,
	0x7b, 0xab, 0x88, 0x17, 0xec, 0xab, 0x77, 0x88,
	0xd2, 0x2e, 0xb7, 0x37, 0x2f, 0xc8, 0xc5, 0xaa,
	0x56, 0xd7, 0x55, 0x58, 0x2b, 0xac, 0xea, 0x13,
	0xbb, 0x57, 0x24, 0x93, 0xbb, 0x8c, 0xb1, 0x08,
	0x03, 0xcf, 0x82, 0x6f, 0xdb, 0x83, 0x3b, 0x79,
	0xc6,
}

// =========================================================================
// Hash derivation tests
// =========================================================================

func TestDeriveAuthHashSpecVector(t *testing.T) {
	hash := DeriveAuthHash(specToken)
	if hash != specAuthHash {
		t.Errorf("auth hash mismatch: %x", hash)
	}
}

func TestDeriveAuthHashWithoutPrefix(t *testing.T) {
	hash := DeriveAuthHash("e2bd319014b24e0a8aca9f00aea4c0d0")
	if hash != specAuthHash {
		t.Errorf("auth hash mismatch: %x", hash)
	}
}

func TestDeriveDeviceHashSpecVector(t *testing.T) {
	hash := DeriveDeviceHash(specSerial)
	if hash != specDeviceHash {
		t.Errorf("device hash mismatch: %x", hash)
	}
}

// =========================================================================
// Key derivation tests
// =========================================================================

var specDerivedKey = []byte{
	0xe5, 0x05, 0xf0, 0x3c, 0xc9, 0xe9, 0x3f, 0xdb,
	0xcc, 0x38, 0x28, 0x44, 0xcc, 0xa3, 0xe1, 0x7f,
	0xdf, 0x0b, 0xb3, 0x13, 0x18, 0x58, 0x53, 0x95,
	0xce, 0xaa, 0xa3, 0x9a, 0x5d, 0x14, 0x19, 0x64,
}

func TestDeriveKeySpecVector32(t *testing.T) {
	key, err := DeriveKey(specToken, specSerial, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, specDerivedKey) {
		t.Errorf("derived key mismatch:\n  want: %x\n  got:  %x", specDerivedKey, key)
	}
}

func TestDeriveKeySpecVector16(t *testing.T) {
	key, err := DeriveKey(specToken, specSerial, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, specDerivedKey[:16]) {
		t.Errorf("derived key (16) mismatch:\n  want: %x\n  got:  %x", specDerivedKey[:16], key)
	}
}

func TestDeriveKeyWithoutPrefix(t *testing.T) {
	keyWith, _ := DeriveKey(specToken, specSerial, 32)
	keyWithout, _ := DeriveKey("e2bd319014b24e0a8aca9f00aea4c0d0", specSerial, 32)
	if !bytes.Equal(keyWith, keyWithout) {
		t.Errorf("keys should match with/without 'at' prefix")
	}
}

func TestDeriveKeyInvalidKeyLen(t *testing.T) {
	_, err := DeriveKey(specToken, specSerial, 8)
	if err == nil {
		t.Fatal("expected error with invalid key length")
	}
}

func TestDeriveKeySealOpenRoundTrip(t *testing.T) {
	key, _ := DeriveKey(specToken, specSerial, 16)
	authHash := DeriveAuthHash(specToken)
	deviceHash := DeriveDeviceHash(specSerial)

	innerFrame := []byte("sensor-01|[temp:=32]")
	envelope, err := SealUplink(EnvelopeMethodPush, innerFrame, 1, authHash, deviceHash, key, CipherSuiteAes128Ccm)
	if err != nil {
		t.Fatal(err)
	}

	_, method, plaintext, err := OpenEnvelope(envelope, key)
	if err != nil {
		t.Fatal(err)
	}
	if method != EnvelopeMethodPush {
		t.Errorf("expected PUSH")
	}
	if !bytes.Equal(plaintext, innerFrame) {
		t.Errorf("plaintext mismatch")
	}
}

// =========================================================================
// Hex utility tests
// =========================================================================

func TestHexToBytes(t *testing.T) {
	result, err := HexToBytes("fe09da81bc4400ee")
	if err != nil {
		t.Fatal(err)
	}
	expected := []byte{0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee}
	if !bytes.Equal(result, expected) {
		t.Errorf("hex_to_bytes mismatch")
	}
}

func TestBytesToHex(t *testing.T) {
	data := []byte{0xfe, 0x09, 0xda, 0x81}
	result := BytesToHex(data)
	if result != "fe09da81" {
		t.Errorf("bytes_to_hex mismatch: %s", result)
	}
}

func TestHexRoundTrip(t *testing.T) {
	original := specKey
	hexStr := BytesToHex(original)
	if hexStr != "fe09da81bc4400ee12ab56cd78ef9012" {
		t.Errorf("hex string mismatch: %s", hexStr)
	}
	decoded, err := HexToBytes(hexStr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("round-trip mismatch")
	}
}

func TestHexToBytesInvalidOddLength(t *testing.T) {
	_, err := HexToBytes("abc")
	if err == nil {
		t.Fatal("expected error for odd length")
	}
}

func TestHexToBytesInvalidChars(t *testing.T) {
	_, err := HexToBytes("zz00")
	if err == nil {
		t.Fatal("expected error for non-hex chars")
	}
}

func TestHexToBytesEmpty(t *testing.T) {
	result, err := HexToBytes("")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result")
	}
}

// =========================================================================
// Validation tests (lowercase-only, serial chars)
// =========================================================================

func TestRejectUppercaseVarname(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[Temperature:=32]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectUppercaseGroup(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[temp:=32^Batch]")
	assertParseError(t, err, ErrInvalidVariable)
}

func TestRejectUppercaseMetaKey(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[temp:=32{Source=dht22}]")
	assertParseError(t, err, ErrInvalidMetadata)
}

func TestAcceptLowercaseVarname(t *testing.T) {
	_, err := ParseUplink("PUSH|" + testAuth + "|dev|[temperature_01:=32]")
	if err != nil {
		t.Fatalf("should accept lowercase varname: %v", err)
	}
}

func TestSerialAcceptsAlphanumHyphenUnderscore(t *testing.T) {
	_, err := ParseUplink("PING|" + testAuth + "|My-Device_01")
	if err != nil {
		t.Fatalf("should accept valid serial: %v", err)
	}
}

func TestSerialRejectsSpecialChars(t *testing.T) {
	_, err := ParseUplink("PING|" + testAuth + "|dev!ce")
	assertParseError(t, err, ErrInvalidSerial)
}

func TestSerialRejectsSpace(t *testing.T) {
	_, err := ParseUplink("PING|" + testAuth + "|my device")
	assertParseError(t, err, ErrInvalidSerial)
}

// =========================================================================
// Headless frame tests
// =========================================================================

func TestParseHeadlessPush(t *testing.T) {
	frame, err := ParseHeadless(MethodPush, "sensor_01|[temp:=32]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Serial != "sensor_01" {
		t.Errorf("wrong serial: %s", frame.Serial)
	}
	if frame.PushBody == nil || frame.PushBody.Structured == nil {
		t.Fatal("expected structured push body")
	}
}

func TestParseHeadlessPull(t *testing.T) {
	frame, err := ParseHeadless(MethodPull, "sensor_01|[temperature]")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Serial != "sensor_01" {
		t.Errorf("wrong serial: %s", frame.Serial)
	}
	if frame.PullBody == nil || len(frame.PullBody.Variables) != 1 {
		t.Fatal("expected pull body with 1 variable")
	}
}

func TestParseHeadlessPing(t *testing.T) {
	frame, err := ParseHeadless(MethodPing, "sensor_01")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Serial != "sensor_01" {
		t.Errorf("wrong serial: %s", frame.Serial)
	}
}

func TestBuildHeadlessRoundTrip(t *testing.T) {
	cases := []struct {
		method Method
		input  string
	}{
		{MethodPush, "sensor_01|[temp:=32]"},
		{MethodPull, "sensor_01|[temperature;humidity]"},
		{MethodPing, "sensor_01"},
	}
	for _, tc := range cases {
		frame, err := ParseHeadless(tc.method, tc.input)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.input, err)
		}
		output, err := BuildHeadless(tc.method, frame)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if output != tc.input {
			t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", tc.input, output)
		}
	}
}

func TestParseAckInner(t *testing.T) {
	frame, err := ParseAckInner("OK|3")
	if err != nil {
		t.Fatal(err)
	}
	if frame.Status != AckStatusOk {
		t.Errorf("wrong status")
	}
	if frame.Detail == nil || frame.Detail.Type != "count" || frame.Detail.Count != 3 {
		t.Errorf("wrong detail: %+v", frame.Detail)
	}
}

func TestBuildAckInnerRoundTrip(t *testing.T) {
	cases := []string{
		"OK|3",
		"PONG",
		"CMD|reboot",
		"ERR|auth_failed",
	}
	for _, input := range cases {
		frame, err := ParseAckInner(input)
		if err != nil {
			t.Fatalf("parse %s: %v", input, err)
		}
		output, err := BuildAckInner(frame)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if output != input {
			t.Errorf("round-trip mismatch:\n  want: %s\n  got:  %s", input, output)
		}
	}
}

// =========================================================================
// Spec vector test (section 11.1)
// =========================================================================

func TestSpecVectorSeal(t *testing.T) {
	innerFrame := []byte("sensor-01|[temp:=32]")
	envelope, err := SealUplink(
		EnvelopeMethodPush,
		innerFrame,
		42,
		specAuthHash,
		specDeviceHash,
		specKey,
		CipherSuiteAes128Ccm,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(envelope) != 49 {
		t.Fatalf("expected 49 bytes, got %d", len(envelope))
	}
	if !bytes.Equal(envelope, specEnvelope) {
		t.Errorf("envelope mismatch:\n  want: %x\n  got:  %x", specEnvelope, envelope)
	}
}

func TestSpecVectorOpen(t *testing.T) {
	header, method, plaintext, err := OpenEnvelope(specEnvelope, specKey)
	if err != nil {
		t.Fatal(err)
	}
	if method != EnvelopeMethodPush {
		t.Errorf("expected PUSH, got %d", method)
	}
	if header.Counter != 42 {
		t.Errorf("expected counter=42, got %d", header.Counter)
	}
	if header.AuthHash != specAuthHash {
		t.Errorf("auth hash mismatch")
	}
	if header.DeviceHash != specDeviceHash {
		t.Errorf("device hash mismatch")
	}
	if string(plaintext) != "sensor-01|[temp:=32]" {
		t.Errorf("plaintext mismatch: %s", string(plaintext))
	}
}

// =========================================================================
// Round-trip tests
// =========================================================================

func TestSealOpenRoundTrip(t *testing.T) {
	authHash := DeriveAuthHash(specToken)
	deviceHash := DeriveDeviceHash(specSerial)

	innerFrame := []byte("sensor-01|[temperature:=32.5;humidity:=65]")
	envelope, err := SealUplink(
		EnvelopeMethodPush,
		innerFrame,
		1,
		authHash,
		deviceHash,
		specKey,
		CipherSuiteAes128Ccm,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, method, plaintext, err := OpenEnvelope(envelope, specKey)
	if err != nil {
		t.Fatal(err)
	}
	if method != EnvelopeMethodPush {
		t.Errorf("expected PUSH")
	}
	if !bytes.Equal(plaintext, innerFrame) {
		t.Errorf("plaintext mismatch")
	}
}

func TestSealOpenRoundTripPing(t *testing.T) {
	authHash := DeriveAuthHash(specToken)
	deviceHash := DeriveDeviceHash(specSerial)

	innerFrame := []byte("sensor-01")
	envelope, err := SealUplink(
		EnvelopeMethodPing,
		innerFrame,
		100,
		authHash,
		deviceHash,
		specKey,
		CipherSuiteAes128Ccm,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, method, plaintext, err := OpenEnvelope(envelope, specKey)
	if err != nil {
		t.Fatal(err)
	}
	if method != EnvelopeMethodPing {
		t.Errorf("expected PING")
	}
	if string(plaintext) != "sensor-01" {
		t.Errorf("plaintext mismatch: %s", string(plaintext))
	}
}

func TestSealOpenRoundTripAck(t *testing.T) {
	authHash := DeriveAuthHash(specToken)
	deviceHash := DeriveDeviceHash(specSerial)

	innerFrame := []byte("OK|3")
	envelope, err := SealUplink(
		EnvelopeMethodAck,
		innerFrame,
		1,
		authHash,
		deviceHash,
		specKey,
		CipherSuiteAes128Ccm,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, method, plaintext, err := OpenEnvelope(envelope, specKey)
	if err != nil {
		t.Fatal(err)
	}
	if method != EnvelopeMethodAck {
		t.Errorf("expected ACK")
	}
	if string(plaintext) != "OK|3" {
		t.Errorf("plaintext mismatch: %s", string(plaintext))
	}
}

// =========================================================================
// Error cases
// =========================================================================

func TestOpenEnvelopeWrongKey(t *testing.T) {
	wrongKey := make([]byte, 16)
	_, _, _, err := OpenEnvelope(specEnvelope, wrongKey)
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
	if !IsSecureError(err) {
		t.Errorf("expected SecureError, got %T", err)
	}
}

func TestOpenEnvelopeTooShort(t *testing.T) {
	_, _, _, err := OpenEnvelope(specEnvelope[:10], specKey)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestOpenEnvelopeTamperedCiphertext(t *testing.T) {
	tampered := make([]byte, len(specEnvelope))
	copy(tampered, specEnvelope)
	tampered[25] ^= 0xFF // flip a ciphertext byte
	_, _, _, err := OpenEnvelope(tampered, specKey)
	if err == nil {
		t.Fatal("expected error with tampered ciphertext")
	}
}

func TestOpenEnvelopeTamperedHeader(t *testing.T) {
	tampered := make([]byte, len(specEnvelope))
	copy(tampered, specEnvelope)
	tampered[5] ^= 0xFF // flip auth hash byte
	_, _, _, err := OpenEnvelope(tampered, specKey)
	if err == nil {
		t.Fatal("expected error with tampered header")
	}
}

func TestSealInvalidKeySize(t *testing.T) {
	_, err := SealUplink(
		EnvelopeMethodPush,
		[]byte("test"),
		1,
		specAuthHash,
		specDeviceHash,
		[]byte{0x01, 0x02}, // wrong size
		CipherSuiteAes128Ccm,
	)
	if err == nil {
		t.Fatal("expected error with wrong key size")
	}
}

// =========================================================================
// IsEnvelope
// =========================================================================

func TestIsEnvelope(t *testing.T) {
	if !IsEnvelope([]byte{0x00, 0x01, 0x02}) {
		t.Errorf("expected true for non-0x41 first byte")
	}
	if IsEnvelope([]byte{0x41, 0x43, 0x4B}) {
		t.Errorf("expected false for 0x41 first byte (ACK)")
	}
	if IsEnvelope([]byte{}) {
		t.Errorf("expected false for empty")
	}
}

// =========================================================================
// ParseEnvelopeHeader
// =========================================================================

func TestParseEnvelopeHeader(t *testing.T) {
	header, err := ParseEnvelopeHeader(specEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if header.Flags != 0x00 {
		t.Errorf("wrong flags: %x", header.Flags)
	}
	if header.Counter != 42 {
		t.Errorf("wrong counter: %d", header.Counter)
	}
	if header.AuthHash != specAuthHash {
		t.Errorf("wrong auth hash")
	}
	if header.DeviceHash != specDeviceHash {
		t.Errorf("wrong device hash")
	}
}
