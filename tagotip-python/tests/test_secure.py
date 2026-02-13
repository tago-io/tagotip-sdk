"""Tests for TagoTiP/S secure crypto envelope."""

import pytest
from tagotip.secure import (
    derive_auth_hash,
    derive_device_hash,
    seal_uplink,
    open_envelope,
    parse_envelope_header,
    is_envelope,
)

SPEC_TOKEN = "ate2bd319014b24e0a8aca9f00aea4c0d0"
SPEC_SERIAL = "sensor-01"
SPEC_KEY = bytes([
    0xfe, 0x09, 0xda, 0x81, 0xbc, 0x44, 0x00, 0xee,
    0x12, 0xab, 0x56, 0xcd, 0x78, 0xef, 0x90, 0x12,
])
SPEC_AUTH_HASH = bytes([0x4d, 0xee, 0xdd, 0x7b, 0xab, 0x88, 0x17, 0xec])
SPEC_DEVICE_HASH = bytes([0xab, 0x77, 0x88, 0xd2, 0x2e, 0xb7, 0x37, 0x2f])
SPEC_ENVELOPE = bytes([
    0x00, 0x00, 0x00, 0x00, 0x2a, 0x4d, 0xee, 0xdd,
    0x7b, 0xab, 0x88, 0x17, 0xec, 0xab, 0x77, 0x88,
    0xd2, 0x2e, 0xb7, 0x37, 0x2f, 0xc8, 0xc5, 0xaa,
    0x56, 0xd7, 0x55, 0x58, 0x2b, 0xac, 0xea, 0x13,
    0xbb, 0x57, 0x24, 0x93, 0xbb, 0x8c, 0xb1, 0x08,
    0x03, 0xcf, 0x82, 0x6f, 0xdb, 0x83, 0x3b, 0x79,
    0xc6,
])


class TestHashDerivation:
    def test_derive_auth_hash_spec_vector(self):
        h = derive_auth_hash(SPEC_TOKEN)
        assert h == SPEC_AUTH_HASH

    def test_derive_auth_hash_without_prefix(self):
        h = derive_auth_hash("e2bd319014b24e0a8aca9f00aea4c0d0")
        assert h == SPEC_AUTH_HASH

    def test_derive_device_hash_spec_vector(self):
        h = derive_device_hash(SPEC_SERIAL)
        assert h == SPEC_DEVICE_HASH


class TestSpecVector:
    def test_seal_spec_vector(self):
        inner_frame = b"sensor-01|[temp:=32]"
        envelope = seal_uplink(0, inner_frame, 42, SPEC_AUTH_HASH, SPEC_DEVICE_HASH, SPEC_KEY)
        assert len(envelope) == 49
        assert envelope == SPEC_ENVELOPE

    def test_open_spec_vector(self):
        result = open_envelope(SPEC_ENVELOPE, SPEC_KEY)
        assert result.method == 0  # PUSH
        assert result.header.counter == 42
        assert result.header.auth_hash == SPEC_AUTH_HASH
        assert result.header.device_hash == SPEC_DEVICE_HASH
        assert result.plaintext == b"sensor-01|[temp:=32]"


class TestRoundTrip:
    def test_round_trip_push(self):
        auth_hash = derive_auth_hash(SPEC_TOKEN)
        device_hash = derive_device_hash(SPEC_SERIAL)
        inner = b"sensor-01|[temperature:=32.5;humidity:=65]"
        envelope = seal_uplink(0, inner, 1, auth_hash, device_hash, SPEC_KEY)
        result = open_envelope(envelope, SPEC_KEY)
        assert result.method == 0
        assert result.plaintext == inner

    def test_round_trip_ping(self):
        auth_hash = derive_auth_hash(SPEC_TOKEN)
        device_hash = derive_device_hash(SPEC_SERIAL)
        inner = b"sensor-01"
        envelope = seal_uplink(2, inner, 100, auth_hash, device_hash, SPEC_KEY)
        result = open_envelope(envelope, SPEC_KEY)
        assert result.method == 2
        assert result.plaintext == inner

    def test_round_trip_ack(self):
        auth_hash = derive_auth_hash(SPEC_TOKEN)
        device_hash = derive_device_hash(SPEC_SERIAL)
        inner = b"OK|3"
        envelope = seal_uplink(3, inner, 1, auth_hash, device_hash, SPEC_KEY)
        result = open_envelope(envelope, SPEC_KEY)
        assert result.method == 3
        assert result.plaintext == inner


class TestErrorCases:
    def test_wrong_key(self):
        wrong_key = bytes(16)
        with pytest.raises(ValueError):
            open_envelope(SPEC_ENVELOPE, wrong_key)

    def test_too_short_envelope(self):
        with pytest.raises(ValueError):
            open_envelope(SPEC_ENVELOPE[:10], SPEC_KEY)

    def test_tampered_ciphertext(self):
        tampered = bytearray(SPEC_ENVELOPE)
        tampered[25] ^= 0xFF
        with pytest.raises(ValueError):
            open_envelope(bytes(tampered), SPEC_KEY)

    def test_tampered_header(self):
        tampered = bytearray(SPEC_ENVELOPE)
        tampered[5] ^= 0xFF
        with pytest.raises(ValueError):
            open_envelope(bytes(tampered), SPEC_KEY)

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            seal_uplink(0, b"test", 1, SPEC_AUTH_HASH, SPEC_DEVICE_HASH, bytes(8))


class TestIsEnvelope:
    def test_non_ack_is_envelope(self):
        assert is_envelope(bytes([0x00, 0x01, 0x02])) is True

    def test_ack_not_envelope(self):
        assert is_envelope(bytes([0x41, 0x43, 0x4B])) is False

    def test_empty_not_envelope(self):
        assert is_envelope(bytes()) is False


class TestParseEnvelopeHeader:
    def test_parse_spec_header(self):
        header = parse_envelope_header(SPEC_ENVELOPE)
        assert header.flags == 0x00
        assert header.counter == 42
        assert header.auth_hash == SPEC_AUTH_HASH
        assert header.device_hash == SPEC_DEVICE_HASH
