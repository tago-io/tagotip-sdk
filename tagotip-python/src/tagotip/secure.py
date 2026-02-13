"""TagoTiP/S secure crypto envelope support."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tagotip._tagotip_native import (
    derive_auth_hash_native,
    derive_device_hash_native,
    seal_uplink_native,
    open_envelope_native,
    parse_envelope_header_native,
    is_envelope_native,
)


@dataclass
class EnvelopeHeader:
    """Parsed envelope header (first 21 bytes)."""

    flags: int
    counter: int
    auth_hash: bytes
    device_hash: bytes


@dataclass
class OpenResult:
    """Result of opening a TagoTiP/S envelope."""

    header: EnvelopeHeader
    method: int
    plaintext: bytes


def derive_auth_hash(token: str) -> bytes:
    """Derive the Authorization Hash from a token.

    The token format is "at" + 32 hex chars. The "at" prefix is stripped,
    and SHA-256 is computed over the remaining hex string (UTF-8 encoded).
    Returns the first 8 bytes of the digest.
    """
    return bytes(derive_auth_hash_native(token))


def derive_device_hash(serial: str) -> bytes:
    """Derive the Device Hash from a serial number.

    Computes SHA-256 of the serial (UTF-8 encoded) and returns the first 8 bytes.
    """
    return bytes(derive_device_hash_native(serial))


def seal_uplink(
    method: int,
    inner_frame: bytes,
    counter: int,
    auth_hash: bytes,
    device_hash: bytes,
    key: bytes,
) -> bytes:
    """Encrypt a headless inner frame into a TagoTiP/S envelope.

    Args:
        method: Envelope method ID (0=PUSH, 1=PULL, 2=PING, 3=ACK).
        inner_frame: The headless inner frame bytes.
        counter: Sequence counter (4-byte big-endian in envelope).
        auth_hash: 8-byte authorization hash.
        device_hash: 8-byte device hash.
        key: 16-byte AES-128-CCM encryption key.

    Returns:
        The complete TagoTiP/S envelope bytes.
    """
    return bytes(seal_uplink_native(method, inner_frame, counter, auth_hash, device_hash, key))


def open_envelope(envelope: bytes, key: bytes) -> OpenResult:
    """Decrypt a TagoTiP/S envelope.

    Args:
        envelope: The complete envelope bytes.
        key: 16-byte AES-128-CCM encryption key.

    Returns:
        OpenResult with header, method, and decrypted plaintext.
    """
    raw = open_envelope_native(envelope, key)
    header = EnvelopeHeader(
        flags=raw["flags"],
        counter=raw["counter"],
        auth_hash=bytes(raw["auth_hash"]),
        device_hash=bytes(raw["device_hash"]),
    )
    return OpenResult(
        header=header,
        method=raw["method"],
        plaintext=bytes(raw["plaintext"]),
    )


def parse_envelope_header(envelope: bytes) -> EnvelopeHeader:
    """Parse the 21-byte envelope header for server-side routing."""
    raw = parse_envelope_header_native(envelope)
    return EnvelopeHeader(
        flags=raw["flags"],
        counter=raw["counter"],
        auth_hash=bytes(raw["auth_hash"]),
        device_hash=bytes(raw["device_hash"]),
    )


def is_envelope(data: bytes) -> bool:
    """Check if a message is a TagoTiP/S envelope or a plaintext fallback."""
    return is_envelope_native(data)
