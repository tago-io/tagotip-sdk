"""Core types for the TagoTiP protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Method(Enum):
    """Uplink frame method."""

    PUSH = "PUSH"
    PULL = "PULL"
    PING = "PING"


class Operator(Enum):
    """Variable value type hint (operator)."""

    NUMBER = "number"  # :=
    STRING = "string"  # =
    BOOLEAN = "boolean"  # ?=
    LOCATION = "location"  # @=


class AckStatus(Enum):
    """ACK response status."""

    OK = "OK"
    PONG = "PONG"
    CMD = "CMD"
    ERR = "ERR"


class ErrorCode(Enum):
    """Known error codes from the protocol spec."""

    INVALID_TOKEN = "INVALID_TOKEN"
    INVALID_METHOD = "INVALID_METHOD"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    INVALID_SEQ = "INVALID_SEQ"
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    VARIABLE_NOT_FOUND = "VARIABLE_NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_FAILED = "AUTH_FAILED"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    SERVER_ERROR = "SERVER_ERROR"
    UNKNOWN = "UNKNOWN"


class PassthroughEncoding(Enum):
    """Passthrough binary encoding."""

    HEX = "hex"
    BASE64 = "base64"


@dataclass
class MetaPair:
    """A metadata key-value pair."""

    key: str
    value: str


@dataclass
class LocationValue:
    """A location value with lat/lng/alt."""

    lat: str
    lng: str
    alt: Optional[str] = None


@dataclass
class Value:
    """Parsed variable value."""

    type: Operator
    str_value: Optional[str] = None  # For Number/String
    bool_value: Optional[bool] = None  # For Boolean
    location: Optional[LocationValue] = None  # For Location


@dataclass
class Variable:
    """A parsed variable with optional suffixes."""

    name: str
    operator: Operator
    value: Value
    unit: Optional[str] = None
    timestamp: Optional[str] = None
    group: Optional[str] = None
    meta: list[MetaPair] = field(default_factory=list)


@dataclass
class StructuredBody:
    """Structured PUSH body."""

    variables: list[Variable] = field(default_factory=list)
    group: Optional[str] = None
    timestamp: Optional[str] = None
    meta: list[MetaPair] = field(default_factory=list)


@dataclass
class PassthroughBody:
    """Passthrough PUSH body."""

    encoding: PassthroughEncoding
    data: str


@dataclass
class PushBody:
    """PUSH body — either structured or passthrough."""

    structured: Optional[StructuredBody] = None
    passthrough: Optional[PassthroughBody] = None


@dataclass
class PullBody:
    """PULL body: list of variable names."""

    variables: list[str] = field(default_factory=list)


@dataclass
class UplinkFrame:
    """A fully parsed uplink frame."""

    method: Method
    auth: str
    serial: str
    seq: Optional[int] = None
    push_body: Optional[PushBody] = None
    pull_body: Optional[PullBody] = None


@dataclass
class AckDetail:
    """ACK detail."""

    type: str  # "count", "variables", "command", "error", "raw"
    count: Optional[int] = None
    text: Optional[str] = None
    error_code: Optional[ErrorCode] = None


@dataclass
class AckFrame:
    """A parsed ACK (downlink) frame."""

    status: AckStatus
    seq: Optional[int] = None
    detail: Optional[AckDetail] = None
