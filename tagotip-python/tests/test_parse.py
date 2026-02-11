"""Tests for tagotip types and structure."""

from tagotip.types import (
    AckDetail,
    AckFrame,
    AckStatus,
    ErrorCode,
    LocationValue,
    MetaPair,
    Method,
    Operator,
    PassthroughBody,
    PassthroughEncoding,
    PullBody,
    PushBody,
    StructuredBody,
    UplinkFrame,
    Value,
    Variable,
)


# =========================================================================
# Existing tests
# =========================================================================


def test_types_importable():
    """Verify that all core types can be imported and constructed."""
    var = Variable(
        name="temperature",
        operator=Operator.NUMBER,
        value=Value(type=Operator.NUMBER, str_value="25.3"),
        unit="C",
    )
    assert var.name == "temperature"
    assert var.operator == Operator.NUMBER
    assert var.unit == "C"


def test_uplink_frame_construction():
    """Verify UplinkFrame can be constructed."""
    frame = UplinkFrame(
        method=Method.PUSH,
        auth="at0123456789abcdef0123456789abcdef",
        serial="my-device",
    )
    assert frame.method == Method.PUSH
    assert frame.serial == "my-device"
    assert frame.seq is None
    assert frame.push_body is None


def test_ack_frame_construction():
    """Verify AckFrame can be constructed."""
    ack = AckFrame(
        status=AckStatus.OK,
        seq=1,
    )
    assert ack.status == AckStatus.OK
    assert ack.seq == 1
    assert ack.detail is None


def test_method_enum_values():
    """Verify Method enum values."""
    assert Method.PUSH.value == "PUSH"
    assert Method.PULL.value == "PULL"
    assert Method.PING.value == "PING"


# =========================================================================
# New tests: Enum values
# =========================================================================


def test_operator_enum_values():
    """Verify all 4 Operator enum values."""
    assert Operator.NUMBER.value == "number"
    assert Operator.STRING.value == "string"
    assert Operator.BOOLEAN.value == "boolean"
    assert Operator.LOCATION.value == "location"


def test_ack_status_enum_values():
    """Verify all 4 AckStatus enum values."""
    assert AckStatus.OK.value == "OK"
    assert AckStatus.PONG.value == "PONG"
    assert AckStatus.CMD.value == "CMD"
    assert AckStatus.ERR.value == "ERR"


def test_error_code_enum_values():
    """Verify all 12 ErrorCode enum values."""
    expected = {
        ErrorCode.INVALID_TOKEN: "INVALID_TOKEN",
        ErrorCode.INVALID_METHOD: "INVALID_METHOD",
        ErrorCode.INVALID_PAYLOAD: "INVALID_PAYLOAD",
        ErrorCode.INVALID_SEQ: "INVALID_SEQ",
        ErrorCode.DEVICE_NOT_FOUND: "DEVICE_NOT_FOUND",
        ErrorCode.VARIABLE_NOT_FOUND: "VARIABLE_NOT_FOUND",
        ErrorCode.RATE_LIMITED: "RATE_LIMITED",
        ErrorCode.AUTH_FAILED: "AUTH_FAILED",
        ErrorCode.UNSUPPORTED_VERSION: "UNSUPPORTED_VERSION",
        ErrorCode.PAYLOAD_TOO_LARGE: "PAYLOAD_TOO_LARGE",
        ErrorCode.SERVER_ERROR: "SERVER_ERROR",
        ErrorCode.UNKNOWN: "UNKNOWN",
    }
    for code, value in expected.items():
        assert code.value == value, f"expected {value}, got {code.value}"
    assert len(ErrorCode) == 12


def test_passthrough_encoding_enum():
    """Verify PassthroughEncoding enum values."""
    assert PassthroughEncoding.HEX.value == "hex"
    assert PassthroughEncoding.BASE64.value == "base64"


# =========================================================================
# Variable construction
# =========================================================================


def test_variable_all_fields():
    """Verify Variable with all optional fields populated."""
    var = Variable(
        name="temperature",
        operator=Operator.NUMBER,
        value=Value(type=Operator.NUMBER, str_value="32.5"),
        unit="C",
        timestamp="1694567890000",
        group="batch_01",
        meta=[
            MetaPair(key="source", value="dht22"),
            MetaPair(key="quality", value="high"),
        ],
    )
    assert var.name == "temperature"
    assert var.unit == "C"
    assert var.timestamp == "1694567890000"
    assert var.group == "batch_01"
    assert len(var.meta) == 2
    assert var.meta[0].key == "source"
    assert var.meta[1].value == "high"


def test_variable_minimal():
    """Verify Variable with only required fields."""
    var = Variable(
        name="status",
        operator=Operator.STRING,
        value=Value(type=Operator.STRING, str_value="online"),
    )
    assert var.name == "status"
    assert var.unit is None
    assert var.timestamp is None
    assert var.group is None
    assert var.meta == []


# =========================================================================
# UplinkFrame variants
# =========================================================================


def test_uplink_frame_push_structured():
    """Verify full structured body construction."""
    frame = UplinkFrame(
        method=Method.PUSH,
        auth="at0123456789abcdef0123456789abcdef",
        serial="sensor_01",
        push_body=PushBody(
            structured=StructuredBody(
                group="batch_42",
                timestamp="1694567890000",
                meta=[MetaPair(key="firmware", value="2.1")],
                variables=[
                    Variable(
                        name="temperature",
                        operator=Operator.NUMBER,
                        value=Value(type=Operator.NUMBER, str_value="32"),
                        unit="C",
                    ),
                    Variable(
                        name="humidity",
                        operator=Operator.NUMBER,
                        value=Value(type=Operator.NUMBER, str_value="65"),
                        unit="%",
                    ),
                ],
            )
        ),
    )
    assert frame.push_body is not None
    assert frame.push_body.structured is not None
    assert frame.push_body.structured.group == "batch_42"
    assert frame.push_body.structured.timestamp == "1694567890000"
    assert len(frame.push_body.structured.meta) == 1
    assert len(frame.push_body.structured.variables) == 2


def test_uplink_frame_push_passthrough():
    """Verify passthrough body construction."""
    frame = UplinkFrame(
        method=Method.PUSH,
        auth="at0123456789abcdef0123456789abcdef",
        serial="sensor_01",
        push_body=PushBody(
            passthrough=PassthroughBody(
                encoding=PassthroughEncoding.HEX,
                data="DEADBEEF",
            )
        ),
    )
    assert frame.push_body is not None
    assert frame.push_body.passthrough is not None
    assert frame.push_body.passthrough.encoding == PassthroughEncoding.HEX
    assert frame.push_body.passthrough.data == "DEADBEEF"


def test_uplink_frame_pull():
    """Verify PULL frame construction."""
    frame = UplinkFrame(
        method=Method.PULL,
        auth="at0123456789abcdef0123456789abcdef",
        serial="weather_denver",
        pull_body=PullBody(variables=["temperature", "humidity"]),
    )
    assert frame.method == Method.PULL
    assert frame.pull_body is not None
    assert len(frame.pull_body.variables) == 2
    assert frame.pull_body.variables[0] == "temperature"


def test_uplink_frame_ping():
    """Verify PING frame construction (no body)."""
    frame = UplinkFrame(
        method=Method.PING,
        auth="at0123456789abcdef0123456789abcdef",
        serial="sensor_01",
    )
    assert frame.method == Method.PING
    assert frame.push_body is None
    assert frame.pull_body is None


# =========================================================================
# AckFrame variants
# =========================================================================


def test_ack_frame_all_statuses():
    """Verify AckFrame with each status."""
    for status in AckStatus:
        ack = AckFrame(status=status)
        assert ack.status == status
        assert ack.detail is None


def test_ack_detail_count():
    """Verify AckDetail with count type."""
    detail = AckDetail(type="count", count=5)
    assert detail.type == "count"
    assert detail.count == 5


def test_ack_detail_error():
    """Verify AckDetail with error code."""
    detail = AckDetail(
        type="error",
        error_code=ErrorCode.INVALID_TOKEN,
        text="invalid_token",
    )
    assert detail.type == "error"
    assert detail.error_code == ErrorCode.INVALID_TOKEN
    assert detail.text == "invalid_token"


# =========================================================================
# Location and Meta
# =========================================================================


def test_location_value_with_alt():
    """Verify LocationValue with altitude."""
    loc = LocationValue(lat="39.74", lng="-104.99", alt="305")
    assert loc.lat == "39.74"
    assert loc.lng == "-104.99"
    assert loc.alt == "305"


def test_location_value_without_alt():
    """Verify LocationValue without altitude."""
    loc = LocationValue(lat="0", lng="0")
    assert loc.lat == "0"
    assert loc.lng == "0"
    assert loc.alt is None


def test_meta_pair():
    """Verify MetaPair construction."""
    mp = MetaPair(key="source", value="dht22")
    assert mp.key == "source"
    assert mp.value == "dht22"
