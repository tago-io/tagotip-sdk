"""Functional tests for parse/build functions using the native PyO3 module."""

import pytest
from tagotip import (
    parse_uplink, parse_ack, build_uplink, build_ack,
    Method, Operator, AckStatus, ErrorCode, PassthroughEncoding,
    UplinkFrame, AckFrame, AckDetail, PushBody, PullBody,
    StructuredBody, PassthroughBody, Variable, Value, LocationValue, MetaPair,
)

AUTH = "at0123456789abcdef0123456789abcdef"


# =========================================================================
# ParseUplink — happy path
# =========================================================================

def test_parse_simple_push():
    f = parse_uplink(f"PUSH|{AUTH}|my-device|[temperature:=32.5;humidity:=65]")
    assert f.method == Method.PUSH
    assert f.auth == AUTH
    assert f.serial == "my-device"
    assert f.push_body is not None
    assert f.push_body.structured is not None
    vars = f.push_body.structured.variables
    assert len(vars) == 2
    assert vars[0].name == "temperature"
    assert vars[0].operator == Operator.NUMBER
    assert vars[0].value.str_value == "32.5"
    assert vars[1].name == "humidity"


def test_parse_push_with_seq():
    f = parse_uplink(f"PUSH|!42|{AUTH}|dev|[x:=1]")
    assert f.seq == 42


def test_parse_push_string():
    f = parse_uplink(f"PUSH|{AUTH}|dev|[status=online]")
    v = f.push_body.structured.variables[0]
    assert v.operator == Operator.STRING
    assert v.value.str_value == "online"


def test_parse_push_boolean():
    f = parse_uplink(f"PUSH|{AUTH}|dev|[active?=true]")
    v = f.push_body.structured.variables[0]
    assert v.operator == Operator.BOOLEAN
    assert v.value.bool_value is True

    f2 = parse_uplink(f"PUSH|{AUTH}|dev|[active?=false]")
    assert f2.push_body.structured.variables[0].value.bool_value is False


def test_parse_push_location():
    f = parse_uplink(f"PUSH|{AUTH}|dev|[pos@=39.74,-104.99,305]")
    v = f.push_body.structured.variables[0]
    assert v.operator == Operator.LOCATION
    assert v.value.location.lat == "39.74"
    assert v.value.location.lng == "-104.99"
    assert v.value.location.alt == "305"


def test_parse_push_location_no_alt():
    f = parse_uplink(f"PUSH|{AUTH}|dev|[pos@=39.74,-104.99]")
    assert f.push_body.structured.variables[0].value.location.alt is None


def test_parse_push_metadata():
    f = parse_uplink(f"PUSH|{AUTH}|dev|[temp:=32{{source=dht22,quality=high}}]")
    v = f.push_body.structured.variables[0]
    assert len(v.meta) == 2
    assert v.meta[0].key == "source"
    assert v.meta[0].value == "dht22"


def test_parse_push_body_modifiers():
    f = parse_uplink(f"PUSH|{AUTH}|dev|^batch@1694567890000{{source=dht22}}[temp:=32]")
    sb = f.push_body.structured
    assert sb.group == "batch"
    assert sb.timestamp == "1694567890000"
    assert len(sb.meta) == 1


def test_parse_push_all_suffixes():
    f = parse_uplink(f"PUSH|{AUTH}|dev|[temp:=32#C@1694567890000^batch{{source=dht22}}]")
    v = f.push_body.structured.variables[0]
    assert v.unit == "C"
    assert v.timestamp == "1694567890000"
    assert v.group == "batch"
    assert len(v.meta) == 1


def test_parse_passthrough_hex():
    f = parse_uplink(f"PUSH|{AUTH}|dev|>xDEADBEEF")
    assert f.push_body.passthrough is not None
    assert f.push_body.passthrough.encoding == PassthroughEncoding.HEX
    assert f.push_body.passthrough.data == "DEADBEEF"


def test_parse_passthrough_base64():
    f = parse_uplink(f"PUSH|{AUTH}|dev|>b3q2+7wECAwQ=")
    assert f.push_body.passthrough.encoding == PassthroughEncoding.BASE64


def test_parse_pull():
    f = parse_uplink(f"PULL|{AUTH}|dev|[temperature;humidity]")
    assert f.method == Method.PULL
    assert f.pull_body is not None
    assert f.pull_body.variables == ["temperature", "humidity"]


def test_parse_ping():
    f = parse_uplink(f"PING|{AUTH}|dev")
    assert f.method == Method.PING
    assert f.push_body is None
    assert f.pull_body is None


def test_parse_trailing_newline():
    f = parse_uplink(f"PING|{AUTH}|dev\n")
    assert f.method == Method.PING


# =========================================================================
# ParseUplink — error cases
# =========================================================================

def test_reject_empty():
    with pytest.raises(ValueError, match="empty_frame"):
        parse_uplink("")


def test_reject_invalid_method():
    with pytest.raises(ValueError, match="invalid_method"):
        parse_uplink(f"INVALID|{AUTH}|dev")


def test_reject_invalid_auth():
    with pytest.raises(ValueError, match="invalid_auth"):
        parse_uplink("PING|invalidtoken|dev")


def test_reject_missing_body_push():
    with pytest.raises(ValueError, match="missing_body"):
        parse_uplink(f"PUSH|{AUTH}|dev")


def test_reject_invalid_boolean():
    with pytest.raises(ValueError, match="invalid_variable"):
        parse_uplink(f"PUSH|{AUTH}|dev|[x?=maybe]")


def test_reject_leading_zero():
    with pytest.raises(ValueError, match="invalid_variable"):
        parse_uplink(f"PUSH|{AUTH}|dev|[x:=01]")


def test_reject_empty_string_value():
    with pytest.raises(ValueError, match="invalid_variable"):
        parse_uplink(f"PUSH|{AUTH}|dev|[x=]")


# =========================================================================
# ParseAck
# =========================================================================

def test_parse_ack_ok_count():
    f = parse_ack("ACK|OK|3")
    assert f.status == AckStatus.OK
    assert f.detail.type == "count"
    assert f.detail.count == 3


def test_parse_ack_pong():
    f = parse_ack("ACK|PONG")
    assert f.status == AckStatus.PONG


def test_parse_ack_cmd():
    f = parse_ack("ACK|CMD|reboot")
    assert f.detail.type == "command"
    assert f.detail.text == "reboot"


def test_parse_ack_err():
    f = parse_ack("ACK|ERR|invalid_token")
    assert f.status == AckStatus.ERR
    assert f.detail.type == "error"
    assert f.detail.error_code == ErrorCode.INVALID_TOKEN


def test_parse_ack_with_seq():
    f = parse_ack("ACK|!5|OK|3")
    assert f.seq == 5


def test_reject_invalid_ack():
    with pytest.raises(ValueError, match="invalid_ack"):
        parse_ack("")


# =========================================================================
# Build + round-trip
# =========================================================================

def test_roundtrip_simple_push():
    inp = f"PUSH|{AUTH}|dev|[temperature:=32.5;humidity:=65]"
    f = parse_uplink(inp)
    assert build_uplink(f) == inp


def test_roundtrip_push_with_seq():
    inp = f"PUSH|!42|{AUTH}|dev|[x:=1]"
    f = parse_uplink(inp)
    assert build_uplink(f) == inp


def test_roundtrip_push_all_suffixes():
    inp = f"PUSH|{AUTH}|dev|[temp:=32#C@1694567890000^batch{{source=dht22}}]"
    f = parse_uplink(inp)
    assert build_uplink(f) == inp


def test_roundtrip_passthrough_hex():
    inp = f"PUSH|{AUTH}|dev|>xDEADBEEF"
    f = parse_uplink(inp)
    assert build_uplink(f) == inp


def test_roundtrip_pull():
    inp = f"PULL|{AUTH}|dev|[temperature;humidity]"
    f = parse_uplink(inp)
    assert build_uplink(f) == inp


def test_roundtrip_ping():
    inp = f"PING|{AUTH}|dev"
    f = parse_uplink(inp)
    assert build_uplink(f) == inp


def test_roundtrip_ack():
    inp = "ACK|!5|OK|3"
    f = parse_ack(inp)
    assert build_ack(f) == inp


def test_roundtrip_ack_err():
    inp = "ACK|ERR|invalid_token"
    f = parse_ack(inp)
    assert build_ack(f) == inp
