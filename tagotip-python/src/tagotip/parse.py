"""Parse functions — convert raw TagoTiP frames into typed objects."""

from __future__ import annotations

from tagotip._tagotip_native import parse_uplink_native, parse_ack_native
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


def _convert_meta(raw_list: list[dict] | None) -> list[MetaPair]:
    if not raw_list:
        return []
    return [MetaPair(key=m["key"], value=m["value"]) for m in raw_list]


def _convert_value(raw: dict) -> Value:
    vtype = raw["type"]
    if vtype == "number":
        return Value(type=Operator.NUMBER, str_value=raw.get("str_value"))
    elif vtype == "string":
        return Value(type=Operator.STRING, str_value=raw.get("str_value"))
    elif vtype == "boolean":
        return Value(type=Operator.BOOLEAN, bool_value=raw.get("bool_value"))
    elif vtype == "location":
        loc_raw = raw["location"]
        return Value(
            type=Operator.LOCATION,
            location=LocationValue(
                lat=loc_raw["lat"],
                lng=loc_raw["lng"],
                alt=loc_raw.get("alt"),
            ),
        )
    raise ValueError(f"unknown value type: {vtype}")


_OPERATOR_MAP = {
    "number": Operator.NUMBER,
    "string": Operator.STRING,
    "boolean": Operator.BOOLEAN,
    "location": Operator.LOCATION,
}


def _convert_variable(raw: dict) -> Variable:
    return Variable(
        name=raw["name"],
        operator=_OPERATOR_MAP[raw["operator"]],
        value=_convert_value(raw["value"]),
        unit=raw.get("unit"),
        timestamp=raw.get("timestamp"),
        group=raw.get("group"),
        meta=_convert_meta(raw.get("meta")),
    )


def parse_uplink(input: str) -> UplinkFrame:
    """Parse a raw uplink frame string into an UplinkFrame."""
    raw = parse_uplink_native(input)

    push_body = None
    pull_body = None

    if "push_body" in raw:
        pb = raw["push_body"]
        if pb["type"] == "structured":
            push_body = PushBody(
                structured=StructuredBody(
                    variables=[_convert_variable(v) for v in pb["variables"]],
                    group=pb.get("group"),
                    timestamp=pb.get("timestamp"),
                    meta=_convert_meta(pb.get("meta")),
                )
            )
        elif pb["type"] == "passthrough":
            enc = (
                PassthroughEncoding.HEX
                if pb["encoding"] == "hex"
                else PassthroughEncoding.BASE64
            )
            push_body = PushBody(
                passthrough=PassthroughBody(encoding=enc, data=pb["data"])
            )

    if "pull_body" in raw:
        pull_body = PullBody(variables=list(raw["pull_body"]["variables"]))

    return UplinkFrame(
        method=Method(raw["method"]),
        auth=raw["auth"],
        serial=raw["serial"],
        seq=raw.get("seq"),
        push_body=push_body,
        pull_body=pull_body,
    )


_ERROR_CODE_MAP = {
    "INVALID_TOKEN": ErrorCode.INVALID_TOKEN,
    "INVALID_METHOD": ErrorCode.INVALID_METHOD,
    "INVALID_PAYLOAD": ErrorCode.INVALID_PAYLOAD,
    "INVALID_SEQ": ErrorCode.INVALID_SEQ,
    "DEVICE_NOT_FOUND": ErrorCode.DEVICE_NOT_FOUND,
    "VARIABLE_NOT_FOUND": ErrorCode.VARIABLE_NOT_FOUND,
    "RATE_LIMITED": ErrorCode.RATE_LIMITED,
    "AUTH_FAILED": ErrorCode.AUTH_FAILED,
    "UNSUPPORTED_VERSION": ErrorCode.UNSUPPORTED_VERSION,
    "PAYLOAD_TOO_LARGE": ErrorCode.PAYLOAD_TOO_LARGE,
    "SERVER_ERROR": ErrorCode.SERVER_ERROR,
    "UNKNOWN": ErrorCode.UNKNOWN,
}


def parse_ack(input: str) -> AckFrame:
    """Parse a raw ACK frame string into an AckFrame."""
    raw = parse_ack_native(input)

    detail = None
    if "detail" in raw:
        d = raw["detail"]
        dtype = d["type"]
        if dtype == "count":
            detail = AckDetail(type="count", count=d["count"])
        elif dtype == "variables":
            detail = AckDetail(type="variables", text=d["text"])
        elif dtype == "command":
            detail = AckDetail(type="command", text=d["text"])
        elif dtype == "error":
            detail = AckDetail(
                type="error",
                error_code=_ERROR_CODE_MAP.get(d["error_code"], ErrorCode.UNKNOWN),
                text=d["text"],
            )
        elif dtype == "raw":
            detail = AckDetail(type="raw", text=d["text"])

    return AckFrame(
        status=AckStatus(raw["status"]),
        seq=raw.get("seq"),
        detail=detail,
    )
