"""Build functions — convert typed objects into raw TagoTiP frame strings."""

from __future__ import annotations

from tagotip.types import (
    AckFrame,
    AckStatus,
    MetaPair,
    Method,
    Operator,
    PassthroughEncoding,
    UplinkFrame,
    Variable,
)


def _write_value(v: Variable) -> str:
    val = v.value
    if v.operator == Operator.NUMBER:
        return f":={val.str_value}" if val.str_value is not None else ":="
    elif v.operator == Operator.STRING:
        return f"={val.str_value}" if val.str_value is not None else "="
    elif v.operator == Operator.BOOLEAN:
        return f"?={'true' if val.bool_value else 'false'}"
    elif v.operator == Operator.LOCATION:
        if val.location is None:
            return "@="
        loc = val.location
        s = f"@={loc.lat},{loc.lng}"
        if loc.alt is not None:
            s += f",{loc.alt}"
        return s
    return "="


def _write_meta(pairs: list[MetaPair]) -> str:
    inner = ",".join(f"{p.key}={p.value}" for p in pairs)
    return f"{{{inner}}}"


def _write_variable(v: Variable) -> str:
    s = v.name + _write_value(v)
    if v.unit is not None:
        s += f"#{v.unit}"
    if v.timestamp is not None:
        s += f"@{v.timestamp}"
    if v.group is not None:
        s += f"^{v.group}"
    if v.meta:
        s += _write_meta(v.meta)
    return s


def build_uplink(frame: UplinkFrame) -> str:
    """Build a raw uplink frame string from an UplinkFrame."""
    parts: list[str] = [frame.method.value]

    if frame.seq is not None:
        parts.append(f"!{frame.seq}")

    parts.append(frame.auth)
    parts.append(frame.serial)

    result = "|".join(parts)

    if frame.method == Method.PUSH and frame.push_body is not None:
        pb = frame.push_body
        if pb.passthrough is not None:
            pt = pb.passthrough
            prefix = ">x" if pt.encoding == PassthroughEncoding.HEX else ">b"
            result += f"|{prefix}{pt.data}"
        elif pb.structured is not None:
            sb = pb.structured
            body = ""
            if sb.timestamp is not None:
                body += f"@{sb.timestamp}"
            if sb.group is not None:
                body += f"^{sb.group}"
            if sb.meta:
                body += _write_meta(sb.meta)
            body += "[" + ";".join(_write_variable(v) for v in sb.variables) + "]"
            result += f"|{body}"
    elif frame.method == Method.PULL and frame.pull_body is not None:
        result += "|[" + ";".join(frame.pull_body.variables) + "]"

    return result


def build_ack(frame: AckFrame) -> str:
    """Build a raw ACK frame string from an AckFrame."""
    parts: list[str] = ["ACK"]

    if frame.seq is not None:
        parts.append(f"!{frame.seq}")

    parts.append(frame.status.value)

    if frame.detail is not None:
        d = frame.detail
        if d.type == "count" and d.count is not None:
            parts.append(str(d.count))
        elif d.type in ("variables", "command", "error", "raw") and d.text is not None:
            parts.append(d.text)

    return "|".join(parts)
