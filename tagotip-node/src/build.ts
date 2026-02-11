import {
  Method,
  Operator,
  AckStatus,
  PassthroughEncoding,
} from "./types.ts";
import type {
  UplinkFrame,
  AckFrame,
  PushBody,
  PullBody,
  StructuredBody,
  Variable,
  MetaPair,
  AckDetail,
} from "./types.ts";

function writeValue(op: Operator, value: Variable["value"]): string {
  switch (op) {
    case Operator.Number:
      if (value.type !== "number") return ":=";
      return `:=${value.value}`;
    case Operator.String:
      if (value.type !== "string") return "=";
      return `=${value.value}`;
    case Operator.Boolean:
      if (value.type !== "boolean") return "?=";
      return `?=${value.value ? "true" : "false"}`;
    case Operator.Location: {
      if (value.type !== "location") return "@=";
      const loc = value.value;
      let s = `@=${loc.lat},${loc.lng}`;
      if (loc.alt !== undefined) s += `,${loc.alt}`;
      return s;
    }
  }
}

function writeMetaPairs(pairs: MetaPair[]): string {
  let s = "{";
  for (let i = 0; i < pairs.length; i++) {
    if (i > 0) s += ",";
    s += `${pairs[i].key}=${pairs[i].value}`;
  }
  s += "}";
  return s;
}

function writeVariable(v: Variable): string {
  let s = v.name;
  s += writeValue(v.operator, v.value);
  if (v.unit !== undefined) s += `#${v.unit}`;
  if (v.timestamp !== undefined) s += `@${v.timestamp}`;
  if (v.group !== undefined) s += `^${v.group}`;
  if (v.meta !== undefined && v.meta.length > 0) s += writeMetaPairs(v.meta);
  return s;
}

function writePushBody(body: PushBody): string {
  if (body.type === "passthrough") {
    const pt = body.body;
    const prefix =
      pt.encoding === PassthroughEncoding.Hex ? ">x" : ">b";
    return `${prefix}${pt.data}`;
  }

  const sb = body.body;
  let s = "";

  // Body-level modifiers
  if (sb.group !== undefined) s += `^${sb.group}`;
  if (sb.timestamp !== undefined) s += `@${sb.timestamp}`;
  if (sb.meta !== undefined && sb.meta.length > 0) s += writeMetaPairs(sb.meta);

  // Variables
  s += "[";
  for (let i = 0; i < sb.variables.length; i++) {
    if (i > 0) s += ";";
    s += writeVariable(sb.variables[i]);
  }
  s += "]";
  return s;
}

function writePullBody(body: PullBody): string {
  return `[${body.variables.join(";")}]`;
}

export function buildUplink(frame: UplinkFrame): string {
  const parts: string[] = [];

  // METHOD
  switch (frame.method) {
    case Method.Push: parts.push("PUSH"); break;
    case Method.Pull: parts.push("PULL"); break;
    case Method.Ping: parts.push("PING"); break;
  }

  // !SEQ
  if (frame.seq !== undefined) parts.push(`!${frame.seq}`);

  // AUTH
  parts.push(frame.auth);

  // SERIAL
  parts.push(frame.serial);

  let result = parts.join("|");

  // BODY
  if (frame.method === Method.Push && frame.pushBody) {
    result += "|" + writePushBody(frame.pushBody);
  } else if (frame.method === Method.Pull && frame.pullBody) {
    result += "|" + writePullBody(frame.pullBody);
  }

  return result;
}

export function buildAck(frame: AckFrame): string {
  const parts: string[] = ["ACK"];

  if (frame.seq !== undefined) parts.push(`!${frame.seq}`);

  switch (frame.status) {
    case AckStatus.Ok: parts.push("OK"); break;
    case AckStatus.Pong: parts.push("PONG"); break;
    case AckStatus.Cmd: parts.push("CMD"); break;
    case AckStatus.Err: parts.push("ERR"); break;
  }

  if (frame.detail !== undefined) {
    switch (frame.detail.type) {
      case "count":
        parts.push(String(frame.detail.count));
        break;
      case "variables":
        parts.push(frame.detail.raw);
        break;
      case "command":
        parts.push(frame.detail.command);
        break;
      case "error":
        parts.push(frame.detail.text);
        break;
      case "raw":
        parts.push(frame.detail.text);
        break;
    }
  }

  return parts.join("|");
}
