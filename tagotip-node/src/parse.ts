import { AUTH_HASH_LEN, MAX_FRAME_SIZE, MAX_VARIABLES, MAX_META_PAIRS } from "./consts.ts";
import { TagotipError, type ParseErrorKind } from "./error.ts";
import {
  validateVarname,
  validateSerial,
  validateGroup,
  validateMetaKey,
  validateUnit,
  validateNumber,
} from "./validate.ts";
import {
  Method,
  Operator,
  AckStatus,
  ErrorCode,
  PassthroughEncoding,
} from "./types.ts";
import type {
  UplinkFrame,
  AckFrame,
  HeadlessFrame,
  PushBody,
  PullBody,
  StructuredBody,
  Variable,
  Value,
  MetaPair,
  AckDetail,
} from "./types.ts";

function fail(kind: ParseErrorKind, pos: number): never {
  throw new TagotipError(kind, pos);
}

// ---------------------------------------------------------------------------
// Field splitting
// ---------------------------------------------------------------------------

const MAX_FIELDS = 8;

function splitFields(input: string): string[] {
  const fields: string[] = [];
  let start = 0;
  let i = 0;
  while (i < input.length) {
    if (input[i] === "\\" && i + 1 < input.length) {
      i += 2;
      continue;
    }
    if (input[i] === "|") {
      fields.push(input.slice(start, i));
      start = i + 1;
      if (fields.length === MAX_FIELDS - 1) {
        fields.push(input.slice(start));
        return fields;
      }
    }
    i += 1;
  }
  fields.push(input.slice(start));
  return fields;
}

// ---------------------------------------------------------------------------
// Helper parsers
// ---------------------------------------------------------------------------

function parseMethod(s: string): Method {
  if (s === "PUSH") return Method.Push;
  if (s === "PULL") return Method.Pull;
  if (s === "PING") return Method.Ping;
  fail("invalid_method", 0);
}

function parseSeq(s: string, pos: number): number {
  if (s[0] !== "!") fail("invalid_seq", pos);
  const numStr = s.slice(1);
  if (numStr.length === 0) fail("invalid_seq", pos);
  if (numStr.length > 1 && numStr[0] === "0") fail("invalid_seq", pos);
  const n = parseU32(numStr);
  if (n === null) fail("invalid_seq", pos);
  return n;
}

function parseU32(s: string): number | null {
  if (s.length === 0) return null;
  let result = 0;
  for (let i = 0; i < s.length; i++) {
    const d = s.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return null;
    result = result * 10 + d;
    if (result > 0xFFFF_FFFF) return null;
  }
  return result;
}

function validateAuth(s: string, pos: number): void {
  if (s.length !== AUTH_HASH_LEN) fail("invalid_auth", pos);
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (
      !((ch >= "0" && ch <= "9") || (ch >= "a" && ch <= "f") || (ch >= "A" && ch <= "F"))
    ) {
      fail("invalid_auth", pos);
    }
  }
}

// ---------------------------------------------------------------------------
// Byte-level scanning helpers
// ---------------------------------------------------------------------------

function findUnescapedChar(s: string, target: string, start = 0): number {
  let i = start;
  while (i < s.length) {
    if (s[i] === "\\" && i + 1 < s.length) {
      i += 2;
      continue;
    }
    if (s[i] === target) return i;
    i += 1;
  }
  return -1;
}

function findClosingBracket(s: string, start: number): number {
  let i = start;
  let depth = 1;
  while (i < s.length) {
    if (s[i] === "\\" && i + 1 < s.length) {
      i += 2;
      continue;
    }
    if (s[i] === "[") depth++;
    else if (s[i] === "]") {
      depth--;
      if (depth === 0) return i;
    }
    i += 1;
  }
  return -1;
}

function findClosingBrace(s: string, start: number): number {
  let i = start;
  while (i < s.length) {
    if (s[i] === "\\" && i + 1 < s.length) {
      i += 2;
      continue;
    }
    if (s[i] === "}") return i;
    i += 1;
  }
  return -1;
}

function scanUntilAny(s: string, pos: number, stops: string): number {
  let i = pos;
  while (i < s.length) {
    if (s[i] === "\\" && i + 1 < s.length) {
      i += 2;
      continue;
    }
    if (stops.includes(s[i])) return i;
    i += 1;
  }
  return i;
}

function validateDigits(s: string, pos: number): void {
  if (s.length === 0) fail("invalid_modifier", pos);
  for (let i = 0; i < s.length; i++) {
    if (s[i] < "0" || s[i] > "9") fail("invalid_modifier", pos);
  }
}

function validateTimestamp(s: string, pos: number): void {
  if (s.length === 0) fail("invalid_variable", pos);
  for (let i = 0; i < s.length; i++) {
    if (s[i] < "0" || s[i] > "9") fail("invalid_variable", pos);
  }
}

function isHexDigit(ch: string): boolean {
  return (ch >= "0" && ch <= "9") || (ch >= "a" && ch <= "f") || (ch >= "A" && ch <= "F");
}

// ---------------------------------------------------------------------------
// Metadata parsing
// ---------------------------------------------------------------------------

function parseMetaPair(s: string, pos: number): MetaPair {
  let i = 0;
  while (i < s.length) {
    if (s[i] === "\\" && i + 1 < s.length) {
      i += 2;
      continue;
    }
    if (s[i] === "=") {
      const key = s.slice(0, i);
      const value = s.slice(i + 1);
      validateMetaKey(key, pos);
      return { key, value };
    }
    i += 1;
  }
  fail("invalid_metadata", pos);
}

function parseMetadata(s: string, basePos: number): MetaPair[] {
  if (s.length === 0) fail("invalid_metadata", basePos);

  const pairs: MetaPair[] = [];
  let start = 0;
  let i = 0;

  for (;;) {
    const atEnd = i >= s.length;
    const isComma = !atEnd && s[i] === ",";

    if (atEnd || isComma) {
      const pairStr = s.slice(start, i);
      if (pairStr.length > 0) {
        if (pairs.length >= MAX_META_PAIRS) fail("too_many_items", basePos + start);
        pairs.push(parseMetaPair(pairStr, basePos + start));
      }
      if (atEnd) break;
      start = i + 1;
      i += 1;
      continue;
    }

    if (s[i] === "\\" && i + 1 < s.length) {
      i += 2;
      continue;
    }
    i += 1;
  }

  if (pairs.length === 0) fail("invalid_metadata", basePos);
  return pairs;
}

// ---------------------------------------------------------------------------
// Variable parsing
// ---------------------------------------------------------------------------

function findOperator(s: string, basePos: number): [number, number, Operator] {
  let i = 0;
  while (i < s.length) {
    if (s[i] === "\\" && i + 1 < s.length) {
      i += 2;
      continue;
    }
    if (i + 1 < s.length && s[i + 1] === "=") {
      if (s[i] === ":") return [i, 2, Operator.Number];
      if (s[i] === "?") return [i, 2, Operator.Boolean];
      if (s[i] === "@") return [i, 2, Operator.Location];
    }
    if (s[i] === "=") return [i, 1, Operator.String];
    i += 1;
  }
  fail("invalid_variable", basePos);
}

function scanValue(s: string, pos: number): [number, number] {
  let i = pos;
  while (i < s.length) {
    const ch = s[i];
    if (ch === "\\" && i + 1 < s.length) {
      i += 2;
      continue;
    }
    if (ch === "#" || ch === "@" || ch === "^" || ch === "{") return [i, i];
    i += 1;
  }
  return [i, i];
}

function parseValue(s: string, op: Operator, pos: number): Value {
  switch (op) {
    case Operator.Number:
      if (s.length === 0) fail("invalid_variable", pos);
      validateNumber(s, pos);
      return { type: "number", value: s };
    case Operator.String:
      if (s.length === 0) fail("invalid_variable", pos);
      return { type: "string", value: s };
    case Operator.Boolean:
      if (s === "true") return { type: "boolean", value: true };
      if (s === "false") return { type: "boolean", value: false };
      fail("invalid_variable", pos);
      break; // unreachable
    case Operator.Location:
      return parseLocation(s, pos);
  }
}

function parseLocation(s: string, pos: number): Value {
  // Count commas to detect > 3 components
  let commaCount = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === ",") commaCount++;
  }
  if (commaCount > 2) fail("invalid_variable", pos);

  const parts = s.split(",");
  const lat = parts[0];
  const lng = parts[1];
  if (lat === undefined || lng === undefined) fail("invalid_variable", pos);
  if (lat.length === 0 || lng.length === 0) fail("invalid_variable", pos);

  validateNumber(lat, pos);
  validateNumber(lng, pos);

  const altStr = parts[2];
  if (altStr !== undefined) {
    if (altStr.length === 0) fail("invalid_variable", pos);
    validateNumber(altStr, pos);
    return { type: "location", value: { lat, lng, alt: altStr } };
  }
  return { type: "location", value: { lat, lng } };
}

function parseVariable(s: string, basePos: number): Variable {
  const [opPos, opLen, operator] = findOperator(s, basePos);
  const name = s.slice(0, opPos);
  if (name.length === 0) fail("invalid_variable", basePos);
  validateVarname(name, basePos);

  let pos = opPos + opLen;

  // Scan value
  const valueStart = pos;
  const [valueEnd, newPos] = scanValue(s, pos);
  pos = newPos;
  const valueStr = s.slice(valueStart, valueEnd);
  const value = parseValue(valueStr, operator, basePos + valueStart);

  let unit: string | undefined;
  let timestamp: string | undefined;
  let group: string | undefined;
  let meta: MetaPair[] | undefined;

  // #unit — NOT allowed with @= (location)
  if (pos < s.length && s[pos] === "#") {
    if (operator === Operator.Location) {
      fail("invalid_variable", basePos + pos);
    }
    pos += 1;
    const start = pos;
    pos = scanUntilAny(s, pos, "@^{");
    const u = s.slice(start, pos);
    validateUnit(u, basePos + start);
    unit = u;
  }

  // @timestamp
  if (pos < s.length && s[pos] === "@") {
    pos += 1;
    const start = pos;
    pos = scanUntilAny(s, pos, "^{");
    const ts = s.slice(start, pos);
    validateTimestamp(ts, basePos + start);
    timestamp = ts;
  }

  // ^group
  if (pos < s.length && s[pos] === "^") {
    pos += 1;
    const start = pos;
    pos = scanUntilAny(s, pos, "{");
    const g = s.slice(start, pos);
    validateGroup(g, basePos + start);
    group = g;
  }

  // {metadata}
  if (pos < s.length && s[pos] === "{") {
    pos += 1;
    const start = pos;
    const end = findClosingBrace(s, pos);
    if (end === -1) fail("invalid_metadata", basePos + start);
    const metaStr = s.slice(start, end);
    meta = parseMetadata(metaStr, basePos + start);
    pos = end + 1;
  }

  return { name, operator, value, unit, timestamp, group, meta };
}

// ---------------------------------------------------------------------------
// Variable list parsing
// ---------------------------------------------------------------------------

function parseVariableList(s: string, basePos: number): Variable[] {
  const variables: Variable[] = [];
  let start = 0;
  let i = 0;

  for (;;) {
    const atEnd = i >= s.length;
    const isSemi = !atEnd && s[i] === ";";

    if (atEnd || isSemi) {
      const varStr = s.slice(start, i);
      if (varStr.length > 0) {
        if (variables.length >= MAX_VARIABLES) fail("too_many_items", basePos + start);
        variables.push(parseVariable(varStr, basePos + start));
      }
      if (atEnd) break;
      start = i + 1;
      i += 1;
      continue;
    }

    if (s[i] === "\\" && i + 1 < s.length) {
      i += 2;
      continue;
    }
    i += 1;
  }

  return variables;
}

// ---------------------------------------------------------------------------
// Body-level modifiers
// ---------------------------------------------------------------------------

interface BodyModifiers {
  group?: string;
  timestamp?: string;
  meta?: MetaPair[];
}

function parseBodyModifiers(s: string, basePos: number): BodyModifiers {
  if (s.length === 0) return {};

  let pos = 0;
  let group: string | undefined;
  let timestamp: string | undefined;
  let meta: MetaPair[] | undefined;
  let phase = 0; // 0=^, 1=@, 2={, 3=done

  while (pos < s.length) {
    const ch = s[pos];
    if (ch === "^") {
      if (phase > 0) fail("invalid_modifier", basePos + pos);
      pos += 1;
      const start = pos;
      pos = scanUntilAny(s, pos, "@{");
      const g = s.slice(start, pos);
      validateGroup(g, basePos + start);
      group = g;
      phase = 1;
    } else if (ch === "@") {
      if (phase > 1) fail("invalid_modifier", basePos + pos);
      pos += 1;
      const start = pos;
      pos = scanUntilAny(s, pos, "{");
      const ts = s.slice(start, pos);
      validateDigits(ts, basePos + start);
      timestamp = ts;
      phase = 2;
    } else if (ch === "{") {
      if (phase > 2) fail("invalid_modifier", basePos + pos);
      pos += 1;
      const start = pos;
      const end = findUnescapedChar(s, "}", pos);
      if (end === -1) fail("invalid_metadata", basePos + start);
      const metaStr = s.slice(start, end);
      meta = parseMetadata(metaStr, basePos + start);
      pos = end + 1;
      phase = 3;
    } else {
      fail("invalid_modifier", basePos + pos);
    }
  }

  return { group, timestamp, meta };
}

// ---------------------------------------------------------------------------
// PUSH body parsing
// ---------------------------------------------------------------------------

function parsePushBody(body: string, basePos: number): PushBody {
  if (body.startsWith(">x")) {
    return parseHexPassthrough(body.slice(2), basePos + 2);
  }
  if (body.startsWith(">b")) {
    return parseBase64Passthrough(body.slice(2), basePos + 2);
  }

  const bracketPos = findUnescapedChar(body, "[");
  if (bracketPos === -1) fail("invalid_variable_block", basePos);

  const modStr = body.slice(0, bracketPos);
  const endBracket = findClosingBracket(body, bracketPos + 1);
  if (endBracket === -1) fail("invalid_variable_block", basePos + bracketPos);

  const varBlock = body.slice(bracketPos + 1, endBracket);
  if (varBlock.length === 0) fail("invalid_variable_block", basePos + bracketPos);

  const mods = parseBodyModifiers(modStr, basePos);
  const variables = parseVariableList(varBlock, basePos + bracketPos + 1);
  if (variables.length === 0) fail("invalid_variable_block", basePos + bracketPos);

  const structured: StructuredBody = { variables };
  if (mods.group !== undefined) structured.group = mods.group;
  if (mods.timestamp !== undefined) structured.timestamp = mods.timestamp;
  if (mods.meta !== undefined && mods.meta.length > 0) structured.meta = mods.meta;

  return { type: "structured", body: structured };
}

function parseHexPassthrough(data: string, pos: number): PushBody {
  if (data.length === 0) fail("invalid_passthrough", pos);
  if (data.length % 2 !== 0) fail("invalid_passthrough", pos);
  for (let i = 0; i < data.length; i++) {
    if (!isHexDigit(data[i])) fail("invalid_passthrough", pos);
  }
  return {
    type: "passthrough",
    body: { encoding: PassthroughEncoding.Hex, data },
  };
}

function parseBase64Passthrough(data: string, pos: number): PushBody {
  if (data.length === 0) fail("invalid_passthrough", pos);
  for (let i = 0; i < data.length; i++) {
    const ch = data[i];
    if (
      !(
        (ch >= "a" && ch <= "z") ||
        (ch >= "A" && ch <= "Z") ||
        (ch >= "0" && ch <= "9") ||
        ch === "+" ||
        ch === "/" ||
        ch === "="
      )
    ) {
      fail("invalid_passthrough", pos);
    }
  }
  return {
    type: "passthrough",
    body: { encoding: PassthroughEncoding.Base64, data },
  };
}

// ---------------------------------------------------------------------------
// PULL body parsing
// ---------------------------------------------------------------------------

function parsePullBody(body: string, basePos: number): PullBody {
  if (!body.startsWith("[") || !body.endsWith("]")) {
    fail("missing_body", basePos);
  }

  const inner = body.slice(1, body.length - 1);
  if (inner.length === 0) fail("invalid_variable_block", basePos);

  const variables: string[] = [];
  let start = 0;
  let i = 0;

  for (;;) {
    const atEnd = i >= inner.length;
    const isSemi = !atEnd && inner[i] === ";";

    if (atEnd || isSemi) {
      const name = inner.slice(start, i);
      if (name.length > 0) {
        if (variables.length >= MAX_VARIABLES) fail("too_many_items", basePos + 1 + start);
        validateVarname(name, basePos + 1 + start);
        variables.push(name);
      }
      if (atEnd) break;
      start = i + 1;
      i += 1;
      continue;
    }

    if (inner[i] === "\\" && i + 1 < inner.length) {
      i += 2;
      continue;
    }
    i += 1;
  }

  if (variables.length === 0) fail("invalid_variable_block", basePos);
  return { variables };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function parseUplink(input: string): UplinkFrame {
  if (input.includes("\0")) fail("nul_byte", 0);
  if (input.length > MAX_FRAME_SIZE) fail("frame_too_large", 0);

  const stripped = input.endsWith("\n") ? input.slice(0, -1) : input;
  const fields = splitFields(stripped);

  if (fields.length === 0 || fields[0].length === 0) fail("empty_frame", 0);

  const method = parseMethod(fields[0]);

  let seq: number | undefined;
  let authIdx: number;
  if (fields.length > 1 && fields[1][0] === "!") {
    seq = parseSeq(fields[1], fields[0].length + 1);
    authIdx = 2;
  } else {
    authIdx = 1;
  }

  let authPos = 0;
  for (let i = 0; i < authIdx; i++) authPos += fields[i].length + 1;

  if (fields.length <= authIdx) fail("invalid_auth", authPos);
  const auth = fields[authIdx];
  validateAuth(auth, authPos);

  const serialIdx = authIdx + 1;
  const serialPos = authPos + auth.length + 1;
  if (fields.length <= serialIdx) fail("invalid_serial", serialPos);
  const serial = fields[serialIdx];
  validateSerial(serial, serialPos);

  const bodyIdx = serialIdx + 1;
  const bodyPos = serialPos + serial.length + 1;

  const frame: UplinkFrame = { method, auth, serial };
  if (seq !== undefined) frame.seq = seq;

  switch (method) {
    case Method.Push: {
      if (fields.length <= bodyIdx) fail("missing_body", bodyPos);
      frame.pushBody = parsePushBody(fields[bodyIdx], bodyPos);
      break;
    }
    case Method.Pull: {
      if (fields.length <= bodyIdx) fail("missing_body", bodyPos);
      frame.pullBody = parsePullBody(fields[bodyIdx], bodyPos);
      break;
    }
    case Method.Ping:
      break;
  }

  return frame;
}

export function parseAck(input: string): AckFrame {
  const stripped = input.endsWith("\n") ? input.slice(0, -1) : input;
  const fields = splitFields(stripped);

  if (fields.length === 0 || fields[0] !== "ACK") fail("invalid_ack", 0);
  if (fields.length < 2) fail("invalid_ack", 0);

  let seq: number | undefined;
  let statusIdx: number;
  if (fields[1][0] === "!") {
    seq = parseSeq(fields[1], 4);
    statusIdx = 2;
  } else {
    statusIdx = 1;
  }

  if (fields.length <= statusIdx) fail("invalid_ack", 0);

  const status = parseAckStatus(fields[statusIdx]);
  let detail: AckDetail | undefined;

  if (fields.length > statusIdx + 1) {
    detail = parseAckDetail(fields[statusIdx + 1], status);
  }

  const frame: AckFrame = { status };
  if (seq !== undefined) frame.seq = seq;
  if (detail !== undefined) frame.detail = detail;
  return frame;
}

function parseAckStatus(s: string): AckStatus {
  switch (s) {
    case "OK": return AckStatus.Ok;
    case "PONG": return AckStatus.Pong;
    case "CMD": return AckStatus.Cmd;
    case "ERR": return AckStatus.Err;
    default: fail("invalid_ack", 0);
  }
}

function parseAckDetail(s: string, status: AckStatus): AckDetail {
  switch (status) {
    case AckStatus.Ok: {
      if (s[0] === "[") return { type: "variables", raw: s };
      const n = parseU32(s);
      if (n !== null) return { type: "count", count: n };
      return { type: "raw", text: s };
    }
    case AckStatus.Pong:
      return { type: "raw", text: s };
    case AckStatus.Cmd:
      return { type: "command", command: s };
    case AckStatus.Err: {
      const code = parseErrorCode(s);
      return { type: "error", code, text: s };
    }
  }
}

export function parseHeadless(method: Method, input: string): HeadlessFrame {
  switch (method) {
    case Method.Push: {
      const pipePos = findUnescapedChar(input, "|");
      if (pipePos === -1) fail("missing_body", 0);
      const serial = input.slice(0, pipePos);
      validateSerial(serial, 0);
      const body = input.slice(pipePos + 1);
      const pushBody = parsePushBody(body, pipePos + 1);
      return { serial, pushBody };
    }
    case Method.Pull: {
      const pipePos = findUnescapedChar(input, "|");
      if (pipePos === -1) fail("missing_body", 0);
      const serial = input.slice(0, pipePos);
      validateSerial(serial, 0);
      const body = input.slice(pipePos + 1);
      const pullBody = parsePullBody(body, pipePos + 1);
      return { serial, pullBody };
    }
    case Method.Ping: {
      validateSerial(input, 0);
      return { serial: input };
    }
  }
}

export function parseAckInner(input: string): AckFrame {
  const fields = splitFields(input);
  if (fields.length === 0 || fields[0].length === 0) fail("invalid_ack", 0);

  const status = parseAckStatus(fields[0]);
  let detail: AckDetail | undefined;

  if (fields.length > 1) {
    detail = parseAckDetail(fields[1], status);
  }

  const frame: AckFrame = { status };
  if (detail !== undefined) frame.detail = detail;
  return frame;
}

function parseErrorCode(s: string): ErrorCode {
  switch (s) {
    case "invalid_token": return ErrorCode.InvalidToken;
    case "invalid_method": return ErrorCode.InvalidMethod;
    case "invalid_payload": return ErrorCode.InvalidPayload;
    case "invalid_seq": return ErrorCode.InvalidSeq;
    case "device_not_found": return ErrorCode.DeviceNotFound;
    case "variable_not_found": return ErrorCode.VariableNotFound;
    case "rate_limited": return ErrorCode.RateLimited;
    case "auth_failed": return ErrorCode.AuthFailed;
    case "unsupported_version": return ErrorCode.UnsupportedVersion;
    case "payload_too_large": return ErrorCode.PayloadTooLarge;
    case "server_error": return ErrorCode.ServerError;
    default: return ErrorCode.Unknown;
  }
}
