/** Uplink frame method. */
export enum Method {
  Push = "PUSH",
  Pull = "PULL",
  Ping = "PING",
}

/** Variable value type hint (operator). */
export enum Operator {
  /** `:=` — numeric value */
  Number = "number",
  /** `=` — string value */
  String = "string",
  /** `?=` — boolean value */
  Boolean = "boolean",
  /** `@=` — location value */
  Location = "location",
}

/** ACK response status. */
export enum AckStatus {
  Ok = "OK",
  Pong = "PONG",
  Cmd = "CMD",
  Err = "ERR",
}

/** Known error codes from the protocol spec. */
export enum ErrorCode {
  InvalidToken = "INVALID_TOKEN",
  InvalidMethod = "INVALID_METHOD",
  InvalidPayload = "INVALID_PAYLOAD",
  InvalidSeq = "INVALID_SEQ",
  DeviceNotFound = "DEVICE_NOT_FOUND",
  VariableNotFound = "VARIABLE_NOT_FOUND",
  RateLimited = "RATE_LIMITED",
  AuthFailed = "AUTH_FAILED",
  UnsupportedVersion = "UNSUPPORTED_VERSION",
  PayloadTooLarge = "PAYLOAD_TOO_LARGE",
  ServerError = "SERVER_ERROR",
  Unknown = "UNKNOWN",
}

/** Passthrough binary encoding. */
export enum PassthroughEncoding {
  Hex = "hex",
  Base64 = "base64",
}

/** A metadata key-value pair. */
export interface MetaPair {
  key: string;
  value: string;
}

/** A location value. */
export interface LocationValue {
  lat: string;
  lng: string;
  alt?: string;
}

/** Parsed variable value. */
export type Value =
  | { type: "number"; value: string }
  | { type: "string"; value: string }
  | { type: "boolean"; value: boolean }
  | { type: "location"; value: LocationValue };

/** A parsed variable with optional suffixes. */
export interface Variable {
  name: string;
  operator: Operator;
  value: Value;
  unit?: string;
  timestamp?: string;
  group?: string;
  meta?: MetaPair[];
}

/** Structured PUSH body. */
export interface StructuredBody {
  group?: string;
  timestamp?: string;
  meta?: MetaPair[];
  variables: Variable[];
}

/** Passthrough PUSH body. */
export interface PassthroughBody {
  encoding: PassthroughEncoding;
  data: string;
}

/** PUSH body — either structured or passthrough. */
export type PushBody =
  | { type: "structured"; body: StructuredBody }
  | { type: "passthrough"; body: PassthroughBody };

/** PULL body: list of variable names. */
export interface PullBody {
  variables: string[];
}

/** A fully parsed uplink frame. */
export interface UplinkFrame {
  method: Method;
  seq?: number;
  auth: string;
  serial: string;
  pushBody?: PushBody;
  pullBody?: PullBody;
}

/** Headless inner frame for TagoTiP/S.
 *  Contains only serial and body -- method, auth, and counter
 *  are carried by the envelope header. */
export interface HeadlessFrame {
  serial: string;
  pushBody?: PushBody;
  pullBody?: PullBody;
}

/** ACK detail variants. */
export type AckDetail =
  | { type: "count"; count: number }
  | { type: "variables"; raw: string }
  | { type: "command"; command: string }
  | { type: "error"; code: ErrorCode; text: string }
  | { type: "raw"; text: string };

/** A parsed ACK (downlink) frame. */
export interface AckFrame {
  seq?: number;
  status: AckStatus;
  detail?: AckDetail;
}
