export type ParseErrorKind =
  | "empty_frame"
  | "nul_byte"
  | "invalid_method"
  | "invalid_seq"
  | "invalid_auth"
  | "invalid_serial"
  | "missing_body"
  | "invalid_modifier"
  | "invalid_variable_block"
  | "invalid_variable"
  | "invalid_passthrough"
  | "invalid_metadata"
  | "invalid_field"
  | "invalid_ack"
  | "too_many_items"
  | "frame_too_large";

const KIND_MESSAGES: Record<ParseErrorKind, string> = {
  empty_frame: "empty frame",
  nul_byte: "frame contains NUL byte",
  invalid_method: "invalid method",
  invalid_seq: "invalid sequence counter",
  invalid_auth: "invalid auth token",
  invalid_serial: "invalid serial",
  missing_body: "missing body",
  invalid_modifier: "invalid body modifier",
  invalid_variable_block: "invalid variable block",
  invalid_variable: "invalid variable",
  invalid_passthrough: "invalid passthrough",
  invalid_metadata: "invalid metadata",
  invalid_field: "invalid field",
  invalid_ack: "invalid ACK frame",
  too_many_items: "too many items",
  frame_too_large: "frame too large",
};

export class TagotipError extends Error {
  readonly kind: ParseErrorKind;
  readonly position: number;

  constructor(kind: ParseErrorKind, position: number) {
    super(`${KIND_MESSAGES[kind]} at byte ${position}`);
    this.name = "TagotipError";
    this.kind = kind;
    this.position = position;
  }
}
