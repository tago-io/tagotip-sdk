use crate::consts::{MAX_META_PAIRS, MAX_VARIABLES};
use crate::inline_vec::InlineVec;

/// Maximum total metadata pairs across all variables + body-level in a single frame.
pub const MAX_TOTAL_META: usize = 512;

/// Uplink method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Push,
    Pull,
    Ping,
}

/// Operator / value type hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    /// `:=` — number
    Number,
    /// `=` — string
    String,
    /// `?=` — boolean
    Boolean,
    /// `@=` — location
    Location,
}

/// A parsed value. Borrows from the input string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    /// Raw number string (not parsed to f64 — avoids libm dependency in `no_std`).
    Number(&'a str),
    /// Raw string value (may contain escape sequences; use `unescape_into()` to decode).
    String(&'a str),
    /// Boolean value.
    Boolean(bool),
    /// Location: lat, lng, optional alt — all as raw strings.
    Location {
        lat: &'a str,
        lng: &'a str,
        alt: Option<&'a str>,
    },
}

/// A single metadata key-value pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaPair<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

/// Index range into a shared metadata pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaRange {
    pub start: u16,
    pub len: u16,
}

/// Standalone metadata block (used for body-level metadata or when not using a pool).
pub type MetadataBlock<'a> = InlineVec<MetaPair<'a>, MAX_META_PAIRS>;

/// A parsed variable with all optional suffixes.
/// Metadata is stored as a range into a shared pool (see `StructuredBody.meta_pool`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Variable<'a> {
    pub name: &'a str,
    pub operator: Operator,
    pub value: Value<'a>,
    pub unit: Option<&'a str>,
    pub timestamp: Option<&'a str>,
    pub group: Option<&'a str>,
    pub meta: Option<MetaRange>,
}

impl Variable<'_> {
    /// Parse the timestamp suffix as a u64, if present.
    pub fn timestamp_u64(&self) -> Option<u64> {
        self.timestamp.and_then(parse_u64)
    }
}

/// Passthrough encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassthroughEncoding {
    Hex,
    Base64,
}

/// Passthrough body data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassthroughBody<'a> {
    pub encoding: PassthroughEncoding,
    pub data: &'a str,
}

/// Structured PUSH body (body-level modifiers + variable list).
/// Metadata for both body-level and variable-level is stored in `meta_pool`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredBody<'a> {
    pub group: Option<&'a str>,
    pub timestamp: Option<&'a str>,
    pub body_meta: Option<MetaRange>,
    pub variables: InlineVec<Variable<'a>, MAX_VARIABLES>,
    /// Shared metadata pool. Variables and body-level metadata reference ranges within this pool.
    pub meta_pool: InlineVec<MetaPair<'a>, MAX_TOTAL_META>,
}

impl<'a> StructuredBody<'a> {
    /// Get the body-level metadata pairs, if any.
    #[must_use]
    pub fn body_metadata(&self) -> &[MetaPair<'a>] {
        match self.body_meta {
            Some(range) => {
                let start = range.start as usize;
                let end = start + range.len as usize;
                &self.meta_pool.as_slice()[start..end]
            }
            None => &[],
        }
    }

    /// Get the metadata pairs for a variable.
    #[must_use]
    pub fn variable_metadata(&self, var: &Variable<'a>) -> &[MetaPair<'a>] {
        match var.meta {
            Some(range) => {
                let start = range.start as usize;
                let end = start + range.len as usize;
                &self.meta_pool.as_slice()[start..end]
            }
            None => &[],
        }
    }
}

/// PUSH body — either structured or passthrough.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum PushBody<'a> {
    Structured(StructuredBody<'a>),
    Passthrough(PassthroughBody<'a>),
}

/// PULL body: list of variable names to retrieve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullBody<'a> {
    pub variables: InlineVec<&'a str, MAX_VARIABLES>,
}

/// A fully parsed uplink frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UplinkFrame<'a> {
    pub method: Method,
    pub seq: Option<u32>,
    pub auth: &'a str,
    pub serial: &'a str,
    pub push_body: Option<PushBody<'a>>,
    pub pull_body: Option<PullBody<'a>>,
}

/// A headless inner frame (for TagoTiP/S). No method/auth — those come from the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadlessFrame<'a> {
    pub serial: &'a str,
    pub push_body: Option<PushBody<'a>>,
    pub pull_body: Option<PullBody<'a>>,
}

/// ACK status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckStatus {
    Ok,
    Pong,
    Cmd,
    Err,
}

/// Known error codes from the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidToken,
    InvalidMethod,
    InvalidPayload,
    InvalidSeq,
    DeviceNotFound,
    VariableNotFound,
    RateLimited,
    AuthFailed,
    UnsupportedVersion,
    PayloadTooLarge,
    ServerError,
    /// Unknown error code (not in the spec list).
    Unknown,
}

/// Detail in an ACK frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckDetail<'a> {
    /// Count of accepted data points (PUSH OK response).
    Count(u32),
    /// Variable list (PULL OK response) — raw bracket-wrapped string.
    Variables(&'a str),
    /// Command string (CMD).
    Command(&'a str),
    /// Error code + raw text.
    Error { code: ErrorCode, text: &'a str },
    /// Raw detail text that doesn't match the above patterns.
    Raw(&'a str),
}

/// A parsed ACK (downlink) frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFrame<'a> {
    pub seq: Option<u32>,
    pub status: AckStatus,
    pub detail: Option<AckDetail<'a>>,
}

/// Parse a decimal string to u64 (`no_std` helper).
fn parse_u64(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut result: u64 = 0;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return None;
        }
        result = result.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(result)
}
