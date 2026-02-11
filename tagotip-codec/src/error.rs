use core::fmt;

/// Specific kind of parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// Frame is empty or contains no fields.
    EmptyFrame,
    /// Frame contains a NUL byte.
    NulByte,
    /// Unknown or unsupported method.
    InvalidMethod,
    /// Malformed or missing sequence counter.
    InvalidSeq,
    /// Auth token is missing, wrong length, or contains non-hex characters.
    InvalidAuth,
    /// Serial number is missing or contains invalid characters.
    InvalidSerial,
    /// PUSH/PULL body is missing when required.
    MissingBody,
    /// Body-level modifier error (out of order, duplicated, etc.).
    InvalidModifier,
    /// Variable block error (empty, unclosed, etc.).
    InvalidVariableBlock,
    /// Variable parsing error (no operator, invalid value, etc.).
    InvalidVariable,
    /// Passthrough payload error (empty, odd hex length, invalid chars).
    InvalidPassthrough,
    /// Metadata block error (empty, unclosed, missing `=`, etc.).
    InvalidMetadata,
    /// Field validation error (name too long, invalid chars, etc.).
    InvalidField,
    /// ACK frame parsing error.
    InvalidAck,
    /// Too many variables or metadata pairs.
    TooManyItems,
    /// Frame exceeds maximum size.
    FrameTooLarge,
}

/// Error returned by parsing functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    /// Byte position in the input where the error was detected (approximate).
    pub position: usize,
}

impl ParseError {
    #[must_use]
    pub fn new(kind: ParseErrorKind, position: usize) -> Self {
        Self { kind, position }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let desc = match self.kind {
            ParseErrorKind::EmptyFrame => "empty frame",
            ParseErrorKind::NulByte => "frame contains NUL byte",
            ParseErrorKind::InvalidMethod => "invalid method",
            ParseErrorKind::InvalidSeq => "invalid sequence counter",
            ParseErrorKind::InvalidAuth => "invalid auth token",
            ParseErrorKind::InvalidSerial => "invalid serial",
            ParseErrorKind::MissingBody => "missing body",
            ParseErrorKind::InvalidModifier => "invalid body modifier",
            ParseErrorKind::InvalidVariableBlock => "invalid variable block",
            ParseErrorKind::InvalidVariable => "invalid variable",
            ParseErrorKind::InvalidPassthrough => "invalid passthrough",
            ParseErrorKind::InvalidMetadata => "invalid metadata",
            ParseErrorKind::InvalidField => "invalid field",
            ParseErrorKind::InvalidAck => "invalid ACK frame",
            ParseErrorKind::TooManyItems => "too many items",
            ParseErrorKind::FrameTooLarge => "frame too large",
        };
        write!(f, "{} at byte {}", desc, self.position)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

/// Specific kind of build error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildErrorKind {
    /// Output buffer is too small.
    BufferTooSmall,
    /// Invalid input data (e.g., empty variable name).
    InvalidInput,
}

/// Error returned by builder functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildError {
    pub kind: BuildErrorKind,
}

impl BuildError {
    #[must_use]
    pub fn buffer_too_small() -> Self {
        Self {
            kind: BuildErrorKind::BufferTooSmall,
        }
    }

    #[must_use]
    pub fn invalid_input() -> Self {
        Self {
            kind: BuildErrorKind::InvalidInput,
        }
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            BuildErrorKind::BufferTooSmall => write!(f, "output buffer too small"),
            BuildErrorKind::InvalidInput => write!(f, "invalid input data"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuildError {}
