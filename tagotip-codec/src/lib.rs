#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "std")]
extern crate std;

pub mod consts;
pub mod error;
pub mod escape;
pub mod fmt;
pub mod inline_vec;
pub mod types;
pub mod validate;

pub mod build;
pub mod parse;

pub use error::{BuildError, ParseError, ParseErrorKind};
pub use types::*;

// Re-export granular parse functions
pub use parse::{
    ParsedVariable, extract_serial, parse_metadata, parse_method, parse_pull_body, parse_push_body,
    parse_seq, parse_variable, validate_auth,
};

// Re-export granular build functions
pub use build::{
    build_ack_inner, build_metadata, build_pull_body, build_push_body, build_variable,
};

// Re-export ACK inner frame parser for TagoTiP/S
pub use parse::parse_ack_inner;
