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
