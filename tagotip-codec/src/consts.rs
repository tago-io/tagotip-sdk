/// Maximum number of variables in a single `[]` block.
pub const MAX_VARIABLES: usize = 100;

/// Maximum number of metadata key-value pairs in a single `{}` block.
pub const MAX_META_PAIRS: usize = 32;

/// Maximum byte length of a variable name.
pub const MAX_VARNAME_LEN: usize = 100;

/// Maximum byte length of a serial number.
pub const MAX_SERIAL_LEN: usize = 100;

/// Maximum byte length of a group name.
pub const MAX_GROUP_LEN: usize = 100;

/// Maximum byte length of a metadata key.
pub const MAX_META_KEY_LEN: usize = 100;

/// Maximum byte length of a unit string.
pub const MAX_UNIT_LEN: usize = 25;

/// Maximum plaintext frame size in bytes (excluding optional `\n` terminator).
pub const MAX_FRAME_SIZE: usize = 16_384;

/// Length of an authorization token (`at` + 32 hex chars).
pub const AUTH_TOKEN_LEN: usize = 34;

/// Maximum fields after pipe-splitting an uplink frame (METHOD|!N|AUTH|SERIAL|BODY = 5).
pub const MAX_UPLINK_FIELDS: usize = 8;

/// Maximum fields after pipe-splitting an ACK frame (ACK|!N|STATUS|DETAIL = 4).
pub const MAX_ACK_FIELDS: usize = 4;
