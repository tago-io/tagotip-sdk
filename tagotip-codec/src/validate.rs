use crate::consts;
use crate::error::{ParseError, ParseErrorKind};

/// Validate a variable name: lowercase a-z, digits, underscore. Max 100 bytes.
pub fn validate_varname(name: &str, pos: usize) -> Result<(), ParseError> {
    if name.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidField, pos));
    }
    if name.len() > consts::MAX_VARNAME_LEN {
        return Err(ParseError::new(ParseErrorKind::InvalidField, pos));
    }
    for &b in name.as_bytes() {
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return Err(ParseError::new(ParseErrorKind::InvalidField, pos));
        }
    }
    Ok(())
}

/// Validate a serial number: alphanumeric, hyphen, underscore. Max 100 bytes.
pub fn validate_serial(serial: &str, pos: usize) -> Result<(), ParseError> {
    if serial.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidSerial, pos));
    }
    if serial.len() > consts::MAX_SERIAL_LEN {
        return Err(ParseError::new(ParseErrorKind::InvalidSerial, pos));
    }
    for &b in serial.as_bytes() {
        if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(ParseError::new(ParseErrorKind::InvalidSerial, pos));
        }
    }
    Ok(())
}

/// Validate a group name: same rules as variable name. Max 100 bytes.
pub fn validate_group(group: &str, pos: usize) -> Result<(), ParseError> {
    if group.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidField, pos));
    }
    if group.len() > consts::MAX_GROUP_LEN {
        return Err(ParseError::new(ParseErrorKind::InvalidField, pos));
    }
    for &b in group.as_bytes() {
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return Err(ParseError::new(ParseErrorKind::InvalidField, pos));
        }
    }
    Ok(())
}

/// Validate a metadata key: same rules as variable name. Max 100 bytes.
pub fn validate_meta_key(key: &str, pos: usize) -> Result<(), ParseError> {
    if key.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidMetadata, pos));
    }
    if key.len() > consts::MAX_META_KEY_LEN {
        return Err(ParseError::new(ParseErrorKind::InvalidMetadata, pos));
    }
    for &b in key.as_bytes() {
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            return Err(ParseError::new(ParseErrorKind::InvalidMetadata, pos));
        }
    }
    Ok(())
}

/// Validate a unit string: non-empty, max 25 bytes.
pub fn validate_unit(unit: &str, pos: usize) -> Result<(), ParseError> {
    if unit.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidField, pos));
    }
    if unit.len() > consts::MAX_UNIT_LEN {
        return Err(ParseError::new(ParseErrorKind::InvalidField, pos));
    }
    Ok(())
}

/// Validate number format per spec: `-?(0|[1-9][0-9]*)(\.[0-9]+)?`
pub fn validate_number(s: &str, pos: usize) -> Result<(), ParseError> {
    let bytes = s.as_bytes();
    let mut i = 0;

    if i < bytes.len() && bytes[i] == b'-' {
        i += 1;
    }

    if i >= bytes.len() {
        return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
    }

    // int-part: "0" / (%x31-39 *DIGIT)
    if bytes[i] == b'0' {
        i += 1;
    } else if bytes[i] >= b'1' && bytes[i] <= b'9' {
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    } else {
        return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
    }

    // Optional decimal fraction
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        if i >= bytes.len() || !bytes[i].is_ascii_digit() {
            return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
        }
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }

    if i != bytes.len() {
        return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
    }

    Ok(())
}
