use crate::error::{ParseError, ParseErrorKind};
use crate::types::{MetaPair, MetadataBlock, Operator, Value, Variable};
use crate::validate;

/// Result of parsing a single variable — includes metadata pairs to be added to the pool.
pub struct ParsedVariable<'a> {
    pub variable: Variable<'a>,
    pub meta_pairs: Option<MetadataBlock<'a>>,
}

/// Parse a single variable string (e.g., `temperature:=32.5#C@1694567890000^group1{k=v}`).
/// Returns the variable and its metadata pairs (to be added to the shared pool by the caller).
pub fn parse_variable(s: &str, base_pos: usize) -> Result<ParsedVariable<'_>, ParseError> {
    let bytes = s.as_bytes();
    let len = bytes.len();

    // Find operator: check multi-char first (:=, ?=, @=), then single =
    let (op_pos, op_len, operator) = find_operator(bytes, base_pos)?;

    // Extract and validate variable name
    let name = &s[..op_pos];
    if name.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidVariable, base_pos));
    }
    validate::validate_varname(name, base_pos)?;

    let mut pos = op_pos + op_len;

    // Parse value — read until suffix start character (unescaped #, @, ^, {)
    let value_start = pos;
    let value_end = scan_value(bytes, &mut pos);
    let value_str = &s[value_start..value_end];

    let value = parse_value(value_str, operator, base_pos + value_start)?;

    // Parse optional suffixes in order: #unit @timestamp ^group {metadata}
    let mut unit = None;
    let mut timestamp = None;
    let mut group = None;
    let mut meta_pairs = None;

    // #unit — MUST NOT appear with @= (location)
    if pos < len && bytes[pos] == b'#' {
        if operator == Operator::Location {
            return Err(ParseError::new(
                ParseErrorKind::InvalidVariable,
                base_pos + pos,
            ));
        }
        pos += 1; // consume #
        let start = pos;
        pos = scan_until_any(bytes, pos, b"@^{");
        let u = &s[start..pos];
        validate::validate_unit(u, base_pos + start)?;
        unit = Some(u);
    }

    // @timestamp
    if pos < len && bytes[pos] == b'@' {
        pos += 1;
        let start = pos;
        pos = scan_until_any(bytes, pos, b"^{");
        let ts = &s[start..pos];
        validate_timestamp(ts, base_pos + start)?;
        timestamp = Some(ts);
    }

    // ^group
    if pos < len && bytes[pos] == b'^' {
        pos += 1;
        let start = pos;
        pos = scan_until_any(bytes, pos, b"{");
        let g = &s[start..pos];
        validate::validate_group(g, base_pos + start)?;
        group = Some(g);
    }

    // {metadata}
    if pos < len && bytes[pos] == b'{' {
        pos += 1;
        let start = pos;
        let end = find_closing_brace(bytes, pos)
            .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidMetadata, base_pos + start))?;
        let meta_str = &s[start..end];
        meta_pairs = Some(parse_metadata(meta_str, base_pos + start)?);
        pos = end + 1; // skip }
    }

    let _ = pos;

    Ok(ParsedVariable {
        variable: Variable {
            name,
            operator,
            value,
            unit,
            timestamp,
            group,
            meta: None, // caller sets this after adding to pool
        },
        meta_pairs,
    })
}

/// Find the operator in a variable string. Returns (position, length, operator).
fn find_operator(bytes: &[u8], base_pos: usize) -> Result<(usize, usize, Operator), ParseError> {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
            match bytes[i] {
                b':' => return Ok((i, 2, Operator::Number)),
                b'?' => return Ok((i, 2, Operator::Boolean)),
                b'@' => return Ok((i, 2, Operator::Location)),
                _ => {}
            }
        }
        if bytes[i] == b'=' {
            return Ok((i, 1, Operator::String));
        }
        i += 1;
    }
    Err(ParseError::new(ParseErrorKind::InvalidVariable, base_pos))
}

/// Scan the value portion of a variable, handling escape sequences.
fn scan_value(bytes: &[u8], pos: &mut usize) -> usize {
    while *pos < bytes.len() {
        let b = bytes[*pos];
        if b == b'\\' && *pos + 1 < bytes.len() {
            *pos += 2;
            continue;
        }
        if b == b'#' || b == b'@' || b == b'^' || b == b'{' {
            return *pos;
        }
        *pos += 1;
    }
    *pos
}

/// Scan forward until one of the stop bytes is found (respecting escapes).
fn scan_until_any(bytes: &[u8], mut pos: usize, stops: &[u8]) -> usize {
    while pos < bytes.len() {
        if bytes[pos] == b'\\' && pos + 1 < bytes.len() {
            pos += 2;
            continue;
        }
        if stops.contains(&bytes[pos]) {
            return pos;
        }
        pos += 1;
    }
    pos
}

/// Find the closing `}` matching an opening `{`, respecting escapes.
fn find_closing_brace(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'}' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse the value string according to the operator type.
fn parse_value(s: &str, op: Operator, pos: usize) -> Result<Value<'_>, ParseError> {
    match op {
        Operator::Number => {
            if s.is_empty() {
                return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
            }
            validate::validate_number(s, pos)?;
            Ok(Value::Number(s))
        }
        Operator::String => {
            if s.is_empty() {
                return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
            }
            Ok(Value::String(s))
        }
        Operator::Boolean => match s {
            "true" => Ok(Value::Boolean(true)),
            "false" => Ok(Value::Boolean(false)),
            _ => Err(ParseError::new(ParseErrorKind::InvalidVariable, pos)),
        },
        Operator::Location => parse_location(s, pos),
    }
}

/// Parse a location value: `lat,lng` or `lat,lng,alt`.
fn parse_location(s: &str, pos: usize) -> Result<Value<'_>, ParseError> {
    let mut parts = s.splitn(4, ',');
    let lat = parts
        .next()
        .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidVariable, pos))?;
    let lng = parts
        .next()
        .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidVariable, pos))?;
    let alt = parts.next();

    if parts.next().is_some() {
        return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
    }

    if lat.is_empty() || lng.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
    }

    validate::validate_number(lat, pos)?;
    validate::validate_number(lng, pos)?;

    if let Some(a) = alt {
        if a.is_empty() {
            return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
        }
        validate::validate_number(a, pos)?;
        Ok(Value::Location {
            lat,
            lng,
            alt: Some(a),
        })
    } else {
        Ok(Value::Location {
            lat,
            lng,
            alt: None,
        })
    }
}

/// Validate a timestamp string: must be non-empty digits.
fn validate_timestamp(s: &str, pos: usize) -> Result<(), ParseError> {
    if s.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
    }
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return Err(ParseError::new(ParseErrorKind::InvalidVariable, pos));
        }
    }
    Ok(())
}

/// Parse a metadata block string (content between `{` and `}`).
pub fn parse_metadata(s: &str, base_pos: usize) -> Result<MetadataBlock<'_>, ParseError> {
    let mut block = MetadataBlock::new();

    if s.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidMetadata, base_pos));
    }

    let bytes = s.as_bytes();
    let mut start = 0;
    let mut i = 0;

    loop {
        let at_end = i >= bytes.len();
        let is_comma = !at_end && bytes[i] == b',';

        if at_end || is_comma {
            let pair_str = &s[start..i];
            if !pair_str.is_empty() {
                let pair = parse_meta_pair(pair_str, base_pos + start)?;
                block
                    .push(pair)
                    .map_err(|_| ParseError::new(ParseErrorKind::TooManyItems, base_pos + start))?;
            }
            if at_end {
                break;
            }
            start = i + 1;
            i += 1;
            continue;
        }

        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }

        i += 1;
    }

    if block.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidMetadata, base_pos));
    }

    Ok(block)
}

/// Parse a single metadata pair: `key=value`.
fn parse_meta_pair(s: &str, pos: usize) -> Result<MetaPair<'_>, ParseError> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'=' {
            let key = &s[..i];
            let value = &s[i + 1..];
            validate::validate_meta_key(key, pos)?;
            return Ok(MetaPair { key, value });
        }
        i += 1;
    }
    Err(ParseError::new(ParseErrorKind::InvalidMetadata, pos))
}
