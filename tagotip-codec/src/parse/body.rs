use crate::consts::MAX_VARIABLES;
use crate::error::{ParseError, ParseErrorKind};
use crate::inline_vec::InlineVec;
use crate::types::{
    MAX_TOTAL_META, MetaPair, MetaRange, PassthroughBody, PassthroughEncoding, PullBody, PushBody,
    StructuredBody, Variable,
};
use crate::validate;

use super::variable::{parse_metadata, parse_variable};

/// Body-level modifiers parsed from the prefix before `[`.
type BodyModifiers<'a> = (Option<&'a str>, Option<&'a str>, Option<MetaRange>);

/// Parse a PUSH body string (everything after SERIAL|).
pub fn parse_push_body<'a>(body: &'a str, base_pos: usize) -> Result<PushBody<'a>, ParseError> {
    // Check for passthrough
    if let Some(rest) = body.strip_prefix(">x") {
        return parse_hex_passthrough(rest, base_pos + 2);
    }
    if let Some(rest) = body.strip_prefix(">b") {
        return parse_base64_passthrough(rest, base_pos + 2);
    }

    // Structured body: [body-mods] "[" var-list "]"
    let bytes = body.as_bytes();
    let bracket_pos = find_unescaped_byte(bytes, b'[')
        .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidVariableBlock, base_pos))?;

    // Parse body-level modifiers (everything before `[`)
    let mod_str = &body[..bracket_pos];

    // Find matching `]`
    let end_bracket = find_closing_bracket(bytes, bracket_pos + 1).ok_or_else(|| {
        ParseError::new(ParseErrorKind::InvalidVariableBlock, base_pos + bracket_pos)
    })?;

    let var_block = &body[bracket_pos + 1..end_bracket];

    if var_block.is_empty() {
        return Err(ParseError::new(
            ParseErrorKind::InvalidVariableBlock,
            base_pos + bracket_pos,
        ));
    }

    // Shared metadata pool
    let mut meta_pool: InlineVec<MetaPair<'a>, MAX_TOTAL_META> = InlineVec::new();

    // Parse body-level modifiers
    let (body_group, body_timestamp, body_meta) =
        parse_body_modifiers(mod_str, base_pos, &mut meta_pool)?;

    // Parse variables
    let variables = parse_variable_list(var_block, base_pos + bracket_pos + 1, &mut meta_pool)?;

    if variables.is_empty() {
        return Err(ParseError::new(
            ParseErrorKind::InvalidVariableBlock,
            base_pos + bracket_pos,
        ));
    }

    Ok(PushBody::Structured(StructuredBody {
        group: body_group,
        timestamp: body_timestamp,
        body_meta,
        variables,
        meta_pool,
    }))
}

/// Parse a PULL body string: `[var1;var2;...]`.
pub fn parse_pull_body<'a>(body: &'a str, base_pos: usize) -> Result<PullBody<'a>, ParseError> {
    if !body.starts_with('[') || !body.ends_with(']') {
        return Err(ParseError::new(ParseErrorKind::MissingBody, base_pos));
    }

    let inner = &body[1..body.len() - 1];
    if inner.is_empty() {
        return Err(ParseError::new(
            ParseErrorKind::InvalidVariableBlock,
            base_pos,
        ));
    }

    let mut variables: InlineVec<&'a str, MAX_VARIABLES> = InlineVec::new();

    let ibytes = inner.as_bytes();
    let mut start = 0;
    let mut i = 0;

    loop {
        let at_end = i >= ibytes.len();
        let is_semi = !at_end && ibytes[i] == b';';

        if at_end || is_semi {
            let name = &inner[start..i];
            if !name.is_empty() {
                validate::validate_varname(name, base_pos + 1 + start)?;
                variables.push(name).map_err(|_| {
                    ParseError::new(ParseErrorKind::TooManyItems, base_pos + 1 + start)
                })?;
            }
            if at_end {
                break;
            }
            start = i + 1;
            i += 1;
            continue;
        }

        if ibytes[i] == b'\\' && i + 1 < ibytes.len() {
            i += 2;
            continue;
        }

        i += 1;
    }

    if variables.is_empty() {
        return Err(ParseError::new(
            ParseErrorKind::InvalidVariableBlock,
            base_pos,
        ));
    }

    Ok(PullBody { variables })
}

/// Parse body-level modifiers: `^GROUP @TIMESTAMP {METADATA}` (before `[`).
fn parse_body_modifiers<'a>(
    s: &'a str,
    base_pos: usize,
    meta_pool: &mut InlineVec<MetaPair<'a>, MAX_TOTAL_META>,
) -> Result<BodyModifiers<'a>, ParseError> {
    if s.is_empty() {
        return Ok((None, None, None));
    }

    let bytes = s.as_bytes();
    let mut pos = 0;
    let mut group = None;
    let mut timestamp = None;
    let mut meta_range = None;

    // phase: 0=^, 1=@, 2={, 3=done
    let mut phase = 0;

    while pos < bytes.len() {
        match bytes[pos] {
            b'^' => {
                if phase > 0 {
                    return Err(ParseError::new(
                        ParseErrorKind::InvalidModifier,
                        base_pos + pos,
                    ));
                }
                pos += 1;
                let start = pos;
                pos = scan_until_mod(bytes, pos);
                let g = &s[start..pos];
                validate::validate_group(g, base_pos + start)?;
                group = Some(g);
                phase = 1;
            }
            b'@' => {
                if phase > 1 {
                    return Err(ParseError::new(
                        ParseErrorKind::InvalidModifier,
                        base_pos + pos,
                    ));
                }
                pos += 1;
                let start = pos;
                pos = scan_until_any(bytes, pos, b"{");
                let ts = &s[start..pos];
                validate_digits(ts, base_pos + start)?;
                timestamp = Some(ts);
                phase = 2;
            }
            b'{' => {
                if phase > 2 {
                    return Err(ParseError::new(
                        ParseErrorKind::InvalidModifier,
                        base_pos + pos,
                    ));
                }
                pos += 1;
                let start = pos;
                let end = find_unescaped_byte(&bytes[pos..], b'}').ok_or_else(|| {
                    ParseError::new(ParseErrorKind::InvalidMetadata, base_pos + start)
                })?;
                let meta_str = &s[start..start + end];
                let parsed = parse_metadata(meta_str, base_pos + start)?;
                meta_range = Some(add_to_pool(meta_pool, &parsed, base_pos + start)?);
                pos = start + end + 1;
                phase = 3;
            }
            _ => {
                return Err(ParseError::new(
                    ParseErrorKind::InvalidModifier,
                    base_pos + pos,
                ));
            }
        }
    }

    Ok((group, timestamp, meta_range))
}

/// Add metadata pairs to the shared pool and return the range.
fn add_to_pool<'a>(
    pool: &mut InlineVec<MetaPair<'a>, MAX_TOTAL_META>,
    pairs: &InlineVec<MetaPair<'a>, { crate::consts::MAX_META_PAIRS }>,
    pos: usize,
) -> Result<MetaRange, ParseError> {
    let start = pool.len() as u16;
    for pair in pairs.iter() {
        pool.push(*pair)
            .map_err(|_| ParseError::new(ParseErrorKind::TooManyItems, pos))?;
    }
    Ok(MetaRange {
        start,
        len: pairs.len() as u16,
    })
}

/// Scan forward until `@` or `{` (body modifier boundaries).
fn scan_until_mod(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() {
        if bytes[pos] == b'\\' && pos + 1 < bytes.len() {
            pos += 2;
            continue;
        }
        if bytes[pos] == b'@' || bytes[pos] == b'{' {
            return pos;
        }
        pos += 1;
    }
    pos
}

/// Scan forward until one of the stop bytes.
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

/// Find an unescaped byte in a slice.
fn find_unescaped_byte(bytes: &[u8], target: u8) -> Option<usize> {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == target {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Find the closing `]` matching an opening `[`.
fn find_closing_bracket(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let mut depth = 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'[' {
            depth += 1;
        } else if bytes[i] == b']' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Parse the variable list inside `[]`, splitting by `;`.
fn parse_variable_list<'a>(
    s: &'a str,
    base_pos: usize,
    meta_pool: &mut InlineVec<MetaPair<'a>, MAX_TOTAL_META>,
) -> Result<InlineVec<Variable<'a>, MAX_VARIABLES>, ParseError> {
    let mut variables = InlineVec::new();
    let bytes = s.as_bytes();
    let mut start = 0;
    let mut i = 0;

    loop {
        let at_end = i >= bytes.len();
        let is_semi = !at_end && bytes[i] == b';';

        if at_end || is_semi {
            let var_str = &s[start..i];
            if !var_str.is_empty() {
                let parsed = parse_variable(var_str, base_pos + start)?;
                let mut var = parsed.variable;

                // Add metadata to pool if present
                if let Some(ref pairs) = parsed.meta_pairs {
                    var.meta = Some(add_to_pool(meta_pool, pairs, base_pos + start)?);
                }

                variables
                    .push(var)
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

    Ok(variables)
}

/// Validate that a string is all decimal digits (for timestamps).
fn validate_digits(s: &str, pos: usize) -> Result<(), ParseError> {
    if s.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidModifier, pos));
    }
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            return Err(ParseError::new(ParseErrorKind::InvalidModifier, pos));
        }
    }
    Ok(())
}

/// Parse hex passthrough.
fn parse_hex_passthrough(data: &str, pos: usize) -> Result<PushBody<'_>, ParseError> {
    if data.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidPassthrough, pos));
    }
    if data.len() % 2 != 0 {
        return Err(ParseError::new(ParseErrorKind::InvalidPassthrough, pos));
    }
    for &b in data.as_bytes() {
        if !b.is_ascii_hexdigit() {
            return Err(ParseError::new(ParseErrorKind::InvalidPassthrough, pos));
        }
    }
    Ok(PushBody::Passthrough(PassthroughBody {
        encoding: PassthroughEncoding::Hex,
        data,
    }))
}

/// Parse base64 passthrough.
fn parse_base64_passthrough(data: &str, pos: usize) -> Result<PushBody<'_>, ParseError> {
    if data.is_empty() {
        return Err(ParseError::new(ParseErrorKind::InvalidPassthrough, pos));
    }
    for &b in data.as_bytes() {
        if !(b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') {
            return Err(ParseError::new(ParseErrorKind::InvalidPassthrough, pos));
        }
    }
    Ok(PushBody::Passthrough(PassthroughBody {
        encoding: PassthroughEncoding::Base64,
        data,
    }))
}
