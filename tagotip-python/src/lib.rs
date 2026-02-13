use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use tagotip_codec::parse;
use tagotip_codec::types::{
    AckDetail, AckStatus, ErrorCode, Method, Operator, PassthroughEncoding, PushBody,
    StructuredBody, Value,
};
use tagotip_codec::{ParseError, ParseErrorKind};

fn parse_error_to_py(e: ParseError) -> PyErr {
    let kind = match e.kind {
        ParseErrorKind::EmptyFrame => "empty_frame",
        ParseErrorKind::NulByte => "nul_byte",
        ParseErrorKind::InvalidMethod => "invalid_method",
        ParseErrorKind::InvalidSeq => "invalid_seq",
        ParseErrorKind::InvalidAuth => "invalid_auth",
        ParseErrorKind::InvalidSerial => "invalid_serial",
        ParseErrorKind::MissingBody => "missing_body",
        ParseErrorKind::InvalidModifier => "invalid_modifier",
        ParseErrorKind::InvalidVariableBlock => "invalid_variable_block",
        ParseErrorKind::InvalidVariable => "invalid_variable",
        ParseErrorKind::InvalidPassthrough => "invalid_passthrough",
        ParseErrorKind::InvalidMetadata => "invalid_metadata",
        ParseErrorKind::InvalidField => "invalid_field",
        ParseErrorKind::InvalidAck => "invalid_ack",
        ParseErrorKind::TooManyItems => "too_many_items",
        ParseErrorKind::FrameTooLarge => "frame_too_large",
    };
    PyValueError::new_err(format!("{}:{}", kind, e.position))
}

fn method_str(m: &Method) -> &'static str {
    match m {
        Method::Push => "PUSH",
        Method::Pull => "PULL",
        Method::Ping => "PING",
    }
}

fn operator_str(o: &Operator) -> &'static str {
    match o {
        Operator::Number => "number",
        Operator::String => "string",
        Operator::Boolean => "boolean",
        Operator::Location => "location",
    }
}

fn ack_status_str(s: &AckStatus) -> &'static str {
    match s {
        AckStatus::Ok => "OK",
        AckStatus::Pong => "PONG",
        AckStatus::Cmd => "CMD",
        AckStatus::Err => "ERR",
    }
}

fn error_code_str(c: &ErrorCode) -> &'static str {
    match c {
        ErrorCode::InvalidToken => "INVALID_TOKEN",
        ErrorCode::InvalidMethod => "INVALID_METHOD",
        ErrorCode::InvalidPayload => "INVALID_PAYLOAD",
        ErrorCode::InvalidSeq => "INVALID_SEQ",
        ErrorCode::DeviceNotFound => "DEVICE_NOT_FOUND",
        ErrorCode::VariableNotFound => "VARIABLE_NOT_FOUND",
        ErrorCode::RateLimited => "RATE_LIMITED",
        ErrorCode::AuthFailed => "AUTH_FAILED",
        ErrorCode::UnsupportedVersion => "UNSUPPORTED_VERSION",
        ErrorCode::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
        ErrorCode::ServerError => "SERVER_ERROR",
        ErrorCode::Unknown => "UNKNOWN",
    }
}

fn structured_body_to_dict<'py>(
    py: Python<'py>,
    sb: &StructuredBody<'_>,
) -> PyResult<Bound<'py, PyDict>> {
    let body_dict = PyDict::new(py);
    body_dict.set_item("type", "structured")?;

    if let Some(g) = sb.group {
        body_dict.set_item("group", g)?;
    }
    if let Some(ts) = sb.timestamp {
        body_dict.set_item("timestamp", ts)?;
    }

    let body_meta = sb.body_metadata();
    if !body_meta.is_empty() {
        let meta_list = PyList::empty(py);
        for mp in body_meta {
            let pair = PyDict::new(py);
            pair.set_item("key", mp.key)?;
            pair.set_item("value", mp.value)?;
            meta_list.append(pair)?;
        }
        body_dict.set_item("meta", meta_list)?;
    }

    let var_list = PyList::empty(py);
    for var in sb.variables.as_slice() {
        let var_dict = PyDict::new(py);
        var_dict.set_item("name", var.name)?;
        var_dict.set_item("operator", operator_str(&var.operator))?;

        let value_dict = PyDict::new(py);
        match &var.value {
            Value::Number(s) => {
                value_dict.set_item("type", "number")?;
                value_dict.set_item("str_value", *s)?;
            }
            Value::String(s) => {
                value_dict.set_item("type", "string")?;
                value_dict.set_item("str_value", *s)?;
            }
            Value::Boolean(b) => {
                value_dict.set_item("type", "boolean")?;
                value_dict.set_item("bool_value", *b)?;
            }
            Value::Location { lat, lng, alt } => {
                value_dict.set_item("type", "location")?;
                let loc_dict = PyDict::new(py);
                loc_dict.set_item("lat", *lat)?;
                loc_dict.set_item("lng", *lng)?;
                if let Some(a) = alt {
                    loc_dict.set_item("alt", *a)?;
                }
                value_dict.set_item("location", loc_dict)?;
            }
        }
        var_dict.set_item("value", value_dict)?;

        if let Some(u) = var.unit {
            var_dict.set_item("unit", u)?;
        }
        if let Some(ts) = var.timestamp {
            var_dict.set_item("timestamp", ts)?;
        }
        if let Some(g) = var.group {
            var_dict.set_item("group", g)?;
        }

        let var_meta = sb.variable_metadata(var);
        if !var_meta.is_empty() {
            let meta_list = PyList::empty(py);
            for mp in var_meta {
                let pair = PyDict::new(py);
                pair.set_item("key", mp.key)?;
                pair.set_item("value", mp.value)?;
                meta_list.append(pair)?;
            }
            var_dict.set_item("meta", meta_list)?;
        }

        var_list.append(var_dict)?;
    }
    body_dict.set_item("variables", var_list)?;

    Ok(body_dict)
}

#[pyfunction]
fn parse_uplink_native(py: Python<'_>, input: &str) -> PyResult<Py<PyDict>> {
    let frame = parse::parse_uplink(input).map_err(parse_error_to_py)?;

    let dict = PyDict::new(py);
    dict.set_item("method", method_str(&frame.method))?;
    dict.set_item("auth", frame.auth)?;
    dict.set_item("serial", frame.serial)?;

    if let Some(seq) = frame.seq {
        dict.set_item("seq", seq)?;
    }

    match &frame.push_body {
        Some(PushBody::Structured(sb)) => {
            dict.set_item("push_body", structured_body_to_dict(py, sb)?)?;
        }
        Some(PushBody::Passthrough(pt)) => {
            let body_dict = PyDict::new(py);
            body_dict.set_item("type", "passthrough")?;
            body_dict.set_item(
                "encoding",
                match pt.encoding {
                    PassthroughEncoding::Hex => "hex",
                    PassthroughEncoding::Base64 => "base64",
                },
            )?;
            body_dict.set_item("data", pt.data)?;
            dict.set_item("push_body", body_dict)?;
        }
        None => {}
    }

    if let Some(pb) = &frame.pull_body {
        let pull_dict = PyDict::new(py);
        let var_list = PyList::empty(py);
        for name in pb.variables.as_slice() {
            var_list.append(*name)?;
        }
        pull_dict.set_item("variables", var_list)?;
        dict.set_item("pull_body", pull_dict)?;
    }

    Ok(dict.into())
}

#[pyfunction]
fn parse_ack_native(py: Python<'_>, input: &str) -> PyResult<Py<PyDict>> {
    let frame = parse::parse_ack(input).map_err(parse_error_to_py)?;

    let dict = PyDict::new(py);
    dict.set_item("status", ack_status_str(&frame.status))?;

    if let Some(seq) = frame.seq {
        dict.set_item("seq", seq)?;
    }

    if let Some(detail) = &frame.detail {
        let detail_dict = PyDict::new(py);
        match detail {
            AckDetail::Count(n) => {
                detail_dict.set_item("type", "count")?;
                detail_dict.set_item("count", *n)?;
            }
            AckDetail::Variables(s) => {
                detail_dict.set_item("type", "variables")?;
                detail_dict.set_item("text", *s)?;
            }
            AckDetail::Command(s) => {
                detail_dict.set_item("type", "command")?;
                detail_dict.set_item("text", *s)?;
            }
            AckDetail::Error { code, text } => {
                detail_dict.set_item("type", "error")?;
                detail_dict.set_item("error_code", error_code_str(code))?;
                detail_dict.set_item("text", *text)?;
            }
            AckDetail::Raw(s) => {
                detail_dict.set_item("type", "raw")?;
                detail_dict.set_item("text", *s)?;
            }
        }
        dict.set_item("detail", detail_dict)?;
    }

    Ok(dict.into())
}

// ---------------------------------------------------------------------------
// TagoTiP/S crypto bindings
// ---------------------------------------------------------------------------

fn crypto_error_to_py(e: tagotip_secure::CryptoError) -> PyErr {
    PyValueError::new_err(format!("tagotips: {e}"))
}

#[pyfunction]
fn derive_auth_hash_native(py: Python<'_>, token: &str) -> PyResult<Py<pyo3::types::PyBytes>> {
    let hash = tagotip_secure::derive_auth_hash(token);
    Ok(pyo3::types::PyBytes::new(py, &hash).into())
}

#[pyfunction]
fn derive_device_hash_native(py: Python<'_>, serial: &str) -> PyResult<Py<pyo3::types::PyBytes>> {
    let hash = tagotip_secure::derive_device_hash(serial);
    Ok(pyo3::types::PyBytes::new(py, &hash).into())
}

#[pyfunction]
fn seal_uplink_native(
    py: Python<'_>,
    method: u8,
    inner_frame: &[u8],
    counter: u32,
    auth_hash: &[u8],
    device_hash: &[u8],
    key: &[u8],
) -> PyResult<Py<pyo3::types::PyBytes>> {
    if auth_hash.len() != 8 {
        return Err(PyValueError::new_err("auth_hash must be 8 bytes"));
    }
    if device_hash.len() != 8 {
        return Err(PyValueError::new_err("device_hash must be 8 bytes"));
    }

    let mut ah = [0u8; 8];
    ah.copy_from_slice(auth_hash);
    let mut dh = [0u8; 8];
    dh.copy_from_slice(device_hash);

    let envelope_method =
        tagotip_secure::EnvelopeMethod::from_id(method).map_err(crypto_error_to_py)?;

    let codec_method = envelope_method.to_codec_method();
    if codec_method.is_none() && method != 3 {
        return Err(PyValueError::new_err("invalid method for uplink"));
    }

    let envelope = tagotip_secure::seal_raw(
        inner_frame,
        envelope_method,
        counter,
        ah,
        dh,
        key,
        tagotip_secure::CipherSuite::Aes128Ccm,
    )
    .map_err(crypto_error_to_py)?;

    Ok(pyo3::types::PyBytes::new(py, &envelope).into())
}

#[pyfunction]
fn open_envelope_native(py: Python<'_>, envelope: &[u8], key: &[u8]) -> PyResult<Py<PyDict>> {
    let (header, method, plaintext) =
        tagotip_secure::open_envelope(envelope, key).map_err(crypto_error_to_py)?;

    let dict = PyDict::new(py);
    dict.set_item("flags", header.flags)?;
    dict.set_item("counter", header.counter)?;
    dict.set_item(
        "auth_hash",
        pyo3::types::PyBytes::new(py, &header.auth_hash),
    )?;
    dict.set_item(
        "device_hash",
        pyo3::types::PyBytes::new(py, &header.device_hash),
    )?;
    dict.set_item("method", method.id())?;
    dict.set_item("plaintext", pyo3::types::PyBytes::new(py, &plaintext))?;

    Ok(dict.into())
}

#[pyfunction]
fn parse_envelope_header_native(py: Python<'_>, envelope: &[u8]) -> PyResult<Py<PyDict>> {
    let header = tagotip_secure::parse_envelope_header(envelope).map_err(crypto_error_to_py)?;

    let dict = PyDict::new(py);
    dict.set_item("flags", header.flags)?;
    dict.set_item("counter", header.counter)?;
    dict.set_item(
        "auth_hash",
        pyo3::types::PyBytes::new(py, &header.auth_hash),
    )?;
    dict.set_item(
        "device_hash",
        pyo3::types::PyBytes::new(py, &header.device_hash),
    )?;

    Ok(dict.into())
}

#[pyfunction]
fn is_envelope_native(data: &[u8]) -> bool {
    tagotip_secure::is_envelope(data)
}

#[pyfunction]
fn derive_key_native(
    py: Python<'_>,
    token: &str,
    serial: &str,
) -> PyResult<Py<pyo3::types::PyBytes>> {
    let key = tagotip_secure::derive_key(token, serial);
    Ok(pyo3::types::PyBytes::new(py, &key).into())
}

#[pyfunction]
fn hex_to_bytes_native(py: Python<'_>, hex: &str) -> PyResult<Py<pyo3::types::PyBytes>> {
    let bytes = tagotip_secure::hex_to_bytes(hex)
        .ok_or_else(|| PyValueError::new_err("invalid hex string"))?;
    Ok(pyo3::types::PyBytes::new(py, &bytes).into())
}

#[pyfunction]
fn bytes_to_hex_native(data: &[u8]) -> String {
    tagotip_secure::bytes_to_hex(data)
}

#[pymodule]
fn _tagotip_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_uplink_native, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ack_native, m)?)?;
    m.add_function(wrap_pyfunction!(derive_auth_hash_native, m)?)?;
    m.add_function(wrap_pyfunction!(derive_device_hash_native, m)?)?;
    m.add_function(wrap_pyfunction!(seal_uplink_native, m)?)?;
    m.add_function(wrap_pyfunction!(open_envelope_native, m)?)?;
    m.add_function(wrap_pyfunction!(parse_envelope_header_native, m)?)?;
    m.add_function(wrap_pyfunction!(is_envelope_native, m)?)?;
    m.add_function(wrap_pyfunction!(derive_key_native, m)?)?;
    m.add_function(wrap_pyfunction!(hex_to_bytes_native, m)?)?;
    m.add_function(wrap_pyfunction!(bytes_to_hex_native, m)?)?;
    Ok(())
}
