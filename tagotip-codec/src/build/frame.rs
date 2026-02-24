use crate::error::BuildError;
use crate::fmt;
use crate::types::{
    AckDetail, AckFrame, AckStatus, HeadlessFrame, MetaPair, MetaRange, Method, Operator,
    PassthroughEncoding, PullBody, PushBody, UplinkFrame, Value, Variable,
};

/// A cursor-based writer into a caller-provided byte buffer.
pub struct FrameWriter<'buf> {
    buf: &'buf mut [u8],
    pos: usize,
}

impl<'buf> FrameWriter<'buf> {
    /// Create a new writer over the given buffer.
    pub fn new(buf: &'buf mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the number of bytes written so far.
    #[must_use]
    pub fn written(&self) -> usize {
        self.pos
    }

    /// Write raw bytes to the buffer.
    fn write_bytes(&mut self, data: &[u8]) -> Result<(), BuildError> {
        if self.pos + data.len() > self.buf.len() {
            return Err(BuildError::buffer_too_small());
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }

    /// Write a single byte.
    fn write_byte(&mut self, b: u8) -> Result<(), BuildError> {
        if self.pos >= self.buf.len() {
            return Err(BuildError::buffer_too_small());
        }
        self.buf[self.pos] = b;
        self.pos += 1;
        Ok(())
    }

    /// Write a raw string (no escaping).
    fn write_str(&mut self, s: &str) -> Result<(), BuildError> {
        self.write_bytes(s.as_bytes())
    }

    /// Write a pipe separator.
    fn write_pipe(&mut self) -> Result<(), BuildError> {
        self.write_byte(b'|')
    }

    /// Write a u32 value as decimal.
    fn write_u32(&mut self, value: u32) -> Result<(), BuildError> {
        let n = fmt::format_u32(value, &mut self.buf[self.pos..])
            .ok_or_else(BuildError::buffer_too_small)?;
        self.pos += n;
        Ok(())
    }

    /// Write a variable's operator and value.
    fn write_value(&mut self, op: Operator, value: &Value<'_>) -> Result<(), BuildError> {
        match op {
            Operator::Number => {
                self.write_str(":=")?;
                if let Value::Number(n) = value {
                    self.write_str(n)?;
                }
            }
            Operator::String => {
                self.write_byte(b'=')?;
                if let Value::String(s) = value {
                    self.write_str(s)?;
                }
            }
            Operator::Boolean => {
                self.write_str("?=")?;
                if let Value::Boolean(b) = value {
                    self.write_str(if *b { "true" } else { "false" })?;
                }
            }
            Operator::Location => {
                self.write_str("@=")?;
                if let Value::Location { lat, lng, alt } = value {
                    self.write_str(lat)?;
                    self.write_byte(b',')?;
                    self.write_str(lng)?;
                    if let Some(a) = alt {
                        self.write_byte(b',')?;
                        self.write_str(a)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Write metadata pairs from a pool slice.
    fn write_metadata_pairs(&mut self, pairs: &[MetaPair<'_>]) -> Result<(), BuildError> {
        self.write_byte(b'{')?;
        for (i, pair) in pairs.iter().enumerate() {
            if i > 0 {
                self.write_byte(b',')?;
            }
            self.write_str(pair.key)?;
            self.write_byte(b'=')?;
            self.write_str(pair.value)?;
        }
        self.write_byte(b'}')?;
        Ok(())
    }

    /// Write a single variable, looking up metadata from the pool.
    fn write_variable(
        &mut self,
        var: &Variable<'_>,
        meta_pool: &[MetaPair<'_>],
    ) -> Result<(), BuildError> {
        self.write_str(var.name)?;
        self.write_value(var.operator, &var.value)?;

        // #unit (not for location)
        if let Some(unit) = var.unit {
            self.write_byte(b'#')?;
            self.write_str(unit)?;
        }

        // @timestamp
        if let Some(ts) = var.timestamp {
            self.write_byte(b'@')?;
            self.write_str(ts)?;
        }

        // ^group
        if let Some(group) = var.group {
            self.write_byte(b'^')?;
            self.write_str(group)?;
        }

        // {metadata}
        if let Some(range) = var.meta {
            let start = range.start as usize;
            let end = start + range.len as usize;
            self.write_metadata_pairs(&meta_pool[start..end])?;
        }

        Ok(())
    }

    /// Write body-level modifiers.
    fn write_body_modifiers(
        &mut self,
        group: Option<&str>,
        timestamp: Option<&str>,
        body_meta: Option<MetaRange>,
        meta_pool: &[MetaPair<'_>],
    ) -> Result<(), BuildError> {
        if let Some(ts) = timestamp {
            self.write_byte(b'@')?;
            self.write_str(ts)?;
        }
        if let Some(g) = group {
            self.write_byte(b'^')?;
            self.write_str(g)?;
        }
        if let Some(range) = body_meta {
            let start = range.start as usize;
            let end = start + range.len as usize;
            self.write_metadata_pairs(&meta_pool[start..end])?;
        }
        Ok(())
    }
}

/// Build a complete uplink frame into the buffer.
/// Returns the number of bytes written.
pub fn build_uplink(frame: &UplinkFrame<'_>, buf: &mut [u8]) -> Result<usize, BuildError> {
    let mut w = FrameWriter::new(buf);

    // METHOD
    let method_str = match frame.method {
        Method::Push => "PUSH",
        Method::Pull => "PULL",
        Method::Ping => "PING",
    };
    w.write_str(method_str)?;

    // |!N (optional)
    if let Some(seq) = frame.seq {
        w.write_pipe()?;
        w.write_byte(b'!')?;
        w.write_u32(seq)?;
    }

    // |AUTH
    w.write_pipe()?;
    w.write_str(frame.auth)?;

    // |SERIAL
    w.write_pipe()?;
    w.write_str(frame.serial)?;

    // |BODY
    match frame.method {
        Method::Push => {
            if let Some(ref push_body) = frame.push_body {
                w.write_pipe()?;
                write_push_body(&mut w, push_body)?;
            }
        }
        Method::Pull => {
            if let Some(ref pull_body) = frame.pull_body {
                w.write_pipe()?;
                write_pull_body(&mut w, pull_body)?;
            }
        }
        Method::Ping => {}
    }

    Ok(w.written())
}

/// Build an ACK frame into the buffer.
/// Returns the number of bytes written.
pub fn build_ack(frame: &AckFrame<'_>, buf: &mut [u8]) -> Result<usize, BuildError> {
    let mut w = FrameWriter::new(buf);

    w.write_str("ACK")?;

    // |!N (optional)
    if let Some(seq) = frame.seq {
        w.write_pipe()?;
        w.write_byte(b'!')?;
        w.write_u32(seq)?;
    }

    // |STATUS
    w.write_pipe()?;
    let status_str = match frame.status {
        AckStatus::Ok => "OK",
        AckStatus::Pong => "PONG",
        AckStatus::Cmd => "CMD",
        AckStatus::Err => "ERR",
    };
    w.write_str(status_str)?;

    // |DETAIL (optional)
    if let Some(ref detail) = frame.detail {
        w.write_pipe()?;
        match detail {
            AckDetail::Count(count) => w.write_u32(*count)?,
            AckDetail::Variables(vars) => w.write_str(vars)?,
            AckDetail::Command(cmd) => w.write_str(cmd)?,
            AckDetail::Error { text, .. } => w.write_str(text)?,
            AckDetail::Raw(raw) => w.write_str(raw)?,
        }
    }

    Ok(w.written())
}

/// Build an ACK inner frame for TagoTiP/S: `STATUS[|DETAIL]` (no `ACK|` prefix, no seq).
/// Returns the number of bytes written.
pub fn build_ack_inner(frame: &AckFrame<'_>, buf: &mut [u8]) -> Result<usize, BuildError> {
    let mut w = FrameWriter::new(buf);

    let status_str = match frame.status {
        AckStatus::Ok => "OK",
        AckStatus::Pong => "PONG",
        AckStatus::Cmd => "CMD",
        AckStatus::Err => "ERR",
    };
    w.write_str(status_str)?;

    if let Some(ref detail) = frame.detail {
        w.write_pipe()?;
        match detail {
            AckDetail::Count(count) => w.write_u32(*count)?,
            AckDetail::Variables(vars) => w.write_str(vars)?,
            AckDetail::Command(cmd) => w.write_str(cmd)?,
            AckDetail::Error { text, .. } => w.write_str(text)?,
            AckDetail::Raw(raw) => w.write_str(raw)?,
        }
    }

    Ok(w.written())
}

/// Build a headless inner frame (SERIAL|BODY for PUSH/PULL, SERIAL for PING).
/// Returns the number of bytes written.
pub fn build_headless(
    method: Method,
    frame: &HeadlessFrame<'_>,
    buf: &mut [u8],
) -> Result<usize, BuildError> {
    let mut w = FrameWriter::new(buf);

    w.write_str(frame.serial)?;

    match method {
        Method::Push => {
            if let Some(ref push_body) = frame.push_body {
                w.write_pipe()?;
                write_push_body(&mut w, push_body)?;
            }
        }
        Method::Pull => {
            if let Some(ref pull_body) = frame.pull_body {
                w.write_pipe()?;
                write_pull_body(&mut w, pull_body)?;
            }
        }
        Method::Ping => {}
    }

    Ok(w.written())
}

/// Write a PUSH body (structured or passthrough).
fn write_push_body(w: &mut FrameWriter<'_>, body: &PushBody<'_>) -> Result<(), BuildError> {
    match body {
        PushBody::Passthrough(pt) => {
            match pt.encoding {
                PassthroughEncoding::Hex => w.write_str(">x")?,
                PassthroughEncoding::Base64 => w.write_str(">b")?,
            }
            w.write_str(pt.data)?;
        }
        PushBody::Structured(structured) => {
            let pool = structured.meta_pool.as_slice();
            w.write_body_modifiers(
                structured.group,
                structured.timestamp,
                structured.body_meta,
                pool,
            )?;
            w.write_byte(b'[')?;
            for (i, var) in structured.variables.iter().enumerate() {
                if i > 0 {
                    w.write_byte(b';')?;
                }
                w.write_variable(var, pool)?;
            }
            w.write_byte(b']')?;
        }
    }
    Ok(())
}

/// Write a PULL body.
fn write_pull_body(w: &mut FrameWriter<'_>, body: &PullBody<'_>) -> Result<(), BuildError> {
    w.write_byte(b'[')?;
    for (i, name) in body.variables.iter().enumerate() {
        if i > 0 {
            w.write_byte(b';')?;
        }
        w.write_str(name)?;
    }
    w.write_byte(b']')?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Standalone build functions
// ---------------------------------------------------------------------------

/// Build a PUSH body into a buffer. Returns the number of bytes written.
pub fn build_push_body(body: &PushBody<'_>, buf: &mut [u8]) -> Result<usize, BuildError> {
    let mut w = FrameWriter::new(buf);
    write_push_body(&mut w, body)?;
    Ok(w.written())
}

/// Build a PULL body into a buffer. Returns the number of bytes written.
pub fn build_pull_body(body: &PullBody<'_>, buf: &mut [u8]) -> Result<usize, BuildError> {
    let mut w = FrameWriter::new(buf);
    write_pull_body(&mut w, body)?;
    Ok(w.written())
}

/// Build a single variable into a buffer. Returns the number of bytes written.
pub fn build_variable(
    var: &Variable<'_>,
    meta_pool: &[MetaPair<'_>],
    buf: &mut [u8],
) -> Result<usize, BuildError> {
    let mut w = FrameWriter::new(buf);
    w.write_variable(var, meta_pool)?;
    Ok(w.written())
}

/// Build a metadata block (`{key=val,...}`) into a buffer. Returns the number of bytes written.
pub fn build_metadata(pairs: &[MetaPair<'_>], buf: &mut [u8]) -> Result<usize, BuildError> {
    let mut w = FrameWriter::new(buf);
    w.write_metadata_pairs(pairs)?;
    Ok(w.written())
}
