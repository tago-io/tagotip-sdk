/// Format a `u32` as decimal into a byte buffer.
/// Returns the number of bytes written, or `None` if the buffer is too small.
/// Maximum output is 10 digits for u32.
pub fn format_u32(value: u32, out: &mut [u8]) -> Option<usize> {
    if value == 0 {
        if out.is_empty() {
            return None;
        }
        out[0] = b'0';
        return Some(1);
    }

    // Max u32 = 4294967295 = 10 digits
    let mut buf = [0u8; 10];
    let mut pos = buf.len();
    let mut v = value;

    while v > 0 {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }

    let len = buf.len() - pos;
    if out.len() < len {
        return None;
    }
    out[..len].copy_from_slice(&buf[pos..]);
    Some(len)
}

/// Format a `u64` as decimal into a byte buffer.
/// Returns the number of bytes written, or `None` if the buffer is too small.
/// Maximum output is 20 digits for u64.
pub fn format_u64(value: u64, out: &mut [u8]) -> Option<usize> {
    if value == 0 {
        if out.is_empty() {
            return None;
        }
        out[0] = b'0';
        return Some(1);
    }

    // Max u64 = 18446744073709551615 = 20 digits
    let mut buf = [0u8; 20];
    let mut pos = buf.len();
    let mut v = value;

    while v > 0 {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }

    let len = buf.len() - pos;
    if out.len() < len {
        return None;
    }
    out[..len].copy_from_slice(&buf[pos..]);
    Some(len)
}
