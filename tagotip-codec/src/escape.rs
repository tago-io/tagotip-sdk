/// Returns `true` if the string contains any backslash escape sequences.
#[must_use]
pub fn needs_unescape(s: &str) -> bool {
    s.as_bytes().contains(&b'\\')
}

/// Unescape a `TagoTiP` string into a caller-provided buffer.
///
/// Decodes: `\|` → `|`, `\[` → `[`, `\]` → `]`, `\;` → `;`, `\,` → `,`,
/// `\{` → `{`, `\}` → `}`, `\#` → `#`, `\@` → `@`, `\^` → `^`,
/// `\\` → `\`, `\n` → newline (0x0A).
///
/// Returns the number of bytes written to `out`, or `None` if `out` is too small.
pub fn unescape_into(s: &str, out: &mut [u8]) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut w = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            let decoded = match next {
                b'|' | b'[' | b']' | b';' | b',' | b'{' | b'}' | b'#' | b'@' | b'^' | b'\\' => next,
                b'n' => b'\n',
                _ => {
                    // Not a recognized escape — output the backslash literally
                    if w >= out.len() {
                        return None;
                    }
                    out[w] = b'\\';
                    w += 1;
                    i += 1;
                    continue;
                }
            };
            if w >= out.len() {
                return None;
            }
            out[w] = decoded;
            w += 1;
            i += 2;
        } else {
            if w >= out.len() {
                return None;
            }
            out[w] = bytes[i];
            w += 1;
            i += 1;
        }
    }

    Some(w)
}

/// Characters that need escaping in string values and metadata values.
const STRUCTURAL: &[u8] = b"|[];,{}#@^\\\n";

/// Returns `true` if the byte needs escaping in a string/metadata value context.
fn needs_escape(b: u8) -> bool {
    STRUCTURAL.contains(&b)
}

/// Escape a string for use in a `TagoTiP` frame, writing into the output buffer.
///
/// Returns the number of bytes written, or `None` if `out` is too small.
pub fn escape_into(s: &str, out: &mut [u8]) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut w = 0;

    for &b in bytes {
        if needs_escape(b) {
            if w + 1 >= out.len() {
                return None;
            }
            out[w] = b'\\';
            w += 1;
            if b == b'\n' {
                out[w] = b'n';
            } else {
                out[w] = b;
            }
            w += 1;
        } else {
            if w >= out.len() {
                return None;
            }
            out[w] = b;
            w += 1;
        }
    }

    Some(w)
}
