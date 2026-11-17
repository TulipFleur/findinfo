//! Pure helpers: domain normalization, extraction, dedupe.
//! No regex crate on purpose: keeps the binary small and predictable.

/// Normalize a candidate hostname. Returns None if it is not a plausible FQDN.
pub fn canon_domain(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_ascii_lowercase();
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    // strip scheme / path / port / wildcard
    for p in ["http://", "https://"] {
        if let Some(rest) = s.strip_prefix(p) {
            s = rest.to_string();
        }
    }
    if let Some(i) = s.find('/') {
        s.truncate(i);
    }
    if let Some(i) = s.find('@') {
        s = s[i + 1..].to_string();
    }
    if s.starts_with("*.") {
        s = s[2..].to_string();
    }
    // drop :port only when it looks like one (avoid breaking ipv6)
    if let Some(i) = s.rfind(':') {
        let tail = &s[i + 1..];
        if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
            s.truncate(i);
        }
    }
    s = s.trim_end_matches('.').to_string();
    if !s.contains('.') || s.starts_with('.') || s.ends_with('.') {
        return None;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return None;
    }
    // each label sanity check
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }
    let tld = s.rsplit('.').next().unwrap_or("");
    if tld.len() < 2 || tld.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(s)
}

/// Does this host belong to root (root itself or a subdomain)?
pub fn under(host: &str, root: &str) -> bool {
    host == root || host.ends_with(&format!(".{}", root))
}

/// Scan arbitrary text (JSON, HTML, CSV) for hosts ending in root.
///
/// This is the single extractor used by every source: it does not care about
/// the response format, only about hostname-shaped tokens. That is why adding
/// a source needs no parser code.
pub fn extract_hosts(text: &str, root: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes = text.as_bytes();
    let root_b = root.as_bytes();
    let mut i = 0usize;
    while i + root_b.len() <= bytes.len() {
        // fast skip: look for start of root
        if !text[i..].starts_with(root) {
            i += 1;
            continue;
        }
        // walk backwards to the beginning of the hostname token
        let mut start = i;
        while start > 0 {
            let c = bytes[start - 1] as char;
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '*' {
                start -= 1;
            } else {
                break;
            }
        }
        // walk forward to the end of the token
        let mut end = i + root_b.len();
        while end < bytes.len() {
            let c = bytes[end] as char;
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                end += 1;
            } else {
                break;
            }
        }
        // Fix JSON/JS escape artifacts: in "\nwww.example.com" the backward
        // walk would swallow the escape letter 'n'. Drop one leading char when
        // the token is preceded by a backslash.
        if start > 0 && start < i && bytes[start - 1] == b'\\' {
            start += 1;
        }
        let token = &text[start..end];
        if let Some(h) = canon_domain(token) {
            if under(&h, root) && !h.contains('_') {
                out.push(h);
            }
        }
        i = end.max(i + 1);
    }
    out
}

/// Stable dedupe, preserving first-seen order.
pub fn dedupe(mut v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    v.retain(|x| seen.insert(x.clone()));
    v
}

/// Minimal base64 (for the FOFA query parameter, which needs encoding).
pub fn b64(input: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
