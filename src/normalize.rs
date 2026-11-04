//! Dependency-free message template normalization.

use std::net::{IpAddr, Ipv4Addr};

/// Normalizes volatile message content into a stable template.
///
/// UUIDs, IP addresses, hexadecimal values, and numbers are replaced in that
/// order. A bare hexadecimal token must contain both an ASCII letter and digit.
/// Therefore, long digit-only values are numbers. Digits inside an identifier
/// are normalized while its alphabetic prefix remains, so `sled7` becomes
/// `sled<n>` and `v2` becomes `v<n>`.
pub fn template(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut output = String::with_capacity(message.len());
    let mut index = 0;

    while index < bytes.len() {
        if let Some(end) = uuid_end(bytes, index) {
            output.push_str("<uuid>");
            index = end;
            continue;
        }
        if bytes[index] == b'[' {
            if let Some(end) = bracketed_ip_end(bytes, index) {
                output.push_str("<ip>");
                index = end;
                continue;
            }
        }
        if is_token_boundary(bytes, index) && bytes[index].is_ascii_digit() {
            let candidate_end = scan_ipv4_candidate(bytes, index);
            if bytes[index..candidate_end].contains(&b'.') {
                if let Some(end) = ipv4_end(bytes, index, candidate_end) {
                    output.push_str("<ip>");
                    index = end;
                    continue;
                }
                normalize_plain_span(message, bytes, index, candidate_end, &mut output);
                index = candidate_end;
                continue;
            }
        }
        if is_token_boundary(bytes, index) && is_network_byte(bytes[index]) {
            let candidate_end = scan_network_candidate(bytes, index);
            if bytes[index..candidate_end].contains(&b':') {
                if let Some(end) = ipv6_end(bytes, index, candidate_end) {
                    output.push_str("<ip>");
                    index = end;
                    continue;
                }
                normalize_plain_span(message, bytes, index, candidate_end, &mut output);
                index = candidate_end;
                continue;
            }
        }
        if let Some(end) = prefixed_hex_end(bytes, index) {
            output.push_str("<hex>");
            index = end;
            continue;
        }
        if let Some(end) = bare_hex_end(bytes, index) {
            output.push_str("<hex>");
            index = end;
            continue;
        }
        normalize_plain_at(message, bytes, &mut index, bytes.len(), &mut output);
    }

    output
}

fn uuid_end(bytes: &[u8], start: usize) -> Option<usize> {
    let end = start.checked_add(36)?;
    if end > bytes.len() || !is_token_boundary(bytes, start) || !is_token_end(bytes, end) {
        return None;
    }
    for offset in 0..36 {
        let byte = bytes[start + offset];
        if matches!(offset, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
        } else if !byte.is_ascii_hexdigit() {
            return None;
        }
    }
    Some(end)
}

fn bracketed_ip_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut end = start + 1;
    while end < bytes.len() && is_network_byte(bytes[end]) {
        end += 1;
    }
    if bytes.get(end) != Some(&b']') || !valid_ip(&bytes[start + 1..end]) {
        return None;
    }
    Some(port_end(bytes, end + 1))
}

fn ipv4_end(bytes: &[u8], start: usize, candidate_end: usize) -> Option<usize> {
    let address_end = trim_trailing_dots(bytes, start, candidate_end);
    if address_end == start
        || !is_token_end(bytes, address_end)
        || !valid_ipv4(&bytes[start..address_end])
    {
        return None;
    }
    Some(port_end(bytes, address_end))
}

fn ipv6_end(bytes: &[u8], start: usize, candidate_end: usize) -> Option<usize> {
    let address_end = trim_trailing_dots(bytes, start, candidate_end);
    if address_end == start
        || !is_token_end(bytes, address_end)
        || !valid_ip(&bytes[start..address_end])
    {
        return None;
    }
    Some(address_end)
}

fn valid_ipv4(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        .is_some()
}

fn valid_ip(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .is_some()
}

fn scan_ipv4_candidate(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
        end += 1;
    }
    end
}

fn scan_network_candidate(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() && is_network_byte(bytes[end]) {
        end += 1;
    }
    end
}

fn trim_trailing_dots(bytes: &[u8], start: usize, mut end: usize) -> usize {
    while end > start && bytes[end - 1] == b'.' {
        end -= 1;
    }
    end
}

fn port_end(bytes: &[u8], start: usize) -> usize {
    if bytes.get(start) != Some(&b':') || !bytes.get(start + 1).is_some_and(u8::is_ascii_digit) {
        return start;
    }
    let mut end = start + 1;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    end
}

fn prefixed_hex_end(bytes: &[u8], start: usize) -> Option<usize> {
    if !is_token_boundary(bytes, start)
        || !matches!(bytes.get(start..start + 2), Some(b"0x") | Some(b"0X"))
    {
        return None;
    }
    let mut end = start + 2;
    while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
        end += 1;
    }
    (end > start + 2 && is_token_end(bytes, end)).then_some(end)
}

fn bare_hex_end(bytes: &[u8], start: usize) -> Option<usize> {
    if !is_token_boundary(bytes, start) || !bytes[start].is_ascii_hexdigit() {
        return None;
    }
    let mut end = start;
    while end < bytes.len() && bytes[end].is_ascii_alphanumeric() {
        end += 1;
    }
    let token = &bytes[start..end];
    (token.len() >= 8
        && token.iter().all(u8::is_ascii_hexdigit)
        && token.iter().any(u8::is_ascii_alphabetic)
        && token.iter().any(u8::is_ascii_digit)
        && is_token_end(bytes, end))
    .then_some(end)
}

fn normalize_plain_span(
    message: &str,
    bytes: &[u8],
    start: usize,
    end: usize,
    output: &mut String,
) {
    let mut index = start;
    while index < end {
        normalize_plain_at(message, bytes, &mut index, end, output);
    }
}

fn normalize_plain_at(
    message: &str,
    bytes: &[u8],
    index: &mut usize,
    end: usize,
    output: &mut String,
) {
    if let Some(next) = number_end(bytes, *index, end) {
        output.push_str("<n>");
        *index = next;
        return;
    }
    if bytes[*index].is_ascii_alphabetic() || bytes[*index] == b'_' {
        let start = *index;
        *index += 1;
        while *index < end && (bytes[*index].is_ascii_alphabetic() || bytes[*index] == b'_') {
            *index += 1;
        }
        output.push_str(&message[start..*index]);
        if *index < end && bytes[*index].is_ascii_digit() {
            while *index < end && bytes[*index].is_ascii_digit() {
                *index += 1;
            }
            output.push_str("<n>");
        }
        return;
    }
    if let Some(character) = message[*index..end].chars().next() {
        output.push(character);
        *index += character.len_utf8();
    } else {
        *index = end;
    }
}

fn number_end(bytes: &[u8], start: usize, limit: usize) -> Option<usize> {
    if start > 0 && (bytes[start - 1].is_ascii_alphabetic() || bytes[start - 1] == b'_') {
        return None;
    }
    let mut end = start;
    if matches!(bytes.get(end), Some(b'+') | Some(b'-')) {
        end += 1;
    }
    let component_start = end;
    end = decimal_end(bytes, end, limit)?;
    if end == component_start {
        return None;
    }
    loop {
        let suffix_start = end;
        while end < limit && bytes[end].is_ascii_alphabetic() {
            end += 1;
        }
        if suffix_start == end {
            break;
        }
        let Some(next) = decimal_end(bytes, end, limit) else {
            break;
        };
        end = next;
    }
    Some(end)
}

fn decimal_end(bytes: &[u8], start: usize, limit: usize) -> Option<usize> {
    let mut end = start;
    let starts_with_digits = bytes.get(end).is_some_and(u8::is_ascii_digit);
    if starts_with_digits {
        while end < limit && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if bytes.get(end) == Some(&b'.') && end + 1 < limit && bytes[end + 1].is_ascii_digit() {
            end += 1;
            while end < limit && bytes[end].is_ascii_digit() {
                end += 1;
            }
        }
        return Some(end);
    }
    if bytes.get(end) == Some(&b'.') && end + 1 < limit && bytes[end + 1].is_ascii_digit() {
        end += 1;
        while end < limit && bytes[end].is_ascii_digit() {
            end += 1;
        }
        return Some(end);
    }
    None
}

fn is_network_byte(byte: u8) -> bool {
    byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.')
}

fn is_token_boundary(bytes: &[u8], index: usize) -> bool {
    index == 0 || !is_word(bytes[index - 1])
}

fn is_token_end(bytes: &[u8], index: usize) -> bool {
    index == bytes.len() || !is_word(bytes[index])
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::template;

    #[test]
    fn normalizes_precedence_and_identifiers() {
        assert_eq!(
            template("job 550e8400-e29b-41d4-a716-446655440000 from 192.168.1.2:443"),
            "job <uuid> from <ip>"
        );
        assert_eq!(
            template("peer [2001:db8::1]:443 and 2001:db8::2"),
            "peer <ip> and <ip>"
        );
        assert_eq!(
            template("hash 0xdeadbeef and a1b2c3d4"),
            "hash <hex> and <hex>"
        );
        assert_eq!(
            template("wait -2.5s for 10GiB on sled7 v2"),
            "wait <n> for <n> on sled<n> v<n>"
        );
        assert_eq!(
            template("word abcdefgh and 1.2.3"),
            "word abcdefgh and <n><n>"
        );
        assert_eq!(template("café 99"), "café <n>");
    }

    #[test]
    fn classifies_numeric_hex_and_compound_units() {
        assert_eq!(template("read 9999999 bytes"), "read <n> bytes");
        assert_eq!(template("read 10000000 bytes"), "read <n> bytes");
        assert_eq!(template("hash deadbeef a1b2c3d4"), "hash deadbeef <hex>");
        assert_eq!(
            template("took 1h30m and 2h45m at 1920x1080"),
            "took <n> and <n> at <n>"
        );
        assert_eq!(template("at 2026-01-01T13:14:15"), "at <n><n><n>:<n>:<n>");
    }

    #[test]
    fn recognizes_only_valid_ip_addresses() {
        assert_eq!(
            template("refused by 10.0.0.1. host 10.0.0.1: down"),
            "refused by <ip>. host <ip>: down"
        );
        assert_eq!(
            template("retry at 12:34:56 through aa:bb:cc:dd:ee:ff and ::"),
            "retry at <n>:<n>:<n> through aa:bb:cc:dd:ee:ff and <ip>"
        );
    }

    #[test]
    fn scans_hostile_colon_runs_linearly() {
        let message = format!("{}g", "0:".repeat(300_000));
        let normalized = template(&message);
        assert_eq!(normalized.matches("<n>").count(), 300_000);
        assert!(!normalized.contains("<ip>"));
    }

    #[test]
    fn scans_hostile_bracket_runs_linearly() {
        let message = format!("{}g", "[".repeat(300_000));
        let normalized = template(&message);
        assert_eq!(normalized, message);
    }
}
