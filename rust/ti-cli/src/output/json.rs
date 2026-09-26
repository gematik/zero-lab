//! Syntax highlighting for JSON text produced by `serde_json`. It works on the text rather
//! than on a `serde_json::Value`, so field order stays the order of the report structs.

use std::io::{self, Write};

use super::style::{JSON_KEY, JSON_LITERAL, JSON_NUMBER, JSON_STRING};

/// Writes `json`, which must be valid JSON, with keys, strings, numbers and literals
/// styled. Outside strings JSON is ASCII, so every token boundary is a char boundary.
pub fn write_highlighted(w: &mut impl Write, json: &str) -> io::Result<()> {
    let bytes = json.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let (end, style) = match bytes[i] {
            b'"' => {
                let end = string_end(bytes, i);
                let is_key = bytes[end..]
                    .iter()
                    .find(|b| !b.is_ascii_whitespace())
                    .is_some_and(|b| *b == b':');
                (end, Some(if is_key { JSON_KEY } else { JSON_STRING }))
            }
            b'-' | b'0'..=b'9' => (
                scan(bytes, i, |b| {
                    b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.' | b'e' | b'E')
                }),
                Some(JSON_NUMBER),
            ),
            b't' | b'f' | b'n' => (
                scan(bytes, i, |b| b.is_ascii_alphabetic()),
                Some(JSON_LITERAL),
            ),
            _ => (i + 1, None),
        };
        let token = &json[i..end];
        match style {
            Some(style) => write!(w, "{style}{token}{style:#}")?,
            None => w.write_all(token.as_bytes())?,
        }
        i = end;
    }
    Ok(())
}

/// The index after the closing quote of the string starting at `start`.
fn string_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

fn scan(bytes: &[u8], start: usize, accept: impl Fn(u8) -> bool) -> usize {
    start + bytes[start..].iter().take_while(|b| accept(**b)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn highlight(json: &str) -> String {
        let mut out = Vec::new();
        write_highlighted(&mut out, json).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn stripping_the_styles_gives_the_input_back() {
        let value = serde_json::json!({
            "schema": 1,
            "name": "Apotheke \"Schneerose\" ÄÖÜ",
            "list": [1.5, -2e3, true, false, null, {}],
            "nested": {"key: not a key": "value"}
        });
        let pretty = serde_json::to_string_pretty(&value).unwrap();
        let styled = highlight(&pretty);
        assert_ne!(styled, pretty);
        assert_eq!(anstream::adapter::strip_str(&styled).to_string(), pretty);
    }

    #[test]
    fn keys_and_values_are_told_apart() {
        let styled = highlight(r#"{"a": "b"}"#);
        assert!(styled.contains(&format!("{JSON_KEY}\"a\"{JSON_KEY:#}")));
        assert!(styled.contains(&format!("{JSON_STRING}\"b\"{JSON_STRING:#}")));
    }
}
