//! The query of a URL, decoded; enough for a `Location` with `code`, `state` and the
//! IDP's error members. No URL crate: the values are short and the shape fixed.

/// The `name=value` pairs of `url`'s query, percent-decoded (`+` is a space).
pub fn pairs(url: &str) -> Vec<(String, String)> {
    let Some((_, query)) = url.split_once('?') else {
        return Vec::new();
    };
    let query = query.split('#').next().unwrap_or_default();
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            (decode(name), decode(value))
        })
        .collect()
}

/// Percent-decoding; an invalid escape is kept as it is.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&text[i + 1..i + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    i += 2;
                }
                Err(_) => out.push(b'%'),
            },
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_query_only() {
        let url = "https://rp.example/cb?code=ab%2Fc&state=x+y&empty&error=invalid_request#frag";
        assert_eq!(
            pairs(url),
            vec![
                ("code".to_owned(), "ab/c".to_owned()),
                ("state".to_owned(), "x y".to_owned()),
                ("empty".to_owned(), String::new()),
                ("error".to_owned(), "invalid_request".to_owned()),
            ]
        );
        assert!(pairs("https://rp.example/cb").is_empty());
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
    }
}
