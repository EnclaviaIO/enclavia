use std::fmt;

use crate::error::Error;
use crate::response::Response;

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Method::Get => write!(f, "GET"),
            Method::Post => write!(f, "POST"),
            Method::Put => write!(f, "PUT"),
            Method::Delete => write!(f, "DELETE"),
            Method::Patch => write!(f, "PATCH"),
            Method::Head => write!(f, "HEAD"),
            Method::Options => write!(f, "OPTIONS"),
        }
    }
}

/// Serialize an HTTP/1.1 request into raw bytes.
pub(crate) fn serialize_request(
    method: Method,
    path: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::new();

    // Request line
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());

    // Headers
    for (key, value) in headers {
        out.extend_from_slice(format!("{key}: {value}\r\n").as_bytes());
    }

    // Content-Length if there's a body and no Content-Length header already set
    if let Some(body) = body {
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
            out.extend_from_slice(
                format!("Content-Length: {}\r\n", body.len()).as_bytes(),
            );
        }
    }

    // End of headers
    out.extend_from_slice(b"\r\n");

    // Body
    if let Some(body) = body {
        out.extend_from_slice(body);
    }

    out
}

/// Try to parse an HTTP/1.1 response head out of `buf` while it's still being
/// streamed in. Returns `Ok(Some((status, head_len)))` when the head ends in
/// the double-CRLF terminator, `Ok(None)` when more bytes are needed, `Err`
/// when the bytes can't be a valid HTTP/1.1 response head. Used by
/// `Client::upgrade` to spot `101 Switching Protocols` (or any other status)
/// without buffering past the headers.
pub(crate) fn try_parse_response_head(buf: &[u8]) -> Result<Option<(u16, usize)>, Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf).map_err(|e| Error::HttpParse(e.to_string()))? {
        httparse::Status::Complete(n) => {
            let code = resp
                .code
                .ok_or_else(|| Error::HttpParse("Missing status code".into()))?;
            Ok(Some((code, n)))
        }
        httparse::Status::Partial => Ok(None),
    }
}

/// Whether `buf` provably holds a whole final HTTP/1.1 response: a complete
/// head, and either a status that carries no body (204, 304) or a
/// `Content-Length` whose bytes have all arrived. A response delimited only
/// by connection close cannot be proven complete and returns `false`, as
/// does an interim 1xx response, which a final response follows.
pub(crate) fn is_complete_response(buf: &[u8]) -> bool {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let Ok(httparse::Status::Complete(head_len)) = resp.parse(buf) else {
        return false;
    };
    let Some(code) = resp.code else {
        return false;
    };
    if code < 200 {
        return false;
    }
    if code == 204 || code == 304 {
        return true;
    }
    let content_length = resp
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse::<usize>().ok());
    match content_length {
        Some(len) => buf.len() - head_len >= len,
        None => false,
    }
}

/// Parse a raw HTTP/1.1 response into a `Response`.
pub(crate) fn parse_response(raw: &[u8]) -> Result<Response, Error> {
    let mut headers_buf = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers_buf);

    let status = resp
        .parse(raw)
        .map_err(|e| Error::HttpParse(e.to_string()))?;

    let header_len = match status {
        httparse::Status::Complete(len) => len,
        httparse::Status::Partial => {
            return Err(Error::HttpParse("Incomplete HTTP response".into()));
        }
    };

    let status_code = resp
        .code
        .ok_or_else(|| Error::HttpParse("Missing status code".into()))?;

    let headers: Vec<(String, String)> = resp
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();

    let body = raw[header_len..].to_vec();

    Ok(Response::new(status_code, headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_response_detection() {
        assert!(is_complete_response(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 3\r\n\r\nbig"));
        assert!(is_complete_response(b"HTTP/1.1 204 No Content\r\n\r\n"));
        // Interim response: the final one is still to come.
        assert!(!is_complete_response(b"HTTP/1.1 100 Continue\r\n\r\n"));
        // Body still short of its Content-Length.
        assert!(!is_complete_response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"));
        // Head not terminated yet.
        assert!(!is_complete_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"));
        // Close-delimited body: completeness unknowable.
        assert!(!is_complete_response(b"HTTP/1.1 200 OK\r\n\r\nwhatever"));
        assert!(!is_complete_response(b""));
    }
}
