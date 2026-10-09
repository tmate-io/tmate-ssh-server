//! PROXY protocol v1 (HAProxy) header, read before the SSH banner when the
//! server runs behind a load balancer (`-x`). Only the human-readable v1
//! form is supported, as in the old server's `get_client_ip_proxy_protocol`:
//!
//! ```text
//! PROXY TCP4 <src> <dst> <sport> <dport>\r\n
//! PROXY TCP6 <src> <dst> <sport> <dport>\r\n
//! PROXY UNKNOWN[ anything]\r\n
//! ```
//!
//! The line is at most 107 bytes including the CRLF. It is read one byte at
//! a time so nothing past the line is consumed: the rest of the stream
//! belongs to the SSH transport.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

/// Longest valid v1 line, CRLF included (from the protocol specification).
pub const MAX_HEADER_LEN: usize = 107;

const SIGNATURE: &[u8] = b"PROXY ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    /// The proxy knows the original endpoints.
    Tcp { src: SocketAddr, dst: SocketAddr },
    /// `PROXY UNKNOWN`: the proxy forwarded something it could not describe;
    /// the receiver is told to fall back to the socket's own addresses.
    Unknown,
}

impl Header {
    /// The original client address, when the header carries one.
    pub fn source(&self) -> Option<SocketAddr> {
        match self {
            Header::Tcp { src, .. } => Some(*src),
            Header::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The line does not start with `PROXY `.
    BadSignature,
    /// More than `MAX_HEADER_LEN` bytes without a line ending.
    TooLong,
    /// Line ended other than with `\r\n`, or a field is malformed.
    Malformed(&'static str),
    /// The peer closed before sending a full line.
    Eof,
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSignature => write!(f, "line does not start with \"PROXY \""),
            Error::TooLong => write!(f, "line longer than {MAX_HEADER_LEN} bytes"),
            Error::Malformed(what) => write!(f, "malformed header: {what}"),
            Error::Eof => write!(f, "connection closed before the header was complete"),
            Error::Io(e) => write!(f, "read error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Parses one complete header line, `\r\n` included.
pub fn parse(line: &[u8]) -> Result<Header, Error> {
    if line.len() > MAX_HEADER_LEN {
        return Err(Error::TooLong);
    }
    if !line.starts_with(SIGNATURE) {
        return Err(Error::BadSignature);
    }
    let Some(body) = line.strip_suffix(b"\r\n") else {
        return Err(Error::Malformed("missing CRLF"));
    };
    let body =
        std::str::from_utf8(&body[SIGNATURE.len()..]).map_err(|_| Error::Malformed("not ASCII"))?;
    if !body.is_ascii() {
        return Err(Error::Malformed("not ASCII"));
    }
    let mut fields = body.split(' ');
    let family = fields.next().unwrap_or("");
    match family {
        // Anything after UNKNOWN is to be ignored.
        "UNKNOWN" => Ok(Header::Unknown),
        "TCP4" | "TCP6" => {
            let [src, dst, sport, dport] = [
                fields
                    .next()
                    .ok_or(Error::Malformed("missing source address"))?,
                fields
                    .next()
                    .ok_or(Error::Malformed("missing destination address"))?,
                fields
                    .next()
                    .ok_or(Error::Malformed("missing source port"))?,
                fields
                    .next()
                    .ok_or(Error::Malformed("missing destination port"))?,
            ];
            if fields.next().is_some() {
                return Err(Error::Malformed("trailing fields"));
            }
            let (src, dst) = if family == "TCP4" {
                (parse_v4(src)?, parse_v4(dst)?)
            } else {
                (parse_v6(src)?, parse_v6(dst)?)
            };
            Ok(Header::Tcp {
                src: SocketAddr::new(src, parse_port(sport)?),
                dst: SocketAddr::new(dst, parse_port(dport)?),
            })
        }
        _ => Err(Error::Malformed("unknown address family")),
    }
}

fn parse_v4(s: &str) -> Result<IpAddr, Error> {
    s.parse::<Ipv4Addr>()
        .map(IpAddr::V4)
        .map_err(|_| Error::Malformed("bad IPv4 address"))
}

fn parse_v6(s: &str) -> Result<IpAddr, Error> {
    s.parse::<Ipv6Addr>()
        .map(IpAddr::V6)
        .map_err(|_| Error::Malformed("bad IPv6 address"))
}

fn parse_port(s: &str) -> Result<u16, Error> {
    // `u16::from_str` would accept a leading `+`; the spec wants plain digits.
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Malformed("bad port"));
    }
    s.parse().map_err(|_| Error::Malformed("bad port"))
}

/// Reads one header line from the start of `stream` without consuming
/// anything after it. Call under a timeout: a client that never sends the
/// line would otherwise hold the task forever.
pub async fn read_header<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Header, Error> {
    let mut line = Vec::with_capacity(MAX_HEADER_LEN);
    loop {
        let mut byte = [0u8; 1];
        match stream.read(&mut byte).await {
            Ok(0) => return Err(Error::Eof),
            Ok(_) => {}
            Err(e) => return Err(Error::Io(e.to_string())),
        }
        line.push(byte[0]);
        // Fail on the first byte that cannot be part of a valid header, so a
        // plain SSH client (or a health checker) is turned away at once.
        let prefix = &SIGNATURE[..line.len().min(SIGNATURE.len())];
        if !line.starts_with(prefix) {
            return Err(Error::BadSignature);
        }
        if byte[0] == b'\n' {
            return parse(&line);
        }
        if line.len() >= MAX_HEADER_LEN {
            return Err(Error::TooLong);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(src: &str, dst: &str) -> Header {
        Header::Tcp {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
        }
    }

    #[test]
    fn parses_tcp4() {
        assert_eq!(
            parse(b"PROXY TCP4 192.0.2.10 10.0.0.1 51234 2200\r\n"),
            Ok(tcp("192.0.2.10:51234", "10.0.0.1:2200"))
        );
    }

    #[test]
    fn parses_tcp6() {
        assert_eq!(
            parse(b"PROXY TCP6 2001:db8::1 ::1 65535 22\r\n"),
            Ok(tcp("[2001:db8::1]:65535", "[::1]:22"))
        );
    }

    #[test]
    fn longest_valid_line_fits() {
        let line = b"PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        assert!(line.len() <= MAX_HEADER_LEN);
        assert!(parse(line).is_ok());
        let padded = format!(
            "PROXY TCP4 1.1.1.1 1.1.1.1 1 {}\r\n",
            "1".repeat(MAX_HEADER_LEN - 31)
        );
        assert_eq!(padded.len(), MAX_HEADER_LEN);
        assert_eq!(parse(padded.as_bytes()), Err(Error::Malformed("bad port")));
    }

    #[test]
    fn unknown_keeps_socket_address() {
        assert_eq!(parse(b"PROXY UNKNOWN\r\n"), Ok(Header::Unknown));
        assert_eq!(
            parse(b"PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"),
            Ok(Header::Unknown)
        );
        assert_eq!(Header::Unknown.source(), None);
    }

    #[test]
    fn rejects_wrong_family_addresses() {
        assert!(parse(b"PROXY TCP4 2001:db8::1 10.0.0.1 1 2\r\n").is_err());
        assert!(parse(b"PROXY TCP6 192.0.2.1 ::1 1 2\r\n").is_err());
        assert!(parse(b"PROXY TCP5 192.0.2.1 10.0.0.1 1 2\r\n").is_err());
    }

    #[test]
    fn rejects_bad_ports_and_field_counts() {
        assert!(parse(b"PROXY TCP4 192.0.2.1 10.0.0.1 65536 2\r\n").is_err());
        assert!(parse(b"PROXY TCP4 192.0.2.1 10.0.0.1 +1 2\r\n").is_err());
        assert!(parse(b"PROXY TCP4 192.0.2.1 10.0.0.1 1\r\n").is_err());
        assert!(parse(b"PROXY TCP4 192.0.2.1 10.0.0.1 1 2 3\r\n").is_err());
        assert!(parse(b"PROXY TCP4  192.0.2.1 10.0.0.1 1 2\r\n").is_err());
    }

    #[test]
    fn rejects_truncated_garbage_and_oversize() {
        assert_eq!(
            parse(b"PROXY TCP4 192.0.2.1 10.0.0.1 1 2"),
            Err(Error::Malformed("missing CRLF"))
        );
        assert_eq!(
            parse(b"PROXY TCP4 192.0.2.1 10.0.0.1 1 2\n"),
            Err(Error::Malformed("missing CRLF"))
        );
        assert_eq!(parse(b"SSH-2.0-OpenSSH_9.9\r\n"), Err(Error::BadSignature));
        assert_eq!(parse(b""), Err(Error::BadSignature));
        let long = format!("PROXY TCP4 192.0.2.1 10.0.0.1 1 2{}\r\n", " ".repeat(100));
        assert_eq!(parse(long.as_bytes()), Err(Error::TooLong));
    }

    #[tokio::test]
    async fn reader_stops_at_the_line_end() {
        let mut stream = std::io::Cursor::new(
            b"PROXY TCP4 192.0.2.10 10.0.0.1 51234 2200\r\nSSH-2.0-x\r\n".to_vec(),
        );
        let header = read_header(&mut stream).await.unwrap();
        assert_eq!(header.source(), Some("192.0.2.10:51234".parse().unwrap()));
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"SSH-2.0-x\r\n");
    }

    #[tokio::test]
    async fn reader_rejects_ssh_banner_early() {
        // An ordinary SSH client is refused after its first byte, before it
        // could be mistaken for a slow proxy.
        let mut stream = std::io::Cursor::new(b"SSH-2.0-OpenSSH_9.9\r\n".to_vec());
        assert_eq!(read_header(&mut stream).await, Err(Error::BadSignature));
        assert_eq!(stream.position(), 1);
    }

    #[tokio::test]
    async fn reader_reports_eof_and_oversize() {
        let mut stream = std::io::Cursor::new(b"PROXY TCP4 192.0.2.10".to_vec());
        assert_eq!(read_header(&mut stream).await, Err(Error::Eof));
        let long = format!("PROXY TCP4 {}", "1".repeat(200));
        let mut stream = std::io::Cursor::new(long.into_bytes());
        assert_eq!(read_header(&mut stream).await, Err(Error::TooLong));
    }
}
