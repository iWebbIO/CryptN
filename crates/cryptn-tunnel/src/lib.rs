//! The tunnel's inner protocol: framed events inside AEAD records.
//!
//! A conversation (one proxied TCP stream) is a sequence of events:
//! - `Open` — first record: `VER(1) ATYP(1) ADDR PORT PAYLOAD...`
//!   (target host/port + any early client bytes)
//! - `Push` — payload bytes either direction
//! - `Close` — half-close signal
//! - `Ack` — pure filler ("typing indicator" cover traffic)
//!
//! Everything is sealed in records by the record layer; this module only
//! defines the framing the plaintext carries. Wire-visible sizes come from
//! the envelope's buckets, so frame boundaries never leak through JSON
//! lengths.

use std::io;

/// Address type byte (SOCKS5-shaped, because it is a familiar, compact
/// encoding — but this is *inside* the encryption).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    Domain(String, u16),
    Ip(std::net::IpAddr, u16),
}

/// One framed tunnel event (record plaintext).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Open a conversation: target + optional early payload.
    Open { target: Addr, early: Vec<u8> },
    /// Payload bytes.
    Push { data: Vec<u8> },
    /// Close the conversation (FIN).
    Close,
    /// Cover traffic / keepalive filler.
    Ack,
}

impl Frame {
    /// Encode to bytes (the record layer seals this, the envelope pads it).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        match self {
            Frame::Open { target, early } => {
                out.push(0x01);
                match target {
                    Addr::Domain(name, port) => {
                        out.push(0x03);
                        out.push(name.len() as u8);
                        out.extend_from_slice(name.as_bytes());
                        out.extend_from_slice(&port.to_be_bytes());
                    }
                    Addr::Ip(ip, port) => match ip {
                        std::net::IpAddr::V4(v4) => {
                            out.push(0x01);
                            out.extend_from_slice(&v4.octets());
                            out.extend_from_slice(&port.to_be_bytes());
                        }
                        std::net::IpAddr::V6(v6) => {
                            out.push(0x04);
                            out.extend_from_slice(&v6.octets());
                            out.extend_from_slice(&port.to_be_bytes());
                        }
                    },
                }
                out.extend_from_slice(early);
            }
            Frame::Push { data } => {
                out.push(0x02);
                out.push((data.len() >> 8) as u8);
                out.push((data.len() & 0xff) as u8);
                out.extend_from_slice(data);
            }
            Frame::Close => out.push(0x03),
            Frame::Ack => out.push(0x04),
        }
        out
    }

    /// Decode from bytes (after record open + envelope strip).
    pub fn decode(buf: &[u8]) -> io::Result<Frame> {
        let mut p = Parser { buf, pos: 0 };
        let tag = p.u8()?;
        match tag {
            0x01 => {
                let atyp = p.u8()?;
                let target = parse_addr(&mut p, atyp)?;
                Ok(Frame::Open {
                    target,
                    early: p.rest().to_vec(),
                })
            }
            0x02 => {
                let len = p.u16()? as usize;
                let data = p.take(len)?.to_vec();
                Ok(Frame::Push { data })
            }
            0x03 => Ok(Frame::Close),
            0x04 => Ok(Frame::Ack),
            _ => Err(invalid("bad frame tag")),
        }
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Parse an address by ATYP byte (0x01 IPv4, 0x03 domain, 0x04 IPv6).
fn parse_addr(p: &mut Parser<'_>, atyp: u8) -> io::Result<Addr> {
    match atyp {
        0x01 => {
            let mut o = [0u8; 4];
            o.copy_from_slice(p.take(4)?);
            Ok(Addr::Ip(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(o)),
                p.u16()?,
            ))
        }
        0x03 => {
            let len = p.u8()? as usize;
            let name =
                String::from_utf8(p.take(len)?.to_vec()).map_err(|_| invalid("bad domain"))?;
            let port = p.u16()?;
            Ok(Addr::Domain(name, port))
        }
        0x04 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(p.take(16)?);
            Ok(Addr::Ip(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(o)),
                p.u16()?,
            ))
        }
        _ => Err(invalid("bad atyp")),
    }
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn u8(&mut self) -> io::Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(invalid("truncated frame"));
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self) -> io::Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(invalid("truncated frame"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn rest(&mut self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_round_trip_domain() {
        let f = Frame::Open {
            target: Addr::Domain("example.com".into(), 443),
            early: b"GET / HTTP/1.1\r\n".to_vec(),
        };
        assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
    }

    #[test]
    fn open_round_trip_ipv6() {
        let f = Frame::Open {
            target: Addr::Ip("2606:4700::1111".parse().unwrap(), 80),
            early: vec![],
        };
        assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
    }

    #[test]
    fn push_round_trip() {
        let f = Frame::Push {
            data: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
    }

    #[test]
    fn close_and_ack() {
        assert_eq!(Frame::decode(&Frame::Close.encode()).unwrap(), Frame::Close);
        assert_eq!(Frame::decode(&Frame::Ack.encode()).unwrap(), Frame::Ack);
    }

    #[test]
    fn truncation_rejected() {
        let f = Frame::Push { data: vec![9; 40] };
        let enc = f.encode();
        assert!(Frame::decode(&enc[..enc.len() - 1]).is_err());
        assert!(Frame::decode(&[]).is_err());
        assert!(Frame::decode(&[0x99]).is_err());
    }

    #[test]
    fn push_max_64k() {
        let f = Frame::Push {
            data: vec![7; 65535],
        };
        assert_eq!(Frame::decode(&f.encode()).unwrap().encode(), f.encode());
    }
}
