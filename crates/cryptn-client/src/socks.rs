//! SOCKS5 acceptor: local proxy entry point (remote-DNS by default).
//!
//! Hand-rolled for full control of the reply bytes. Supports CONNECT with
//! domain and IP targets, no-auth only (the tunnel authenticates at the
//! API, and a local password adds nothing), and refuses BIND/UDP.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksTarget {
    Domain(String, u16),
    Ip(std::net::IpAddr, u16),
}

/// Result of the SOCKS5 handshake.
pub struct SocksAccepted {
    pub target: SocksTarget,
    pub stream: TcpStream,
}

/// SOCKS protocol errors (close the connection; no reply on early ones).
#[derive(Debug)]
pub enum SocksError {
    Closed,
    BadProtocol,
    Unsupported,
}

/// Read the SOCKS5 greeting + request, reply, return the stream.
pub async fn accept(mut stream: TcpStream) -> Result<SocksAccepted, SocksError> {
    // Greeting: VER(5) NMETHODS METHODS...
    let mut head = [0u8; 2];
    if stream.read_exact(&mut head).await.is_err() {
        return Err(SocksError::Closed);
    }
    if head[0] != 5 {
        return Err(SocksError::BadProtocol);
    }
    let nmethods = head[1] as usize;
    if nmethods > 16 {
        return Err(SocksError::BadProtocol);
    }
    let mut methods = vec![0u8; nmethods];
    if stream.read_exact(&mut methods).await.is_err() {
        return Err(SocksError::Closed);
    }
    // We accept only NO-AUTH (0x00); anything else is refused.
    let reply: [u8; 2] = if methods.contains(&0x00) {
        [0x05, 0x00]
    } else {
        let _ = stream.write_all(&[0x05, 0xFF]).await;
        return Err(SocksError::Unsupported);
    };
    if stream.write_all(&reply).await.is_err() {
        return Err(SocksError::Closed);
    }

    // Request: VER CMD RSV ATYP ADDR PORT.
    let mut req = [0u8; 4];
    if stream.read_exact(&mut req).await.is_err() {
        return Err(SocksError::Closed);
    }
    if req[0] != 5 {
        return Err(SocksError::BadProtocol);
    }
    let target = match req[1] {
        0x01 => {
            // CONNECT
            match req[3] {
                0x01 => {
                    let mut a = [0u8; 4];
                    if stream.read_exact(&mut a).await.is_err() {
                        return Err(SocksError::Closed);
                    }
                    let mut p = [0u8; 2];
                    if stream.read_exact(&mut p).await.is_err() {
                        return Err(SocksError::Closed);
                    }
                    SocksTarget::Ip(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::from(a)),
                        u16::from_be_bytes(p),
                    )
                }
                0x03 => {
                    let mut l = [0u8; 1];
                    if stream.read_exact(&mut l).await.is_err() {
                        return Err(SocksError::Closed);
                    }
                    let mut name = vec![0u8; l[0] as usize];
                    if stream.read_exact(&mut name).await.is_err() {
                        return Err(SocksError::Closed);
                    }
                    let mut p = [0u8; 2];
                    if stream.read_exact(&mut p).await.is_err() {
                        return Err(SocksError::Closed);
                    }
                    SocksTarget::Domain(
                        String::from_utf8(name).map_err(|_| SocksError::BadProtocol)?,
                        u16::from_be_bytes(p),
                    )
                }
                0x04 => {
                    let mut a = [0u8; 16];
                    if stream.read_exact(&mut a).await.is_err() {
                        return Err(SocksError::Closed);
                    }
                    let mut p = [0u8; 2];
                    if stream.read_exact(&mut p).await.is_err() {
                        return Err(SocksError::Closed);
                    }
                    SocksTarget::Ip(
                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(a)),
                        u16::from_be_bytes(p),
                    )
                }
                _ => return Err(SocksError::BadProtocol),
            }
        }
        _ => {
            // BIND (0x02) / UDP (0x03) unsupported: reply and close.
            let _ = stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(SocksError::Unsupported);
        }
    };

    // Success reply: bound at 0.0.0.0:0 (the local app never needs the real
    // endpoint; browsers ignore it after a 0x00 status).
    let ok = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    if stream.write_all(&ok).await.is_err() {
        return Err(SocksError::Closed);
    }

    Ok(SocksAccepted { target, stream })
}

/// Tell the local app the tunnel refused the target (reply 0x04 host
/// unreachable). Called by the conversation engine when the server reports
/// the dial failed.
#[allow(dead_code)] // wired in the engine's dial-failure path
pub async fn reply_refused(mut stream: TcpStream) {
    let refused = [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let _ = stream.write_all(&refused).await;
}
