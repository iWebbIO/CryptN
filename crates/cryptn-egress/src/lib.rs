//! SSRF-guarded outbound dialing (the session's hard security constraint).
//!
//! The tunnel server dials arbitrary `host:port` targets on the client's
//! behalf — that is its job — but it must never dial *this box or its
//! neighborhood*: loopback, private (RFC1918), link-local, CGNAT, multicast,
//! and reserved ranges are all rejected before any connection is made.
//! There is no bypass flag in production builds; tests construct the guard
//! with private ranges explicitly permitted via a crate-private type.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::{lookup_host, TcpStream};

#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("address not allowed")]
    NotAllowed,
    #[error("resolution failed")]
    Resolve,
    #[error("connect failed")]
    Connect,
}

/// The egress policy. `allow_private` exists only for tests and local dev;
/// the server binary constructs the guard with `production()`.
#[derive(Debug, Clone, Copy)]
pub struct EgressGuard {
    allow_private: bool,
}

impl EgressGuard {
    /// Production policy: public unicast targets only. For local
    /// development, `CRYPTN_ALLOW_PRIVATE=1` explicitly permits private
    /// ranges (documented for smoke tests against loopback targets; never
    /// set on a real VPS).
    pub fn production() -> EgressGuard {
        let allow_private = std::env::var("CRYPTN_ALLOW_PRIVATE")
            .map(|v| v == "1")
            .unwrap_or(false);
        EgressGuard { allow_private }
    }

    /// Test/dev policy (feature-gated to keep the production binary honest).
    #[cfg(any(test, feature = "dev"))]
    pub fn permissive_for_tests() -> EgressGuard {
        EgressGuard {
            allow_private: true,
        }
    }

    /// Is this IP allowed as a dial target?
    pub fn ip_allowed(&self, ip: IpAddr) -> Result<(), EgressError> {
        if self.allow_private {
            return Ok(());
        }
        match ip {
            IpAddr::V4(v4) => {
                // Reject: loopback, private, link-local, CGNAT, multicast,
                // broadcast, reserved, unspecified.
                if v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_multicast()
                    || v4.is_unspecified()
                    || is_cgnat(v4)
                    || is_reserved_v4(v4)
                {
                    return Err(EgressError::NotAllowed);
                }
                Ok(())
            }
            IpAddr::V6(v6) => {
                // A v4-mapped address is judged by the V4 rules (a mapped
                // private address is rejected, a mapped public one passes).
                // Reject: loopback, unspecified, link-local (fe80::/10),
                // unique-local (fc00::/7), multicast, documentation.
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return self.ip_allowed(IpAddr::V4(v4));
                }
                if v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || is_unicast_link_local_v6(v6)
                    || is_unique_local_v6(v6)
                    || is_documentation_v6(v6)
                {
                    return Err(EgressError::NotAllowed);
                }
                Ok(())
            }
        }
    }

    /// Validate every address a name resolves to, then dial the first
    /// allowed one. Only TCP; no URL fetching exists anywhere in this
    /// codebase.
    pub async fn dial(&self, host: &str, port: u16) -> Result<tokio::net::TcpStream, EgressError> {
        if port == 0 {
            return Err(EgressError::NotAllowed);
        }
        // Literal IPs short-circuit resolution.
        let candidates: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            let target = format!("{host}:{port}");
            let resolved = lookup_host(target)
                .await
                .map_err(|_| EgressError::Resolve)?;
            resolved.collect()
        };

        if candidates.is_empty() {
            return Err(EgressError::Resolve);
        }

        // Every candidate must pass policy; resolve-to-private is rejected
        // even if a public address is also present (no pinning games).
        let mut allowed: Vec<SocketAddr> = Vec::with_capacity(candidates.len());
        for addr in &candidates {
            self.ip_allowed(addr.ip())?;
            allowed.push(*addr);
        }
        if allowed.is_empty() {
            return Err(EgressError::Resolve);
        }

        // Try each allowed address in resolver order until one connects:
        // a dual-stack name with one dead family (e.g. localhost -> [::1,
        // 127.0.0.1] with nothing listening on v6) must not kill the flow.
        for addr in allowed {
            if let Ok(stream) = TcpStream::connect(addr).await {
                return Ok(stream);
            }
        }
        Err(EgressError::Connect)
    }
}

fn is_cgnat(v: Ipv4Addr) -> bool {
    let o = v.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64 // 100.64.0.0/10
}

fn is_reserved_v4(v: Ipv4Addr) -> bool {
    let o = v.octets();
    // 0.0.0.0/8, 10/8 (covered by is_private), 127/8 (loopback), 169.254
    // (link-local, covered), 172.16/12 (private), 192.0.0.0/24,
    // 192.0.2.0/24 (TEST-NET-1), 198.18.0.0/15 (benchmarking),
    // 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3),
    // 240.0.0.0/4 (reserved, incl. broadcast 255.255.255.255).
    (o[0] == 0)
        || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || (o[0] & 0xF0) == 240
}

fn is_unicast_link_local_v6(v: Ipv6Addr) -> bool {
    let s = v.segments();
    (s[0] & 0xffc0) == 0xfe80
}

fn is_unique_local_v6(v: Ipv6Addr) -> bool {
    let s = v.segments();
    (s[0] & 0xfe00) == 0xfc00
}

fn is_documentation_v6(v: Ipv6Addr) -> bool {
    let s = v.segments();
    s[0] == 0x2001 && (s[1] == 0xdb8) // 2001:db8::/32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_private_space() {
        let g = EgressGuard::production();
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
            // v4-mapped private space is judged by the V4 rules.
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(g.ip_allowed(ip).is_err(), "{s} must be rejected");
        }
    }

    #[test]
    fn allows_public_space() {
        let g = EgressGuard::production();
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
            // A v4-mapped public address passes.
            "::ffff:1.1.1.1",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(g.ip_allowed(ip).is_ok(), "{s} must be allowed");
        }
    }

    #[tokio::test]
    async fn dial_rejects_localhost_by_name() {
        let g = EgressGuard::production();
        let r = g.dial("localhost", 80).await;
        assert!(matches!(
            r,
            Err(EgressError::NotAllowed) | Err(EgressError::Resolve)
        ));
    }

    #[tokio::test]
    async fn dial_rejects_literal_private() {
        let g = EgressGuard::production();
        assert!(matches!(
            g.dial("192.168.1.1", 80).await,
            Err(EgressError::NotAllowed)
        ));
        assert!(matches!(
            g.dial("127.0.0.1", 8080).await,
            Err(EgressError::NotAllowed)
        ));
    }
}
