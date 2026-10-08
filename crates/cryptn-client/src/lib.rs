//! cryptn-client library: SOCKS front + tunnel client, importable for tests.

pub mod socks;
pub mod tunnel;

pub use tunnel::{ClientConfig, ClientErr, TunnelClient};
