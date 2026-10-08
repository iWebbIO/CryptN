//! Byte-exact embedded assets (Ubuntu apache2 packaging originals).

/// `debian/index.html` — the "Apache2 Ubuntu Default Page: It works" page,
/// embedded verbatim (10672 bytes, 2022-03-22 revision).
pub const DEFAULT_PAGE: &[u8] = include_bytes!("../assets/index.html");

/// `debian/icons/ubuntu-logo.png` — the logo referenced by the default page
/// (184×146 RGBA PNG, 7427 bytes).
pub const UBUNTU_LOGO_PNG: &[u8] = include_bytes!("../assets/ubuntu-logo.png");
