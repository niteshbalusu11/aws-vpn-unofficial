//! Reusable AWS Client VPN orchestration library.
//!
//! The crate is intentionally library-first. The `awsvpn` binary should remain
//! a thin adapter over these public types.

mod client;
pub mod config;
#[cfg(unix)]
pub mod daemon;
pub mod diagnose;
mod dns;
mod error;
mod event;
pub mod logredact;
pub mod openvpn;
mod runtime;
pub mod saml;

pub use client::{BrowserMode, ConnectOptions, DnsMode, LogLevel, VpnClient, VpnSession};
pub use diagnose::{Diagnostics, RouteEntry, collect_diagnostics};
pub use error::{Error, Result};
pub use event::{ExitReason, VpnEvent};
pub use runtime::{OpenVpnRuntime, bundled_runtime_available, bundled_runtime_target};
