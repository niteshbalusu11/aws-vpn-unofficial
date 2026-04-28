use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("VPN config does not exist: {0}")]
    ConfigNotFound(PathBuf),

    #[error("invalid VPN config: {0}")]
    InvalidConfig(String),

    #[error("OpenVPN binary was not found")]
    OpenVpnNotFound,

    #[error("OpenVPN process support is not implemented yet")]
    OpenVpnProcessNotImplemented,

    #[error("management protocol error: {0}")]
    ManagementProtocol(String),

    #[error("invalid SAML URL: {0}")]
    InvalidSamlUrl(String),

    #[error("VPN authentication failed: {0}")]
    AuthFailed(String),

    #[error("OpenVPN fatal error: {0}")]
    FatalOpenVpn(String),

    #[error("operation was interrupted")]
    Interrupted,
}

pub type Result<T> = std::result::Result<T, Error>;
