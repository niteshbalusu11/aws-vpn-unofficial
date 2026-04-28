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

    #[error("could not start OpenVPN: {0}")]
    OpenVpnSpawnFailed(std::io::Error),

    #[error("OpenVPN process failed: {0}")]
    OpenVpnProcess(std::io::Error),

    #[error("could not create secure temporary file: {0}")]
    TempFile(std::io::Error),

    #[error("management protocol error: {0}")]
    ManagementProtocol(String),

    #[error("could not connect to OpenVPN management socket: {0}")]
    ManagementConnectFailed(std::io::Error),

    #[error("OpenVPN management socket failed: {0}")]
    ManagementIo(std::io::Error),

    #[error("invalid SAML URL: {0}")]
    InvalidSamlUrl(String),

    #[error("could not bind SAML callback server: {0}")]
    AcsBindFailed(std::io::Error),

    #[error("SAML callback server failed: {0}")]
    AcsServer(std::io::Error),

    #[error("SAML login timed out")]
    SamlTimeout,

    #[error("SAML response was missing")]
    SamlResponseMissing,

    #[error("SAML response exceeded 128 KiB limit")]
    SamlResponseTooLarge,

    #[error("could not open browser: {0}")]
    BrowserLaunchFailed(std::io::Error),

    #[error("VPN authentication failed: {0}")]
    AuthFailed(String),

    #[error("OpenVPN fatal error: {0}")]
    FatalOpenVpn(String),

    #[error("diagnostic command failed: {0}")]
    DiagnosticFailed(String),

    #[error("DNS configuration failed: {0}")]
    DnsConfigurationFailed(String),

    #[error("operation was interrupted")]
    Interrupted,
}

pub type Result<T> = std::result::Result<T, Error>;
