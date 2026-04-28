use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnEvent {
    OpenVpnStarted { pid: u32 },
    ManagementConnected,
    AuthPromptReceived,
    SamlChallengeReceived,
    BrowserOpened,
    SamlAssertionReceived,
    Connected { vpn_ip: Option<IpAddr> },
    Reconnecting { reason: Option<String> },
    Disconnected,
    Warning { message: String },
    Log { line: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Disconnected,
    Interrupted,
    OpenVpnExited,
}
