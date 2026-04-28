use crate::config::OvpnConfigSummary;
use crate::dns::{NativeDnsGuard, configure_native_dns};
use crate::openvpn::management::ManagementClient;
use crate::openvpn::process::{OpenVpnLaunchOptions, OpenVpnPrepared, OpenVpnProcess};
use crate::runtime::{OpenVpnRuntime, RuntimeDeployment, deploy_openvpn_runtime};
use crate::saml::acs::SamlAcsServer;
use crate::saml::flow::drive_saml_auth;
use crate::{Error, ExitReason, Result, VpnEvent};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserMode {
    System,
    Specific(webbrowser::Browser),
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    OpenVpnDefault,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    OpenVpnDefault,
    IgnoreDefaultRoute,
    IgnorePushedRoutes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Debug,
}

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub config_path: PathBuf,
    pub openvpn_runtime: OpenVpnRuntime,
    pub management_host: IpAddr,
    pub management_port: Option<u16>,
    pub acs_host: IpAddr,
    pub acs_port: u16,
    pub auth_timeout: Duration,
    pub browser: BrowserMode,
    pub log_level: LogLevel,
    pub dns_mode: DnsMode,
    pub route_mode: RouteMode,
    pub print_login_url: bool,
    pub event_tx: Option<mpsc::UnboundedSender<VpnEvent>>,
}

impl ConnectOptions {
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
            openvpn_runtime: OpenVpnRuntime::Bundled,
            management_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            management_port: None,
            acs_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            acs_port: 35001,
            auth_timeout: Duration::from_secs(600),
            browser: BrowserMode::System,
            log_level: LogLevel::Info,
            dns_mode: DnsMode::OpenVpnDefault,
            route_mode: RouteMode::OpenVpnDefault,
            print_login_url: false,
            event_tx: None,
        }
    }

    pub fn with_openvpn_binary(mut self, path: impl Into<PathBuf>) -> Self {
        self.openvpn_runtime = OpenVpnRuntime::External(path.into());
        self
    }

    pub fn with_openvpn_runtime(mut self, runtime: OpenVpnRuntime) -> Self {
        self.openvpn_runtime = runtime;
        self
    }

    pub fn with_browser_mode(mut self, browser: BrowserMode) -> Self {
        self.browser = browser;
        self
    }

    pub fn with_log_level(mut self, log_level: LogLevel) -> Self {
        self.log_level = log_level;
        self
    }

    pub fn with_print_login_url(mut self, print_login_url: bool) -> Self {
        self.print_login_url = print_login_url;
        self
    }

    pub fn with_dns_mode(mut self, dns_mode: DnsMode) -> Self {
        self.dns_mode = dns_mode;
        self
    }

    pub fn with_route_mode(mut self, route_mode: RouteMode) -> Self {
        self.route_mode = route_mode;
        self
    }

    pub fn with_event_sender(mut self, event_tx: mpsc::UnboundedSender<VpnEvent>) -> Self {
        self.event_tx = Some(event_tx);
        self
    }

    pub fn validate(&self) -> Result<()> {
        if !self.config_path.exists() {
            return Err(Error::ConfigNotFound(self.config_path.clone()));
        }

        if !self.config_path.is_file() {
            return Err(Error::InvalidConfig(format!(
                "expected a file path, got {}",
                self.config_path.display()
            )));
        }

        let summary = OvpnConfigSummary::parse_file(&self.config_path)?;
        if summary.remotes.is_empty() {
            return Err(Error::InvalidConfig(
                "config does not contain a remote directive".to_string(),
            ));
        }

        if !summary.supports_saml_auth_flow() {
            return Err(Error::InvalidConfig(
                "config must contain auth-user-pass or auth-federate".to_string(),
            ));
        }

        if let OpenVpnRuntime::External(openvpn_binary) = &self.openvpn_runtime {
            validate_file(openvpn_binary, "OpenVPN binary")?;
        }

        if !self.acs_host.is_loopback() {
            return Err(Error::InvalidConfig(
                "ACS host must be a loopback address".to_string(),
            ));
        }

        if !self.management_host.is_loopback() {
            return Err(Error::InvalidConfig(
                "management host must be a loopback address".to_string(),
            ));
        }

        Ok(())
    }
}

fn validate_file(path: &Path, label: &str) -> Result<()> {
    if !path.exists() {
        return Err(Error::InvalidConfig(format!(
            "{label} does not exist: {}",
            path.display()
        )));
    }

    if !path.is_file() {
        return Err(Error::InvalidConfig(format!(
            "{label} is not a file: {}",
            path.display()
        )));
    }

    Ok(())
}

#[derive(Debug, Default, Clone, Copy)]
pub struct VpnClient;

impl VpnClient {
    pub fn new() -> Self {
        Self
    }

    pub async fn connect(&self, options: ConnectOptions) -> Result<VpnSession> {
        options.validate()?;
        tracing::debug!(config = %options.config_path.display(), "validated VPN config");
        let runtime_deployment = deploy_openvpn_runtime(&options.openvpn_runtime)?;
        let openvpn_binary = runtime_deployment.binary().to_path_buf();

        tracing::debug!(host = %options.acs_host, port = options.acs_port, "binding SAML ACS server");
        let acs =
            SamlAcsServer::bind(options.acs_host, options.acs_port, options.auth_timeout).await?;

        let prepared = OpenVpnPrepared::new(OpenVpnLaunchOptions {
            binary: openvpn_binary,
            config: options.config_path.clone(),
            management_host: options.management_host,
            management_port: options.management_port,
            configure_dns: matches!(options.dns_mode, DnsMode::OpenVpnDefault),
            ignore_default_route: matches!(options.route_mode, RouteMode::IgnoreDefaultRoute),
            ignore_pushed_routes: matches!(options.route_mode, RouteMode::IgnorePushedRoutes),
        })?;
        let openvpn_configures_dns = prepared.uses_dns_scripts();

        let (internal_event_tx, event_rx) = mpsc::unbounded_channel();
        let event_tx = options.event_tx.clone().unwrap_or(internal_event_tx);
        tracing::debug!("spawning OpenVPN process");
        let mut openvpn = prepared.spawn(Some(event_tx.clone())).await?;
        tracing::debug!(management_addr = %openvpn.management_addr(), "connecting to OpenVPN management socket");
        let mut management = ManagementClient::connect_with_retry(
            openvpn.management_addr(),
            Duration::from_secs(10),
        )
        .await?;
        let _ = event_tx.send(VpnEvent::ManagementConnected);
        tracing::debug!("authenticating to OpenVPN management socket");
        time::timeout(
            Duration::from_secs(10),
            management.authenticate(openvpn.management_password()),
        )
        .await
        .map_err(|_| {
            Error::ManagementProtocol(
                "timed out waiting for OpenVPN management authentication".to_string(),
            )
        })??;

        tracing::debug!("starting SAML auth flow");
        let outcome = match drive_saml_auth(
            &mut management,
            &acs,
            options.browser,
            options.print_login_url,
            Some(event_tx.clone()),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                let _ = management.shutdown().await;
                let _ = openvpn.terminate(Duration::from_secs(3)).await;
                return Err(err);
            }
        };
        let dns_guard =
            if matches!(options.dns_mode, DnsMode::OpenVpnDefault) && !openvpn_configures_dns {
                if outcome.dns_servers.is_empty() {
                    tracing::warn!("VPN endpoint did not push DNS servers");
                    None
                } else {
                    tracing::info!(dns_servers = ?outcome.dns_servers, "configuring native DNS");
                    configure_native_dns(&outcome.dns_servers, outcome.vpn_ip)?
                }
            } else {
                None
            };
        let _ = event_tx.send(VpnEvent::Connected {
            vpn_ip: outcome.vpn_ip,
        });

        Ok(VpnSession {
            openvpn,
            management: Some(management),
            event_rx: options.event_tx.is_none().then_some(event_rx),
            dns_guard,
            vpn_ip: outcome.vpn_ip,
            _runtime_deployment: runtime_deployment,
        })
    }
}

#[derive(Debug)]
pub struct VpnSession {
    openvpn: OpenVpnProcess,
    management: Option<ManagementClient>,
    event_rx: Option<mpsc::UnboundedReceiver<VpnEvent>>,
    dns_guard: Option<NativeDnsGuard>,
    vpn_ip: Option<IpAddr>,
    _runtime_deployment: RuntimeDeployment,
}

impl VpnSession {
    pub fn pid(&self) -> Option<u32> {
        self.openvpn.pid()
    }

    pub fn vpn_ip(&self) -> Option<IpAddr> {
        self.vpn_ip
    }

    pub fn take_event_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<VpnEvent>> {
        self.event_rx.take()
    }

    pub async fn wait(&mut self) -> Result<ExitReason> {
        let result = self.openvpn.wait().await;
        let restore_result = self.restore_dns();
        result?;
        restore_result?;
        Ok(ExitReason::OpenVpnExited)
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitReason>> {
        let Some(_status) = self.openvpn.try_wait()? else {
            return Ok(None);
        };

        self.restore_dns()?;
        Ok(Some(ExitReason::OpenVpnExited))
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        let mut first_error = None;

        if let Some(management) = &mut self.management {
            if let Err(err) = management.shutdown().await {
                first_error = Some(err);
            }
        }
        self.management = None;

        if let Err(err) = self.openvpn.terminate(Duration::from_secs(5)).await
            && first_error.is_none()
        {
            first_error = Some(err);
        }

        if let Err(err) = self.restore_dns()
            && first_error.is_none()
        {
            first_error = Some(err);
        }

        if let Some(err) = first_error {
            return Err(err);
        }

        Ok(())
    }

    fn restore_dns(&mut self) -> Result<()> {
        if let Some(mut dns_guard) = self.dns_guard.take() {
            tracing::info!("restoring native DNS");
            dns_guard.restore()?;
        }
        Ok(())
    }
}
