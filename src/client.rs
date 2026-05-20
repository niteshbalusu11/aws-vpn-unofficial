use crate::config::OvpnConfigSummary;
use crate::dns::{NativeDnsGuard, cleanup_stale_native_dns, configure_native_dns};
use crate::openvpn::management::ManagementClient;
use crate::openvpn::parser::PushedRoute;
use crate::openvpn::process::{OpenVpnLaunchOptions, OpenVpnPrepared, OpenVpnProcess};
use crate::runtime::{OpenVpnRuntime, RuntimeDeployment, deploy_openvpn_runtime};
use crate::saml::acs::SamlAcsServer;
use crate::saml::flow::{SamlFlowState, drive_saml_auth, handle_saml_management_event};
use crate::{Error, ExitReason, Result, VpnEvent};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
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
        cleanup_stale_native_dns()?;
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
            configure_dns: matches!(options.dns_mode, DnsMode::OpenVpnDefault)
                && !cfg!(target_os = "macos"),
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
        let vpn_ip = Arc::new(Mutex::new(outcome.vpn_ip));
        let reconnect_monitor = spawn_reconnect_monitor(
            management,
            acs,
            options.browser,
            options.print_login_url,
            event_tx.clone(),
            Arc::clone(&vpn_ip),
        );
        let route_monitor = spawn_route_monitor(outcome.routes.clone(), event_tx.clone());
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
            reconnect_monitor,
            route_monitor,
            event_rx: options.event_tx.is_none().then_some(event_rx),
            dns_guard,
            vpn_ip,
            _runtime_deployment: runtime_deployment,
        })
    }
}

#[derive(Debug)]
pub struct VpnSession {
    openvpn: OpenVpnProcess,
    reconnect_monitor: JoinHandle<()>,
    route_monitor: Option<JoinHandle<()>>,
    event_rx: Option<mpsc::UnboundedReceiver<VpnEvent>>,
    dns_guard: Option<NativeDnsGuard>,
    vpn_ip: Arc<Mutex<Option<IpAddr>>>,
    _runtime_deployment: RuntimeDeployment,
}

impl VpnSession {
    pub fn pid(&self) -> Option<u32> {
        self.openvpn.pid()
    }

    pub fn vpn_ip(&self) -> Option<IpAddr> {
        *self.vpn_ip.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn take_event_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<VpnEvent>> {
        self.event_rx.take()
    }

    pub async fn wait(&mut self) -> Result<ExitReason> {
        let result = self.openvpn.wait().await;
        self.reconnect_monitor.abort();
        self.abort_route_monitor();
        let restore_result = self.restore_dns();
        result?;
        restore_result?;
        Ok(ExitReason::OpenVpnExited)
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitReason>> {
        let Some(_status) = self.openvpn.try_wait()? else {
            return Ok(None);
        };

        self.reconnect_monitor.abort();
        self.abort_route_monitor();
        self.restore_dns()?;
        Ok(Some(ExitReason::OpenVpnExited))
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        let mut first_error = None;

        if let Err(err) = self.openvpn.terminate(Duration::from_secs(5)).await
            && first_error.is_none()
        {
            first_error = Some(err);
        }
        self.reconnect_monitor.abort();
        self.abort_route_monitor();

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

    fn abort_route_monitor(&mut self) {
        if let Some(route_monitor) = self.route_monitor.take() {
            route_monitor.abort();
        }
    }
}

fn spawn_reconnect_monitor(
    mut management: ManagementClient,
    acs: SamlAcsServer,
    browser: BrowserMode,
    print_login_url: bool,
    event_tx: mpsc::UnboundedSender<VpnEvent>,
    vpn_ip: Arc<Mutex<Option<IpAddr>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        match monitor_reconnects(
            &mut management,
            &acs,
            browser,
            print_login_url,
            Some(event_tx.clone()),
            vpn_ip,
        )
        .await
        {
            Ok(MonitorExit::ManagementClosed) => {
                tracing::warn!(
                    "OpenVPN management socket closed; reconnect monitor stopped for this session"
                );
                let _ = event_tx.send(VpnEvent::Warning {
                    message:
                        "OpenVPN management socket closed; reconnect monitor stopped for this session"
                            .to_string(),
                });
            }
            Err(err) => {
                tracing::warn!(error = %err, "OpenVPN management reconnect monitor stopped");
                let _ = event_tx.send(VpnEvent::Warning {
                    message: format!("OpenVPN management reconnect monitor stopped: {err}"),
                });
            }
        }
    })
}

fn spawn_route_monitor(
    routes: Vec<PushedRoute>,
    event_tx: mpsc::UnboundedSender<VpnEvent>,
) -> Option<JoinHandle<()>> {
    spawn_route_monitor_impl(routes, event_tx)
}

#[cfg(target_os = "macos")]
fn spawn_route_monitor_impl(
    routes: Vec<PushedRoute>,
    event_tx: mpsc::UnboundedSender<VpnEvent>,
) -> Option<JoinHandle<()>> {
    (!routes.is_empty()).then(|| {
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(10));
            interval.tick().await;
            loop {
                interval.tick().await;
                match macos_pushed_routes_present(&routes) {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::warn!(
                            routes = ?routes,
                            "VPN route table drift detected; reconnect may be required"
                        );
                        let _ = event_tx.send(VpnEvent::Warning {
                            message: route_drift_warning_message().to_string(),
                        });
                        break;
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "could not inspect VPN route table");
                    }
                }
            }
        })
    })
}

#[cfg(not(target_os = "macos"))]
fn spawn_route_monitor_impl(
    _routes: Vec<PushedRoute>,
    _event_tx: mpsc::UnboundedSender<VpnEvent>,
) -> Option<JoinHandle<()>> {
    None
}

#[cfg(any(target_os = "macos", test))]
fn route_drift_warning_message() -> &'static str {
    "VPN route table drift detected; reconnect may be required"
}

#[cfg(target_os = "macos")]
fn macos_pushed_routes_present(routes: &[PushedRoute]) -> Result<bool> {
    let output = std::process::Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .map_err(Error::OpenVpnProcess)?;

    if !output.status.success() {
        return Err(Error::OpenVpnProcess(std::io::Error::other(format!(
            "netstat exited with status {}",
            output.status
        ))));
    }

    Ok(pushed_routes_present_in_netstat(
        &String::from_utf8_lossy(&output.stdout),
        routes,
    ))
}

#[cfg(any(target_os = "macos", test))]
fn pushed_routes_present_in_netstat(output: &str, expected_routes: &[PushedRoute]) -> bool {
    expected_routes.iter().all(|expected| {
        output
            .lines()
            .filter_map(parse_macos_netstat_route)
            .any(|actual| actual == pushed_route_key(expected))
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_netstat_route(line: &str) -> Option<(Ipv4Addr, u8)> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 4 || fields[0] == "Destination" || fields[0] == "Internet:" {
        return None;
    }

    let interface = fields.last()?;
    if !interface.starts_with("utun") {
        return None;
    }

    parse_macos_route_destination(fields[0])
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_route_destination(destination: &str) -> Option<(Ipv4Addr, u8)> {
    if destination == "default" {
        return Some((Ipv4Addr::UNSPECIFIED, 0));
    }

    let (raw_addr, raw_prefix) = destination.split_once('/')?;
    let prefix = raw_prefix.parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }

    let mut octets = [0_u8; 4];
    let parts = raw_addr.split('.').collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    for (index, part) in parts.iter().enumerate() {
        octets[index] = part.parse::<u8>().ok()?;
    }

    let mask = prefix_mask(prefix);
    let network = u32::from(Ipv4Addr::from(octets)) & mask;
    Some((Ipv4Addr::from(network), prefix))
}

#[cfg(any(target_os = "macos", test))]
fn pushed_route_key(route: &PushedRoute) -> (Ipv4Addr, u8) {
    let prefix = netmask_prefix(route.netmask).unwrap_or(32);
    let network = u32::from(route.network) & prefix_mask(prefix);
    (Ipv4Addr::from(network), prefix)
}

#[cfg(any(target_os = "macos", test))]
fn netmask_prefix(netmask: Ipv4Addr) -> Option<u8> {
    let mut mask = u32::from(netmask);
    let mut prefix = 0_u8;

    while mask & 0x8000_0000 != 0 {
        prefix += 1;
        mask <<= 1;
    }

    (mask == 0).then_some(prefix)
}

#[cfg(any(target_os = "macos", test))]
fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MonitorExit {
    ManagementClosed,
}

async fn monitor_reconnects(
    management: &mut ManagementClient,
    acs: &SamlAcsServer,
    browser: BrowserMode,
    print_login_url: bool,
    event_tx: Option<mpsc::UnboundedSender<VpnEvent>>,
    vpn_ip: Arc<Mutex<Option<IpAddr>>>,
) -> Result<MonitorExit> {
    let mut state = SamlFlowState::default();

    loop {
        let Some(event) = management.read_event().await? else {
            tracing::debug!("OpenVPN management socket closed");
            return Ok(MonitorExit::ManagementClosed);
        };

        if let Some(outcome) = handle_saml_management_event(
            management,
            acs,
            browser,
            print_login_url,
            &event_tx,
            &mut state,
            true,
            event,
        )
        .await?
        {
            tracing::info!(vpn_ip = ?outcome.vpn_ip, "VPN reconnected");
            *vpn_ip.lock().unwrap_or_else(|err| err.into_inner()) = outcome.vpn_ip;
            if let Some(event_tx) = &event_tx {
                let _ = event_tx.send(VpnEvent::Connected {
                    vpn_ip: outcome.vpn_ip,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn reconnect_monitor_answers_saml_auth_after_connected_session() {
        let acs = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let acs_addr = acs.local_addr().unwrap();

        let management_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let management_addr = management_listener.local_addr().unwrap();
        let vpn_ip = Arc::new(Mutex::new(Some("10.0.0.10".parse().unwrap())));

        let fake_openvpn = tokio::spawn(async move {
            let (stream, _) = management_listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);

            stream
                .get_mut()
                .write_all(b">STATE:1,RECONNECTING,ping-restart,,,,,\n")
                .await
                .unwrap();
            stream
                .get_mut()
                .write_all(b">PASSWORD:Need 'Auth' username/password\n")
                .await
                .unwrap();
            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                &format!("password \"Auth\" ACS::{}", acs_addr.port()),
            )
            .await;

            stream
                .get_mut()
                .write_all(
                    b">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:state456:b'Ti9B':https://idp.example.com/saml']\n",
                )
                .await
                .unwrap();
            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                "password \"Auth\" CRV1::state456::assertion-after-reconnect",
            )
            .await;

            stream
                .get_mut()
                .write_all(b">STATE:2,CONNECTED,SUCCESS,10.0.0.11,1.2.3.4,443,,\n")
                .await
                .unwrap();
        });

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let mut management = ManagementClient::connect(management_addr).await.unwrap();
        let monitor_vpn_ip = Arc::clone(&vpn_ip);
        let monitor = tokio::spawn(async move {
            monitor_reconnects(
                &mut management,
                &acs,
                BrowserMode::Disabled,
                false,
                Some(event_tx),
                monitor_vpn_ip,
            )
            .await
        });

        loop {
            match event_rx.recv().await.unwrap() {
                VpnEvent::SamlChallengeReceived => break,
                VpnEvent::Warning { message } => panic!("{message}"),
                _ => {}
            }
        }
        post_saml_response(acs_addr, "assertion-after-reconnect").await;

        loop {
            match event_rx.recv().await.unwrap() {
                VpnEvent::Connected { vpn_ip } => {
                    assert_eq!(vpn_ip, Some("10.0.0.11".parse().unwrap()));
                    break;
                }
                VpnEvent::Warning { message } => panic!("{message}"),
                _ => {}
            }
        }

        fake_openvpn.await.unwrap();
        assert_eq!(
            monitor.await.unwrap().unwrap(),
            MonitorExit::ManagementClosed
        );
        assert_eq!(*vpn_ip.lock().unwrap(), Some("10.0.0.11".parse().unwrap()));
    }

    #[tokio::test]
    async fn reconnect_monitor_reports_management_socket_closure() {
        let acs = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();

        let management_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let management_addr = management_listener.local_addr().unwrap();
        let fake_openvpn = tokio::spawn(async move {
            let (_stream, _) = management_listener.accept().await.unwrap();
        });

        let mut management = ManagementClient::connect(management_addr).await.unwrap();
        let exit = monitor_reconnects(
            &mut management,
            &acs,
            BrowserMode::Disabled,
            false,
            None,
            Arc::new(Mutex::new(Some("10.0.0.10".parse().unwrap()))),
        )
        .await
        .unwrap();

        fake_openvpn.await.unwrap();
        assert_eq!(exit, MonitorExit::ManagementClosed);
    }

    #[test]
    fn detects_expected_pushed_routes_in_macos_netstat() {
        let output = r#"
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.4.1        UGScg                 en0
10.24/16           10.0.0.1           UGSc                utun6
203.0.113/24       10.0.0.1           UGSc                utun6
"#;

        assert!(pushed_routes_present_in_netstat(
            output,
            &[
                PushedRoute {
                    network: "10.24.0.0".parse().unwrap(),
                    netmask: "255.255.0.0".parse().unwrap(),
                },
                PushedRoute {
                    network: "203.0.113.0".parse().unwrap(),
                    netmask: "255.255.255.0".parse().unwrap(),
                },
            ],
        ));
    }

    #[test]
    fn detects_missing_pushed_route_in_macos_netstat() {
        let output = r#"
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
10.24/16           10.0.0.1           UGSc                utun6
"#;

        assert!(!pushed_routes_present_in_netstat(
            output,
            &[PushedRoute {
                network: "203.0.113.0".parse().unwrap(),
                netmask: "255.255.255.0".parse().unwrap(),
            }],
        ));
    }

    #[test]
    fn route_drift_warning_does_not_request_restart() {
        let message = route_drift_warning_message();

        assert!(message.contains("route table drift"));
        assert!(!message.contains("restart"));
        assert!(!message.contains("restarting"));
    }

    async fn expect_line(reader: &mut BufReader<TcpStream>, expected: &str) {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line.trim_end(), expected);
    }

    async fn post_saml_response(addr: std::net::SocketAddr, assertion: &str) {
        let body = format!("SAMLResponse={assertion}");
        let request = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
    }
}
