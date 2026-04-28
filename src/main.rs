#[cfg(unix)]
use awsvpn::daemon::{
    ControlRequest, ControlResponse, ControlServer, DaemonPaths, SessionState, SessionStatus,
};
use awsvpn::{
    BrowserMode, ConnectOptions, Diagnostics, DnsMode, Error, LogLevel, RouteMode, VpnClient,
    VpnEvent, collect_diagnostics, validate_dns_search_domain,
};
use clap::{Args, Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::time;
use tracing::Level;

const DEFAULT_CONFIG_RELATIVE_PATH: &str = ".awsvpnunofficial/vpnconfig.ovpn";
const DEFAULT_DNS_DOMAINS_RELATIVE_PATH: &str = ".awsvpnunofficial/dns-domains";
#[cfg(unix)]
const DAEMON_READY_LINE: &str = "__AWSVPN_DAEMON_READY__";
#[cfg(unix)]
const DAEMON_ERROR_PREFIX: &str = "__AWSVPN_DAEMON_ERROR__\t";

#[derive(Debug, Parser)]
#[command(name = "awsvpn", version, about = "Unofficial AWS Client VPN CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Connect {
        #[command(flatten)]
        args: ConnectArgs,

        #[arg(long, help = "Keep the VPN session attached to this terminal")]
        foreground: bool,
    },
    Disconnect,
    Status,
    Diagnose,
    #[command(hide = true)]
    DaemonRun {
        #[command(flatten)]
        args: ConnectArgs,
    },
}

#[derive(Debug, Args, Clone)]
struct ConnectArgs {
    #[arg(
        value_name = "CONFIG",
        help = "OpenVPN config path [default: ~/.awsvpnunofficial/vpnconfig.ovpn]"
    )]
    config: Option<PathBuf>,

    #[arg(long)]
    openvpn: Option<PathBuf>,

    #[arg(long)]
    debug: bool,

    #[arg(long)]
    no_browser: bool,

    #[arg(long, value_parser = parse_browser)]
    browser: Option<webbrowser::Browser>,

    #[arg(long)]
    print_login_url: bool,

    #[arg(long, default_value = "openvpn", value_parser = parse_dns_mode)]
    dns: DnsMode,

    #[arg(
        long = "dns-domain",
        value_parser = parse_dns_domain,
        help = "Route DNS lookups for this domain suffix to VPN DNS; repeat for multiple internal domains"
    )]
    dns_domains: Vec<String>,

    #[arg(
        long,
        help = "Ignore VPN-pushed default routes and keep normal internet routing outside the VPN"
    )]
    no_default_route: bool,

    #[arg(
        long,
        help = "Ignore all VPN-pushed routes; useful for isolating route-related networking hangs"
    )]
    no_pushed_routes: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(&cli);

    if let Err(err) = run(cli).await {
        tracing::error!("{err}");
        if matches!(
            err,
            Error::OpenVpnNotFound | Error::BundledOpenVpnUnavailable { .. }
        ) {
            tracing::warn!(
                "hint: build or install a bundled runtime, or pass the AWS-patched OpenVPN binary with --openvpn <path>"
            );
        }
        std::process::exit(1);
    }
}

fn init_tracing(cli: &Cli) {
    let level = if cli.debug_enabled() {
        Level::DEBUG
    } else {
        Level::INFO
    };

    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(level)
        .init();
}

impl Cli {
    fn debug_enabled(&self) -> bool {
        match &self.command {
            Command::Connect { args, .. } | Command::DaemonRun { args } => args.debug,
            Command::Diagnose => false,
            Command::Disconnect | Command::Status => false,
        }
    }
}

async fn run(cli: Cli) -> awsvpn::Result<()> {
    match cli.command {
        Command::Connect { args, foreground } => {
            if foreground {
                run_foreground_connect(args).await
            } else {
                run_daemon_connect(args).await
            }
        }
        Command::Disconnect => disconnect_daemon().await,
        Command::Status => status_daemon().await,
        Command::DaemonRun { args } => run_daemon_runner(args).await,
        Command::Diagnose => {
            let diagnostics = collect_diagnostics()?;
            print_diagnostics(&diagnostics);
            Ok(())
        }
    }
}

fn connect_options(args: &ConnectArgs) -> ConnectOptions {
    let config = args.config.clone().unwrap_or_else(default_config_path);
    let dns_domains = default_dns_domains()
        .into_iter()
        .chain(args.dns_domains.clone())
        .collect::<Vec<_>>();
    let browser_mode = if args.no_browser {
        BrowserMode::Disabled
    } else if let Some(browser) = args.browser {
        BrowserMode::Specific(browser)
    } else {
        BrowserMode::System
    };

    let mut options = ConnectOptions::new(config)
        .with_log_level(if args.debug {
            LogLevel::Debug
        } else {
            LogLevel::Info
        })
        .with_browser_mode(browser_mode)
        .with_print_login_url(args.print_login_url)
        .with_dns_mode(args.dns)
        .with_dns_search_domains(dns_domains)
        .with_route_mode(if args.no_pushed_routes {
            RouteMode::IgnorePushedRoutes
        } else if args.no_default_route {
            RouteMode::IgnoreDefaultRoute
        } else {
            RouteMode::OpenVpnDefault
        });

    if let Some(openvpn) = &args.openvpn {
        options = options.with_openvpn_binary(openvpn.clone());
    }

    options
}

async fn run_foreground_connect(args: ConnectArgs) -> awsvpn::Result<()> {
    let mut options = connect_options(&args);

    let (event_tx, mut events) = tokio::sync::mpsc::unbounded_channel();
    options = options.with_event_sender(event_tx);
    let log_task = tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            print_event(event);
        }
    });

    let client = VpnClient::new();
    let mut session = match client.connect(options).await {
        Ok(session) => session,
        Err(err) => {
            log_task.abort();
            return Err(err);
        }
    };
    if let Some(pid) = session.pid() {
        tracing::info!(pid, "connected");
    } else {
        tracing::info!("connected");
    }

    tokio::select! {
        result = session.wait() => {
            result?;
        }
        signal = shutdown_signal() => {
            let signal = signal?;
            tracing::info!(signal, "disconnecting");
            session.disconnect().await?;
        }
    }

    log_task.abort();
    Ok(())
}

#[cfg(unix)]
async fn run_daemon_connect(args: ConnectArgs) -> awsvpn::Result<()> {
    let mut command = TokioCommand::new(std::env::current_exe().map_err(Error::OpenVpnProcess)?);
    command
        .arg("daemon-run")
        .args(connect_args_for_child(&args))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(Error::OpenVpnProcess)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::DaemonControl("daemon child stdout was not captured".to_string()))?;
    let mut lines = BufReader::new(stdout).lines();

    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line.map_err(Error::OpenVpnProcess)? else {
                    let status = child.wait().await.map_err(Error::OpenVpnProcess)?;
                    return Err(Error::DaemonControl(format!(
                        "daemon exited before reporting startup status: {status}"
                    )));
                };

                if line == DAEMON_READY_LINE {
                    return Ok(());
                }

                if let Some(message) = line.strip_prefix(DAEMON_ERROR_PREFIX) {
                    let _ = child.wait().await;
                    return Err(Error::DaemonControl(message.to_string()));
                }

                println!("{line}");
            }
            signal = shutdown_signal() => {
                let _ = signal?;
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(Error::Interrupted);
            }
        }
    }
}

#[cfg(not(unix))]
async fn run_daemon_connect(_args: ConnectArgs) -> awsvpn::Result<()> {
    Err(Error::DaemonControl(
        "daemon mode is currently supported on macOS and Linux".to_string(),
    ))
}

#[cfg(unix)]
async fn run_daemon_runner(args: ConnectArgs) -> awsvpn::Result<()> {
    let server = match ControlServer::bind_default().await {
        Ok(server) => server,
        Err(err) => {
            print_daemon_startup_error(&err);
            return Err(err);
        }
    };
    let paths = server.paths().clone();
    let daemon_pid = std::process::id();
    let _ = awsvpn::daemon::write_state(
        &paths,
        &SessionStatus {
            state: SessionState::Connecting,
            daemon_pid,
            openvpn_pid: None,
            vpn_ip: None,
        },
    );

    let mut options = connect_options(&args);
    let (event_tx, mut events) = tokio::sync::mpsc::unbounded_channel();
    options = options.with_event_sender(event_tx);
    let event_task = tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            print_daemon_startup_event(event);
        }
    });

    let client = VpnClient::new();
    let session = match client.connect(options).await {
        Ok(session) => session,
        Err(err) => {
            event_task.abort();
            paths.cleanup();
            print_daemon_startup_error(&err);
            return Err(err);
        }
    };
    event_task.abort();

    let status = session_status(&session, SessionState::Connected, daemon_pid);
    awsvpn::daemon::write_state(&paths, &status)?;
    println!("{DAEMON_READY_LINE}");
    let _ = std::io::stdout().flush();

    run_daemon_control_loop(server, paths, session, daemon_pid).await
}

#[cfg(not(unix))]
async fn run_daemon_runner(_args: ConnectArgs) -> awsvpn::Result<()> {
    Err(Error::DaemonControl(
        "daemon mode is currently supported on macOS and Linux".to_string(),
    ))
}

#[cfg(unix)]
async fn run_daemon_control_loop(
    server: ControlServer,
    paths: DaemonPaths,
    mut session: awsvpn::VpnSession,
    daemon_pid: u32,
) -> awsvpn::Result<()> {
    let mut tick = time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if session.try_wait()?.is_some() {
                    paths.cleanup();
                    return Ok(());
                }
            }
            signal = shutdown_signal() => {
                let signal = signal?;
                tracing::info!(signal, "daemon disconnecting");
                let result = session.disconnect().await;
                paths.cleanup();
                return result;
            }
            connection = server.accept() => {
                let mut connection = connection?;
                let request = connection.read_request().await?;
                match request {
                    ControlRequest::Status => {
                        let status = session_status(&session, SessionState::Connected, daemon_pid);
                        connection
                            .write_response(&ControlResponse::Ok(status))
                            .await?;
                    }
                    ControlRequest::Disconnect => {
                        let status = session_status(&session, SessionState::Disconnecting, daemon_pid);
                        let _ = awsvpn::daemon::write_state(&paths, &status);
                        let result = session.disconnect().await;
                        match &result {
                            Ok(()) => {
                                connection
                                    .write_response(&ControlResponse::Disconnected)
                                    .await?;
                            }
                            Err(err) => {
                                connection
                                    .write_response(&ControlResponse::Error(err.to_string()))
                                    .await?;
                            }
                        }
                        paths.cleanup();
                        return result;
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
async fn disconnect_daemon() -> awsvpn::Result<()> {
    match awsvpn::daemon::send_default(ControlRequest::Disconnect).await? {
        ControlResponse::Disconnected => {
            tracing::info!("disconnected");
            Ok(())
        }
        ControlResponse::Ok(status) => {
            print_status(&status);
            Ok(())
        }
        ControlResponse::Error(message) => Err(Error::DaemonControl(message)),
    }
}

#[cfg(not(unix))]
async fn disconnect_daemon() -> awsvpn::Result<()> {
    Err(Error::DaemonControl(
        "daemon mode is currently supported on macOS and Linux".to_string(),
    ))
}

#[cfg(unix)]
async fn status_daemon() -> awsvpn::Result<()> {
    match awsvpn::daemon::send_default(ControlRequest::Status).await? {
        ControlResponse::Ok(status) => {
            print_status(&status);
            Ok(())
        }
        ControlResponse::Disconnected => {
            println!("disconnected");
            Ok(())
        }
        ControlResponse::Error(message) => Err(Error::DaemonControl(message)),
    }
}

#[cfg(not(unix))]
async fn status_daemon() -> awsvpn::Result<()> {
    Err(Error::DaemonControl(
        "daemon mode is currently supported on macOS and Linux".to_string(),
    ))
}

#[cfg(unix)]
fn session_status(
    session: &awsvpn::VpnSession,
    state: SessionState,
    daemon_pid: u32,
) -> SessionStatus {
    SessionStatus {
        state,
        daemon_pid,
        openvpn_pid: session.pid(),
        vpn_ip: session.vpn_ip(),
    }
}

#[cfg(unix)]
fn print_status(status: &SessionStatus) {
    println!("state: {}", status.state.as_str());
    println!("daemon pid: {}", status.daemon_pid);
    if let Some(openvpn_pid) = status.openvpn_pid {
        println!("openvpn pid: {openvpn_pid}");
    }
    if let Some(vpn_ip) = status.vpn_ip {
        println!("vpn ip: {vpn_ip}");
    }
}

#[cfg(unix)]
fn print_daemon_startup_error(err: &Error) {
    println!("{DAEMON_ERROR_PREFIX}{err}");
    let _ = std::io::stdout().flush();
}

#[cfg(unix)]
fn print_daemon_startup_event(event: VpnEvent) {
    match event {
        VpnEvent::Log { line } => println!("{line}"),
        VpnEvent::Warning { message } => println!("warning: {message}"),
        VpnEvent::OpenVpnStarted { pid } => println!("openvpn started: pid {pid}"),
        VpnEvent::ManagementConnected => println!("management connected"),
        VpnEvent::AuthPromptReceived => println!("auth prompt received"),
        VpnEvent::SamlChallengeReceived => println!("saml challenge received"),
        VpnEvent::SamlLoginUrl { url } => println!("{url}"),
        VpnEvent::BrowserOpened => println!("browser opened"),
        VpnEvent::SamlAssertionReceived => println!("saml assertion received"),
        VpnEvent::Connected { vpn_ip } => {
            if let Some(vpn_ip) = vpn_ip {
                println!("vpn connected: {vpn_ip}");
            } else {
                println!("vpn connected");
            }
        }
        _ => {}
    }
    let _ = std::io::stdout().flush();
}

#[cfg(unix)]
fn connect_args_for_child(args: &ConnectArgs) -> Vec<String> {
    let mut values = Vec::new();

    if let Some(config) = &args.config {
        values.push(config.display().to_string());
    }
    if let Some(openvpn) = &args.openvpn {
        values.push("--openvpn".to_string());
        values.push(openvpn.display().to_string());
    }
    if args.debug {
        values.push("--debug".to_string());
    }
    if args.no_browser {
        values.push("--no-browser".to_string());
    }
    if let Some(browser) = args.browser {
        values.push("--browser".to_string());
        values.push(browser.to_string().to_ascii_lowercase().replace(' ', ""));
    }
    if args.print_login_url {
        values.push("--print-login-url".to_string());
    }
    if args.no_default_route {
        values.push("--no-default-route".to_string());
    }
    if args.no_pushed_routes {
        values.push("--no-pushed-routes".to_string());
    }
    for domain in &args.dns_domains {
        values.push("--dns-domain".to_string());
        values.push(domain.clone());
    }
    values.push("--dns".to_string());
    values.push(format_dns_mode(args.dns).to_string());

    values
}

fn default_config_path() -> PathBuf {
    default_config_home()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_CONFIG_RELATIVE_PATH)
}

fn default_dns_domains_path() -> PathBuf {
    default_config_home()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_DNS_DOMAINS_RELATIVE_PATH)
}

fn default_dns_domains() -> Vec<String> {
    let path = default_dns_domains_path();
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };

    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}

fn default_config_home() -> Option<PathBuf> {
    sudo_user_home().or_else(|| std::env::var_os("HOME").map(PathBuf::from))
}

#[cfg(unix)]
fn sudo_user_home() -> Option<PathBuf> {
    let user = std::env::var("SUDO_USER").ok()?;
    if user == "root" {
        return None;
    }

    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == user)
            .then(|| fields.nth(4).map(PathBuf::from))
            .flatten()
    })
}

#[cfg(not(unix))]
fn sudo_user_home() -> Option<PathBuf> {
    None
}

fn parse_browser(value: &str) -> Result<webbrowser::Browser, String> {
    webbrowser::Browser::from_str(&value.to_ascii_lowercase())
        .map_err(|_| "expected one of: default, chrome, firefox, safari, opera".to_string())
}

fn parse_dns_mode(value: &str) -> Result<DnsMode, String> {
    match value {
        "openvpn" => Ok(DnsMode::OpenVpnDefault),
        "disabled" => Ok(DnsMode::Disabled),
        _ => Err("expected one of: openvpn, disabled".to_string()),
    }
}

fn parse_dns_domain(value: &str) -> Result<String, String> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if validate_dns_search_domain(&normalized) {
        Ok(normalized)
    } else {
        Err("expected a DNS domain suffix such as internal.example.com".to_string())
    }
}

fn format_dns_mode(value: DnsMode) -> &'static str {
    match value {
        DnsMode::OpenVpnDefault => "openvpn",
        DnsMode::Disabled => "disabled",
    }
}

fn print_event(event: VpnEvent) {
    match event {
        VpnEvent::Log { line } => tracing::info!("{line}"),
        VpnEvent::Warning { message } => tracing::warn!("{message}"),
        VpnEvent::OpenVpnStarted { pid } => tracing::info!(pid, "openvpn started"),
        VpnEvent::ManagementConnected => tracing::info!("management connected"),
        VpnEvent::AuthPromptReceived => tracing::info!("auth prompt received"),
        VpnEvent::SamlChallengeReceived => tracing::info!("saml challenge received"),
        VpnEvent::SamlLoginUrl { url } => println!("{url}"),
        VpnEvent::BrowserOpened => tracing::info!("browser opened"),
        VpnEvent::SamlAssertionReceived => tracing::info!("saml assertion received"),
        VpnEvent::Connected { vpn_ip } => {
            if let Some(vpn_ip) = vpn_ip {
                tracing::info!(%vpn_ip, "vpn connected");
            } else {
                tracing::info!("vpn connected");
            }
        }
        _ => {}
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> awsvpn::Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt()).map_err(Error::OpenVpnProcess)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(Error::OpenVpnProcess)?;
    let mut hangup = signal(SignalKind::hangup()).map_err(Error::OpenVpnProcess)?;

    tokio::select! {
        _ = interrupt.recv() => Ok("SIGINT"),
        _ = terminate.recv() => Ok("SIGTERM"),
        _ = hangup.recv() => Ok("SIGHUP"),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> awsvpn::Result<&'static str> {
    tokio::signal::ctrl_c()
        .await
        .map_err(Error::OpenVpnProcess)?;
    Ok("Ctrl-C")
}

fn print_diagnostics(diagnostics: &Diagnostics) {
    println!("DNS servers: {}", format_dns_servers(diagnostics));
    println!("VPN DNS present: {}", yes_no(diagnostics.vpn_dns_present));
    println!("utun routes: {}", diagnostics.routes.len());
    println!(
        "VPN routes present: {}",
        yes_no(diagnostics.vpn_routes_present)
    );
    println!(
        "AWS up log present: {}",
        yes_no(diagnostics.aws_up_log_exists)
    );
    println!(
        "AWS down log present: {}",
        yes_no(diagnostics.aws_down_log_exists)
    );

    if !diagnostics.routes.is_empty() {
        println!("Sample VPN routes:");
        for route in diagnostics.routes.iter().take(8) {
            println!(
                "  {} via {} dev {}",
                route.destination, route.gateway, route.interface
            );
        }
    }
}

fn format_dns_servers(diagnostics: &Diagnostics) -> String {
    if diagnostics.dns_servers.is_empty() {
        return "none".to_string();
    }

    diagnostics
        .dns_servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
