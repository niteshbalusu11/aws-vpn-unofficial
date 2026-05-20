#[cfg(unix)]
use awsvpn::daemon::{
    ControlRequest, ControlResponse, ControlServer, DaemonPaths, SessionState, SessionStatus,
};
use awsvpn::{
    BrowserMode, ConnectOptions, Diagnostics, DnsMode, Error, LogLevel, VpnClient, VpnEvent,
    collect_diagnostics,
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
#[cfg(unix)]
const DAEMON_READY_LINE: &str = "__AWSVPN_DAEMON_READY__";
#[cfg(unix)]
const DAEMON_ERROR_PREFIX: &str = "__AWSVPN_DAEMON_ERROR__\t";
#[cfg(unix)]
const AUTO_RECONNECT_INITIAL_DELAY: Duration = Duration::from_secs(2);
#[cfg(unix)]
const AUTO_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(60);

#[derive(Debug, Parser)]
#[command(name = "awsvpn", version, about = "Unofficial AWS Client VPN CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(visible_alias = "c")]
    Connect {
        #[command(flatten)]
        args: ConnectArgs,

        #[arg(long, help = "Keep the VPN session attached to this terminal")]
        foreground: bool,
    },
    #[command(visible_alias = "d")]
    Disconnect,
    #[command(visible_alias = "r")]
    Reconnect {
        #[command(flatten)]
        args: ConnectArgs,

        #[arg(long, help = "Keep the VPN session attached to this terminal")]
        foreground: bool,
    },
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

    #[arg(long, help = "Override the bundled AWS-patched OpenVPN binary")]
    openvpn: Option<PathBuf>,

    #[arg(long, help = "Print verbose, redacted startup logs")]
    debug: bool,

    #[arg(long, help = "Do not open the SAML login URL in a browser")]
    no_browser: bool,

    #[arg(long, value_parser = parse_browser, help = "Open the SAML login URL in a specific browser")]
    browser: Option<webbrowser::Browser>,

    #[arg(long, help = "Print the SAML login URL to stdout")]
    print_login_url: bool,

    #[arg(
        long,
        default_value = "openvpn",
        value_parser = parse_dns_mode,
        help = "DNS mode: openvpn or disabled"
    )]
    dns: DnsMode,
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
            Command::Connect { args, .. }
            | Command::Reconnect { args, .. }
            | Command::DaemonRun { args } => args.debug,
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
        Command::Reconnect { args, foreground } => reconnect(args, foreground).await,
        Command::Status => status_daemon().await,
        Command::DaemonRun { args } => run_daemon_runner(args).await,
        Command::Diagnose => {
            let diagnostics = collect_diagnostics()?;
            print_diagnostics(&diagnostics);
            Ok(())
        }
    }
}

async fn reconnect(args: ConnectArgs, foreground: bool) -> awsvpn::Result<()> {
    match disconnect_daemon().await {
        Ok(()) => wait_for_daemon_shutdown().await?,
        Err(Error::DaemonUnavailable) => {
            tracing::info!("daemon is not running; connecting");
        }
        Err(err) => return Err(err),
    }

    if foreground {
        run_foreground_connect(args).await
    } else {
        run_daemon_connect(args).await
    }
}

#[cfg(unix)]
async fn wait_for_daemon_shutdown() -> awsvpn::Result<()> {
    let paths = DaemonPaths::default_for_current_user()?;
    let deadline = time::Instant::now() + Duration::from_secs(2);

    while paths.socket.exists() {
        if time::Instant::now() >= deadline {
            return Err(Error::DaemonControl(
                "timed out waiting for daemon control socket cleanup".to_string(),
            ));
        }
        time::sleep(Duration::from_millis(50)).await;
    }

    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_daemon_shutdown() -> awsvpn::Result<()> {
    Ok(())
}

fn connect_options(args: &ConnectArgs) -> ConnectOptions {
    let config = args.config.clone().unwrap_or_else(default_config_path);
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
        .with_dns_mode(args.dns);

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
    let session = match client.connect(options.clone()).await {
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

    run_daemon_control_loop(server, paths, session, options, daemon_pid).await
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
    session: awsvpn::VpnSession,
    options: ConnectOptions,
    daemon_pid: u32,
) -> awsvpn::Result<()> {
    let mut tick = time::interval(Duration::from_secs(1));
    let mut session = Some(session);
    let mut reconnect = None::<ReconnectAttempt>;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Some(active_session) = &mut session
                    && active_session.try_wait()?.is_some()
                {
                    tracing::warn!("OpenVPN exited unexpectedly; scheduling reconnect");
                    session = None;
                    reconnect = Some(start_reconnect_attempt(options.clone(), 1));
                    let _ = awsvpn::daemon::write_state(
                        &paths,
                        &connecting_status(daemon_pid),
                    );
                }

                if let Some(attempt) = reconnect.take() {
                    if attempt.task.is_finished() {
                        match attempt.task.await {
                            Ok(Ok(new_session)) => {
                                tracing::info!("daemon reconnected VPN session");
                                let status = session_status(&new_session, SessionState::Connected, daemon_pid);
                                awsvpn::daemon::write_state(&paths, &status)?;
                                session = Some(new_session);
                            }
                            Ok(Err(err)) => {
                                let next_attempt = attempt.attempt.saturating_add(1);
                                tracing::warn!(attempt = attempt.attempt, error = %err, "daemon reconnect attempt failed");
                                reconnect = Some(start_reconnect_attempt(options.clone(), next_attempt));
                                let _ = awsvpn::daemon::write_state(
                                    &paths,
                                    &connecting_status(daemon_pid),
                                );
                            }
                            Err(err) => {
                                let next_attempt = attempt.attempt.saturating_add(1);
                                tracing::warn!(attempt = attempt.attempt, error = %err, "daemon reconnect task failed");
                                reconnect = Some(start_reconnect_attempt(options.clone(), next_attempt));
                                let _ = awsvpn::daemon::write_state(
                                    &paths,
                                    &connecting_status(daemon_pid),
                                );
                            }
                        }
                    } else {
                        reconnect = Some(attempt);
                    }
                }
            }
            signal = shutdown_signal() => {
                let signal = signal?;
                tracing::info!(signal, "daemon disconnecting");
                let result = if let Some(mut active_session) = session.take() {
                    active_session.disconnect().await
                } else {
                    if let Some(attempt) = reconnect.take() {
                        attempt.task.abort();
                    }
                    Ok(())
                };
                paths.cleanup();
                return result;
            }
            connection = server.accept() => {
                let mut connection = connection?;
                let request = connection.read_request().await?;
                match request {
                    ControlRequest::Status => {
                        let status = if let Some(active_session) = &session {
                            session_status(active_session, SessionState::Connected, daemon_pid)
                        } else {
                            connecting_status(daemon_pid)
                        };
                        connection
                            .write_response(&ControlResponse::Ok(status))
                            .await?;
                    }
                    ControlRequest::Disconnect => {
                        let status = if let Some(active_session) = &session {
                            session_status(active_session, SessionState::Disconnecting, daemon_pid)
                        } else {
                            SessionStatus {
                                state: SessionState::Disconnecting,
                                daemon_pid,
                                openvpn_pid: None,
                                vpn_ip: None,
                            }
                        };
                        let _ = awsvpn::daemon::write_state(&paths, &status);
                        let result = if let Some(mut active_session) = session.take() {
                            active_session.disconnect().await
                        } else {
                            if let Some(attempt) = reconnect.take() {
                                attempt.task.abort();
                            }
                            Ok(())
                        };
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
struct ReconnectAttempt {
    attempt: u32,
    task: tokio::task::JoinHandle<awsvpn::Result<awsvpn::VpnSession>>,
}

#[cfg(unix)]
fn start_reconnect_attempt(options: ConnectOptions, attempt: u32) -> ReconnectAttempt {
    let delay = reconnect_delay(attempt);
    let task = tokio::spawn(async move {
        tracing::info!(
            attempt,
            delay_secs = delay.as_secs(),
            "waiting before reconnect"
        );
        time::sleep(delay).await;
        VpnClient::new().connect(options).await
    });

    ReconnectAttempt { attempt, task }
}

#[cfg(unix)]
fn reconnect_delay(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(5);
    let delay = AUTO_RECONNECT_INITIAL_DELAY.saturating_mul(1 << exponent);
    delay.min(AUTO_RECONNECT_MAX_DELAY)
}

#[cfg(unix)]
fn connecting_status(daemon_pid: u32) -> SessionStatus {
    SessionStatus {
        state: SessionState::Connecting,
        daemon_pid,
        openvpn_pid: None,
        vpn_ip: None,
    }
}

#[cfg(unix)]
async fn disconnect_daemon() -> awsvpn::Result<()> {
    match awsvpn::daemon::send_default(ControlRequest::Disconnect).await {
        Err(Error::DaemonUnavailable) => {
            awsvpn::cleanup_stale_native_dns()?;
            tracing::info!("disconnected");
            Ok(())
        }
        Err(err) => Err(err),
        Ok(response) => handle_disconnect_response(response),
    }
}

#[cfg(unix)]
fn handle_disconnect_response(response: ControlResponse) -> awsvpn::Result<()> {
    match response {
        ControlResponse::Disconnected => {
            awsvpn::cleanup_stale_native_dns()?;
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
    values.push("--dns".to_string());
    values.push(format_dns_mode(args.dns).to_string());

    values
}

fn default_config_path() -> PathBuf {
    default_config_home()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_CONFIG_RELATIVE_PATH)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn reconnect_delay_backs_off_and_caps() {
        assert_eq!(reconnect_delay(1), Duration::from_secs(2));
        assert_eq!(reconnect_delay(2), Duration::from_secs(4));
        assert_eq!(reconnect_delay(3), Duration::from_secs(8));
        assert_eq!(reconnect_delay(10), Duration::from_secs(60));
    }
}
