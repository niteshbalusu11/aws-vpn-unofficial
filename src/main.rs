use awsvpn::{
    BrowserMode, ConnectOptions, Diagnostics, DnsMode, Error, LogLevel, VpnClient, VpnEvent,
    collect_diagnostics,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;
use tracing::Level;

const DEFAULT_CONFIG_RELATIVE_PATH: &str = ".awsvpnunofficial/vpnconfig.ovpn";

#[derive(Debug, Parser)]
#[command(name = "awsvpn", version, about = "Unofficial AWS Client VPN CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Connect {
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
    },
    Diagnose,
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
            Command::Connect { debug, .. } => *debug,
            Command::Diagnose => false,
        }
    }
}

async fn run(cli: Cli) -> awsvpn::Result<()> {
    match cli.command {
        Command::Connect {
            config,
            openvpn,
            debug,
            no_browser,
            browser,
            print_login_url,
            dns,
        } => {
            let config = config.unwrap_or_else(default_config_path);
            let browser_mode = if no_browser {
                BrowserMode::Disabled
            } else if let Some(browser) = browser {
                BrowserMode::Specific(browser)
            } else {
                BrowserMode::System
            };

            let mut options = ConnectOptions::new(config)
                .with_log_level(if debug {
                    LogLevel::Debug
                } else {
                    LogLevel::Info
                })
                .with_browser_mode(browser_mode)
                .with_print_login_url(print_login_url)
                .with_dns_mode(dns);

            if let Some(openvpn) = openvpn {
                options = options.with_openvpn_binary(openvpn);
            }

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
        Command::Diagnose => {
            let diagnostics = collect_diagnostics()?;
            print_diagnostics(&diagnostics);
            Ok(())
        }
    }
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
