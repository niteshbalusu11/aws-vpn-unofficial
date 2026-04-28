use awsvpn::{BrowserMode, ConnectOptions, DnsMode, Error, LogLevel, VpnClient, VpnEvent};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;
use tracing::Level;

#[derive(Debug, Parser)]
#[command(name = "awsvpn", version, about = "Unofficial AWS Client VPN CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Connect {
        config: PathBuf,

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
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(&cli);

    if let Err(err) = run(cli).await {
        tracing::error!("{err}");
        if matches!(err, Error::OpenVpnNotFound) {
            tracing::warn!("hint: pass the AWS-patched OpenVPN binary with --openvpn <path>");
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
                signal = tokio::signal::ctrl_c() => {
                    signal.map_err(Error::OpenVpnProcess)?;
                    tracing::info!("disconnecting");
                    session.disconnect().await?;
                }
            }

            log_task.abort();
            Ok(())
        }
    }
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
