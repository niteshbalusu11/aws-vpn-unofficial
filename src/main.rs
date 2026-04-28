use awsvpn::{BrowserMode, ConnectOptions, Error, LogLevel, VpnClient};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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

        #[arg(long)]
        print_login_url: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli).await {
        eprintln!("error: {err}");
        if matches!(err, Error::OpenVpnProcessNotImplemented) {
            eprintln!(
                "hint: the library/CLI skeleton is in place; OpenVPN process orchestration is the next implementation milestone"
            );
        }
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> awsvpn::Result<()> {
    match cli.command {
        Command::Connect {
            config,
            openvpn,
            debug,
            no_browser,
            print_login_url,
        } => {
            let mut options = ConnectOptions::new(config)
                .with_log_level(if debug {
                    LogLevel::Debug
                } else {
                    LogLevel::Info
                })
                .with_browser_mode(if no_browser {
                    BrowserMode::Disabled
                } else {
                    BrowserMode::System
                })
                .with_print_login_url(print_login_url);

            if let Some(openvpn) = openvpn {
                options = options.with_openvpn_binary(openvpn);
            }

            let client = VpnClient::new();
            let mut session = client.connect(options).await?;
            session.wait().await?;
            Ok(())
        }
    }
}
