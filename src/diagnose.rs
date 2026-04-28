use crate::{Error, Result};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;

const AWS_SCRIPT_LOG_DIR: &str = "/Library/Application Support/AWSVPNClient";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostics {
    pub dns_servers: Vec<Ipv4Addr>,
    pub vpn_dns_present: bool,
    pub routes: Vec<RouteEntry>,
    pub vpn_routes_present: bool,
    pub aws_up_log_exists: bool,
    pub aws_down_log_exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
}

pub fn collect_diagnostics() -> Result<Diagnostics> {
    let dns_output = run_command("scutil", &["--dns"])?;
    let route_output = run_command("netstat", &["-rn", "-f", "inet"])?;
    let dns_servers = parse_dns_servers(&dns_output);
    let routes = parse_routes(&route_output);

    Ok(Diagnostics {
        vpn_dns_present: dns_servers.iter().any(is_private_dns),
        dns_servers,
        vpn_routes_present: routes
            .iter()
            .any(|route| route.interface.starts_with("utun")),
        routes,
        aws_up_log_exists: Path::new(AWS_SCRIPT_LOG_DIR).join("UpLog.txt").is_file(),
        aws_down_log_exists: Path::new(AWS_SCRIPT_LOG_DIR).join("DownLog.txt").is_file(),
    })
}

fn run_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| Error::DiagnosticFailed(format!("{program}: {err}")))?;

    if !output.status.success() {
        return Err(Error::DiagnosticFailed(format!(
            "{program} exited with status {}",
            output.status
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn parse_dns_servers(output: &str) -> Vec<Ipv4Addr> {
    let mut servers = Vec::new();

    for line in output.lines() {
        let Some((_, value)) = line.split_once(':') else {
            continue;
        };
        if !line.trim_start().starts_with("nameserver[") {
            continue;
        }
        let Ok(addr) = value.trim().parse::<Ipv4Addr>() else {
            continue;
        };
        if !servers.contains(&addr) {
            servers.push(addr);
        }
    }

    servers
}

fn parse_routes(output: &str) -> Vec<RouteEntry> {
    let mut routes = Vec::new();

    for line in output.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 || fields[0] == "Destination" || fields[0] == "Internet:" {
            continue;
        }

        let Some(interface) = fields.last() else {
            continue;
        };
        if !interface.starts_with("utun") {
            continue;
        }

        routes.push(RouteEntry {
            destination: fields[0].to_string(),
            gateway: fields[1].to_string(),
            interface: (*interface).to_string(),
        });
    }

    routes
}

fn is_private_dns(addr: &Ipv4Addr) -> bool {
    addr.is_private()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unique_ipv4_dns_servers() {
        let output = r#"
resolver #1
  nameserver[0] : 172.31.0.2
  nameserver[1] : 172.31.0.2
resolver #2
  nameserver[0] : 170.250.249.249
"#;

        assert_eq!(
            parse_dns_servers(output),
            vec![
                "172.31.0.2".parse::<Ipv4Addr>().unwrap(),
                "170.250.249.249".parse::<Ipv4Addr>().unwrap()
            ]
        );
    }

    #[test]
    fn parses_utun_routes() {
        let output = r#"
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.4.1        UGScg                 en0
10.28/16           192.168.104.129    UGSc                utun6
172.31             192.168.104.129    UGSc                utun6
"#;

        assert_eq!(
            parse_routes(output),
            vec![
                RouteEntry {
                    destination: "10.28/16".to_string(),
                    gateway: "192.168.104.129".to_string(),
                    interface: "utun6".to_string(),
                },
                RouteEntry {
                    destination: "172.31".to_string(),
                    gateway: "192.168.104.129".to_string(),
                    interface: "utun6".to_string(),
                },
            ]
        );
    }
}
