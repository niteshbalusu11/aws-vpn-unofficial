use crate::{Error, Result};
use std::net::Ipv4Addr;
#[cfg(target_os = "macos")]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
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
    collect_diagnostics_impl()
}

#[cfg(target_os = "macos")]
fn collect_diagnostics_impl() -> Result<Diagnostics> {
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

#[cfg(not(target_os = "macos"))]
fn collect_diagnostics_impl() -> Result<Diagnostics> {
    Err(Error::DiagnosticFailed(
        "diagnostics are currently implemented only on macOS".to_string(),
    ))
}

#[cfg(target_os = "macos")]
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

#[cfg(any(target_os = "macos", test))]
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

#[cfg(any(target_os = "macos", test))]
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

#[cfg(target_os = "macos")]
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
  nameserver[0] : 192.0.2.53
  nameserver[1] : 192.0.2.53
resolver #2
  nameserver[0] : 198.51.100.53
"#;

        assert_eq!(
            parse_dns_servers(output),
            vec![
                "192.0.2.53".parse::<Ipv4Addr>().unwrap(),
                "198.51.100.53".parse::<Ipv4Addr>().unwrap()
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
192.0.2/24         198.51.100.1       UGSc                utun6
203.0.113/24       198.51.100.1       UGSc                utun6
"#;

        assert_eq!(
            parse_routes(output),
            vec![
                RouteEntry {
                    destination: "192.0.2/24".to_string(),
                    gateway: "198.51.100.1".to_string(),
                    interface: "utun6".to_string(),
                },
                RouteEntry {
                    destination: "203.0.113/24".to_string(),
                    gateway: "198.51.100.1".to_string(),
                    interface: "utun6".to_string(),
                },
            ]
        );
    }
}
