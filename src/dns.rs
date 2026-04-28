use crate::{Error, Result};
use std::net::{IpAddr, Ipv4Addr};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

#[derive(Debug)]
pub struct NativeDnsGuard {
    #[cfg(target_os = "macos")]
    macos_active: bool,
    #[cfg(target_os = "linux")]
    linux: Option<LinuxDnsGuard>,
}

impl NativeDnsGuard {
    pub fn restore(&mut self) -> Result<()> {
        restore_native_dns(self)
    }
}

impl Drop for NativeDnsGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(target_os = "macos")]
const MACOS_DNS_SERVICE_KEY: &str = "com.amazonaws.acvc";

pub fn configure_native_dns(
    servers: &[Ipv4Addr],
    vpn_ip: Option<IpAddr>,
) -> Result<Option<NativeDnsGuard>> {
    configure_native_dns_impl(servers, vpn_ip)
}

#[cfg(target_os = "macos")]
fn configure_native_dns_impl(
    servers: &[Ipv4Addr],
    _vpn_ip: Option<IpAddr>,
) -> Result<Option<NativeDnsGuard>> {
    if servers.is_empty() {
        return Ok(None);
    }

    let server_values = servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let commands = format!(
        "\
d.init
d.add ServerAddresses * {server_values}
d.add SearchDomains * openvpn
d.add DomainName openvpn
set State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/DNS
"
    );

    run_scutil(&commands)?;
    Ok(Some(NativeDnsGuard { macos_active: true }))
}

#[cfg(target_os = "linux")]
fn configure_native_dns_impl(
    servers: &[Ipv4Addr],
    vpn_ip: Option<IpAddr>,
) -> Result<Option<NativeDnsGuard>> {
    if servers.is_empty() {
        return Ok(None);
    }

    let Some(IpAddr::V4(vpn_ip)) = vpn_ip else {
        return Err(Error::DnsConfigurationFailed(
            "OpenVPN did not report an IPv4 tunnel address, so Linux DNS could not identify the tunnel interface".to_string(),
        ));
    };
    let interface = linux_interface_for_ipv4(vpn_ip)?;
    let linux = configure_linux_dns(&interface, servers)?;

    Ok(Some(NativeDnsGuard { linux: Some(linux) }))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn configure_native_dns_impl(
    servers: &[Ipv4Addr],
    _vpn_ip: Option<IpAddr>,
) -> Result<Option<NativeDnsGuard>> {
    if servers.is_empty() {
        return Ok(None);
    }

    Err(Error::DnsConfigurationFailed(
        "native DNS configuration is not implemented for this platform; use trusted OpenVPN helper scripts or --dns disabled".to_string(),
    ))
}

fn restore_native_dns(guard: &mut NativeDnsGuard) -> Result<()> {
    restore_native_dns_impl(guard)
}

#[cfg(target_os = "macos")]
fn restore_native_dns_impl(guard: &mut NativeDnsGuard) -> Result<()> {
    if !guard.macos_active {
        return Ok(());
    }

    let commands = format!(
        "\
remove State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/DNS
remove State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/SMB
"
    );

    run_scutil(&commands)?;
    guard.macos_active = false;
    Ok(())
}

#[cfg(target_os = "linux")]
fn restore_native_dns_impl(guard: &mut NativeDnsGuard) -> Result<()> {
    let Some(linux) = guard.linux.take() else {
        return Ok(());
    };
    restore_linux_dns(linux)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn restore_native_dns_impl(_guard: &mut NativeDnsGuard) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_scutil(commands: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| Error::DnsConfigurationFailed(err.to_string()))?;

    child
        .stdin
        .as_mut()
        .expect("scutil stdin is piped")
        .write_all(commands.as_bytes())
        .map_err(|err| Error::DnsConfigurationFailed(err.to_string()))?;

    let output = child
        .wait_with_output()
        .map_err(|err| Error::DnsConfigurationFailed(err.to_string()))?;

    if !output.status.success() {
        return Err(Error::DnsConfigurationFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxDnsGuard {
    method: LinuxDnsMethod,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum LinuxDnsMethod {
    SystemdResolved { interface: String },
    Resolvconf { key: String },
}

#[cfg(target_os = "linux")]
fn linux_interface_for_ipv4(addr: Ipv4Addr) -> Result<String> {
    let output = run_command_capture("ip", &["-o", "-4", "addr", "show"])?;
    parse_linux_interface_for_ipv4(&output, addr).ok_or_else(|| {
        Error::DnsConfigurationFailed(format!(
            "could not find a Linux tunnel interface assigned {addr}"
        ))
    })
}

#[cfg(target_os = "linux")]
fn configure_linux_dns(interface: &str, servers: &[Ipv4Addr]) -> Result<LinuxDnsGuard> {
    let mut errors = Vec::new();

    match configure_systemd_resolved(interface, servers) {
        Ok(guard) => return Ok(guard),
        Err(err) => errors.push(err),
    }

    match configure_resolvconf(interface, servers) {
        Ok(guard) => return Ok(guard),
        Err(err) => errors.push(err),
    }

    Err(Error::DnsConfigurationFailed(format!(
        "could not configure Linux DNS with systemd-resolved or resolvconf: {}",
        errors.join("; ")
    )))
}

#[cfg(target_os = "linux")]
fn configure_systemd_resolved(
    interface: &str,
    servers: &[Ipv4Addr],
) -> std::result::Result<LinuxDnsGuard, String> {
    let server_args = servers.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut dns_args = vec!["dns".to_string(), interface.to_string()];
    dns_args.extend(server_args);
    run_command_status("resolvectl", &dns_args)?;
    if let Err(err) = run_command_status(
        "resolvectl",
        &[
            "domain".to_string(),
            interface.to_string(),
            "~.".to_string(),
        ],
    ) {
        let _ = run_command_status("resolvectl", &["revert".to_string(), interface.to_string()]);
        return Err(err);
    }

    Ok(LinuxDnsGuard {
        method: LinuxDnsMethod::SystemdResolved {
            interface: interface.to_string(),
        },
    })
}

#[cfg(target_os = "linux")]
fn configure_resolvconf(
    interface: &str,
    servers: &[Ipv4Addr],
) -> std::result::Result<LinuxDnsGuard, String> {
    let key = format!("{interface}.awsvpn");
    let config = render_resolvconf_config(servers);
    run_command_with_stdin("resolvconf", &["-a", key.as_str()], &config)?;

    Ok(LinuxDnsGuard {
        method: LinuxDnsMethod::Resolvconf { key },
    })
}

#[cfg(target_os = "linux")]
fn restore_linux_dns(guard: LinuxDnsGuard) -> Result<()> {
    match guard.method {
        LinuxDnsMethod::SystemdResolved { interface } => {
            match run_command_status("resolvectl", &["revert".to_string(), interface.clone()]) {
                Ok(()) => Ok(()),
                Err(err) if is_resolvectl_missing_interface_error(&err) => {
                    tracing::debug!(
                        interface,
                        "systemd-resolved link state was already gone during DNS restore"
                    );
                    Ok(())
                }
                Err(err) => Err(Error::DnsConfigurationFailed(err)),
            }
        }
        LinuxDnsMethod::Resolvconf { key } => {
            run_command_status("resolvconf", &["-d".to_string(), key])
                .map_err(Error::DnsConfigurationFailed)
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn is_resolvectl_missing_interface_error(message: &str) -> bool {
    message.contains("Failed to resolve interface") && message.contains("No such device")
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_interface_for_ipv4(output: &str, addr: Ipv4Addr) -> Option<String> {
    let expected = addr.to_string();

    for line in output.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 || fields.get(2) != Some(&"inet") {
            continue;
        }

        let Some(raw_addr) = fields.get(3).and_then(|value| value.split('/').next()) else {
            continue;
        };
        if raw_addr == expected {
            let interface = fields.get(1)?.trim_end_matches(':');
            return Some(interface.to_string());
        }
    }

    None
}

#[cfg(any(target_os = "linux", test))]
fn render_resolvconf_config(servers: &[Ipv4Addr]) -> String {
    let mut config = String::from("search openvpn\n");
    for server in servers {
        config.push_str("nameserver ");
        config.push_str(&server.to_string());
        config.push('\n');
    }
    config
}

#[cfg(target_os = "linux")]
fn run_command_capture(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| Error::DnsConfigurationFailed(format!("{program}: {err}")))?;

    if !output.status.success() {
        return Err(Error::DnsConfigurationFailed(format!(
            "{program} exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn run_command_status(program: &str, args: &[String]) -> std::result::Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("{program}: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "{program} exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn run_command_with_stdin(
    program: &str,
    args: &[&str],
    stdin: &str,
) -> std::result::Result<(), String> {
    use std::io::Write;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("{program}: {err}"))?;

    {
        let mut child_stdin = child.stdin.take().expect("stdin is piped");
        child_stdin
            .write_all(stdin.as_bytes())
            .map_err(|err| format!("{program}: {err}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("{program}: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "{program} exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_interface_for_assigned_ipv4() {
        let output = r#"
1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
7: tun0    inet 192.0.2.42/27 scope global tun0\       valid_lft forever preferred_lft forever
"#;

        assert_eq!(
            parse_linux_interface_for_ipv4(output, "192.0.2.42".parse().unwrap()),
            Some("tun0".to_string())
        );
    }

    #[test]
    fn ignores_non_matching_linux_ipv4_addresses() {
        let output = "7: tun0    inet 192.0.2.42/27 scope global tun0";

        assert_eq!(
            parse_linux_interface_for_ipv4(output, "198.51.100.10".parse().unwrap()),
            None
        );
    }

    #[test]
    fn renders_resolvconf_config() {
        let config = render_resolvconf_config(&[
            "192.0.2.53".parse().unwrap(),
            "198.51.100.53".parse().unwrap(),
        ]);

        assert_eq!(
            config,
            "search openvpn\nnameserver 192.0.2.53\nnameserver 198.51.100.53\n"
        );
    }

    #[test]
    fn treats_missing_systemd_resolved_interface_as_already_restored() {
        let error = r#"resolvectl exited with status exit status: 1: Failed to resolve interface "tun0": No such device"#;

        assert!(is_resolvectl_missing_interface_error(error));
    }
}
