use crate::{Error, Result};
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct NativeDnsGuard {
    #[cfg(target_os = "macos")]
    active: bool,
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

pub fn configure_native_dns(servers: &[Ipv4Addr]) -> Result<Option<NativeDnsGuard>> {
    configure_native_dns_impl(servers)
}

#[cfg(target_os = "macos")]
fn configure_native_dns_impl(servers: &[Ipv4Addr]) -> Result<Option<NativeDnsGuard>> {
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
set Setup:/Network/Service/{MACOS_DNS_SERVICE_KEY}/DNS
"
    );

    run_scutil(&commands)?;
    Ok(Some(NativeDnsGuard { active: true }))
}

#[cfg(not(target_os = "macos"))]
fn configure_native_dns_impl(_servers: &[Ipv4Addr]) -> Result<Option<NativeDnsGuard>> {
    Ok(None)
}

fn restore_native_dns(guard: &mut NativeDnsGuard) -> Result<()> {
    restore_native_dns_impl(guard)
}

#[cfg(target_os = "macos")]
fn restore_native_dns_impl(guard: &mut NativeDnsGuard) -> Result<()> {
    if !guard.active {
        return Ok(());
    }

    let commands = format!(
        "\
remove State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/DNS
remove Setup:/Network/Service/{MACOS_DNS_SERVICE_KEY}/DNS
remove State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/SMB
remove Setup:/Network/Service/{MACOS_DNS_SERVICE_KEY}/SMB
"
    );

    run_scutil(&commands)?;
    guard.active = false;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
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
