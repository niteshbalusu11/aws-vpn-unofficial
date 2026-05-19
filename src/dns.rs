use crate::{Error, Result};
use std::net::{IpAddr, Ipv4Addr};
#[cfg(target_os = "macos")]
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "macos")]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[cfg(target_os = "macos")]
use std::thread::{self, JoinHandle};
#[cfg(target_os = "macos")]
use std::time::Duration;

#[derive(Debug)]
pub struct NativeDnsGuard {
    #[cfg(target_os = "macos")]
    macos: Option<MacosDnsGuard>,
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
#[cfg(target_os = "macos")]
const MACOS_STATE_ROOT: &str = "State:/Network/awsvpn";
#[cfg(target_os = "macos")]
const MACOS_LOCAL_DNS: &str = "127.0.0.1";

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

    restore_macos_system_dns()?;

    let proxy = DnsProxyGuard::start(servers)?;
    let primary_service = macos_primary_service_id()?;
    let had_dns =
        macos_scutil_key_exists(&format!("State:/Network/Service/{primary_service}/DNS"))?;

    if let Err(err) = run_scutil(&render_macos_dns_setup(&primary_service, had_dns)) {
        drop(proxy);
        return Err(err);
    }
    flush_macos_dns_cache();

    let monitor = MacosDnsMonitor::start(primary_service.clone());

    Ok(Some(NativeDnsGuard {
        macos: Some(MacosDnsGuard { proxy, monitor }),
    }))
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
    let Some(macos) = guard.macos.take() else {
        return Ok(());
    };

    macos.restore()
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
#[derive(Debug)]
struct MacosDnsGuard {
    proxy: DnsProxyGuard,
    monitor: MacosDnsMonitor,
}

#[cfg(target_os = "macos")]
impl MacosDnsGuard {
    fn restore(mut self) -> Result<()> {
        restore_macos_dns_guard_order(
            || self.monitor.stop(),
            restore_macos_system_dns,
            || self.proxy.stop(),
        )
    }
}

#[cfg(any(target_os = "macos", test))]
fn restore_macos_dns_guard_order(
    mut stop_monitor: impl FnMut(),
    mut restore_dns: impl FnMut() -> Result<()>,
    mut stop_proxy: impl FnMut(),
) -> Result<()> {
    stop_monitor();
    let restore_result = restore_dns();
    stop_proxy();
    restore_result
}

#[cfg(target_os = "macos")]
impl Drop for MacosDnsGuard {
    fn drop(&mut self) {
        self.monitor.stop();
        self.proxy.stop();
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MacosDnsMonitor {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[cfg(target_os = "macos")]
impl MacosDnsMonitor {
    fn start(primary_service: String) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let monitor_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            monitor_macos_dns(primary_service, monitor_shutdown);
        });

        Self {
            shutdown,
            handle: Some(handle),
        }
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosDnsMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct DnsProxyGuard {
    shutdown: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

#[cfg(target_os = "macos")]
impl DnsProxyGuard {
    fn start(servers: &[Ipv4Addr]) -> Result<Self> {
        let upstreams = Arc::new(
            servers
                .iter()
                .map(|server| SocketAddr::from((*server, 53)))
                .collect::<Vec<_>>(),
        );
        let shutdown = Arc::new(AtomicBool::new(false));

        let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 53)).map_err(|err| {
            Error::DnsConfigurationFailed(format!(
                "could not bind local DNS UDP proxy on {MACOS_LOCAL_DNS}:53: {err}"
            ))
        })?;
        udp_socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(|err| Error::DnsConfigurationFailed(format!("local DNS UDP proxy: {err}")))?;

        let tcp_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 53)).map_err(|err| {
            Error::DnsConfigurationFailed(format!(
                "could not bind local DNS TCP proxy on {MACOS_LOCAL_DNS}:53: {err}"
            ))
        })?;
        tcp_listener
            .set_nonblocking(true)
            .map_err(|err| Error::DnsConfigurationFailed(format!("local DNS TCP proxy: {err}")))?;

        let udp_shutdown = shutdown.clone();
        let udp_upstreams = upstreams.clone();
        let udp_handle =
            thread::spawn(move || udp_proxy_loop(udp_socket, udp_upstreams, udp_shutdown));

        let tcp_shutdown = shutdown.clone();
        let tcp_handle =
            thread::spawn(move || tcp_proxy_loop(tcp_listener, upstreams, tcp_shutdown));

        Ok(Self {
            shutdown,
            handles: vec![udp_handle, tcp_handle],
        })
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| socket.send_to(&[], (Ipv4Addr::LOCALHOST, 53)));
        let _ = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, 53)),
            Duration::from_millis(100),
        );

        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for DnsProxyGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(target_os = "macos")]
fn udp_proxy_loop(socket: UdpSocket, upstreams: Arc<Vec<SocketAddr>>, shutdown: Arc<AtomicBool>) {
    let mut buffer = [0_u8; 4096];
    while !shutdown.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buffer) {
            Ok((0, _)) => {}
            Ok((len, client)) => {
                if let Some(response) = forward_dns_udp(&buffer[..len], &upstreams) {
                    let _ = socket.send_to(&response, client);
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
}

#[cfg(target_os = "macos")]
fn tcp_proxy_loop(
    listener: TcpListener,
    upstreams: Arc<Vec<SocketAddr>>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let upstreams = upstreams.clone();
                thread::spawn(move || {
                    let _ = handle_dns_tcp_client(stream, &upstreams);
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
}

#[cfg(target_os = "macos")]
fn forward_dns_udp(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    for upstream in upstreams {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .ok()?;
        if socket.send_to(query, upstream).is_err() {
            continue;
        }

        let mut response = [0_u8; 4096];
        if let Ok((len, _)) = socket.recv_from(&mut response) {
            return Some(response[..len].to_vec());
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn handle_dns_tcp_client(mut client: TcpStream, upstreams: &[SocketAddr]) -> std::io::Result<()> {
    use std::io::{Read, Write};

    client.set_read_timeout(Some(Duration::from_secs(2)))?;
    client.set_write_timeout(Some(Duration::from_secs(2)))?;

    let mut length = [0_u8; 2];
    client.read_exact(&mut length)?;
    let query_len = u16::from_be_bytes(length) as usize;
    if query_len == 0 {
        return Ok(());
    }

    let mut query = vec![0_u8; query_len];
    client.read_exact(&mut query)?;

    if let Some(response) = forward_dns_tcp(&query, upstreams) {
        client.write_all(&(response.len() as u16).to_be_bytes())?;
        client.write_all(&response)?;
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn forward_dns_tcp(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    use std::io::{Read, Write};

    for upstream in upstreams {
        let Ok(mut stream) = TcpStream::connect_timeout(upstream, Duration::from_secs(2)) else {
            continue;
        };
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .ok()?;
        if stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .and_then(|_| stream.write_all(query))
            .is_err()
        {
            continue;
        }

        let mut length = [0_u8; 2];
        if stream.read_exact(&mut length).is_err() {
            continue;
        }
        let response_len = u16::from_be_bytes(length) as usize;
        if response_len == 0 {
            continue;
        }
        let mut response = vec![0_u8; response_len];
        if stream.read_exact(&mut response).is_ok() {
            return Some(response);
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn monitor_macos_dns(primary_service: String, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::Relaxed) {
        if !wait_for_macos_dns_check_interval(&shutdown) {
            break;
        }

        match macos_dns_uses_local_proxy(&primary_service) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    primary_service,
                    "macOS DNS settings drifted from VPN resolver; restoring"
                );
                if let Err(err) = repair_macos_dns(&primary_service) {
                    tracing::warn!(error = %err, "could not restore macOS VPN DNS settings");
                }
            }
            Err(err) => {
                tracing::debug!(error = %err, "could not inspect macOS VPN DNS settings");
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn wait_for_macos_dns_check_interval(shutdown: &AtomicBool) -> bool {
    for _ in 0..50 {
        if shutdown.load(Ordering::Relaxed) {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }

    !shutdown.load(Ordering::Relaxed)
}

#[cfg(target_os = "macos")]
fn macos_primary_service_id() -> Result<String> {
    let output = run_scutil_capture("show State:/Network/Global/IPv4\n")?;
    for line in output.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() == 3 && fields[0] == "PrimaryService" && fields[1] == ":" {
            let value = fields[2].to_string();
            if value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Ok(value);
            }
        }
    }

    Err(Error::DnsConfigurationFailed(
        "could not determine macOS primary network service".to_string(),
    ))
}

#[cfg(target_os = "macos")]
fn macos_scutil_key_exists(key: &str) -> Result<bool> {
    let output = run_scutil_capture(&format!("show {key}\n"))?;
    Ok(!output.contains("No such key"))
}

#[cfg(target_os = "macos")]
fn macos_dns_uses_local_proxy(primary_service: &str) -> Result<bool> {
    let primary_dns_key = format!("State:/Network/Service/{primary_service}/DNS");
    let output = run_scutil_capture(&format!("show {primary_dns_key}\n"))?;
    if output.contains("No such key") {
        return Ok(false);
    }

    Ok(scutil_array_contains(
        &output,
        "ServerAddresses",
        MACOS_LOCAL_DNS,
    ))
}

#[cfg(target_os = "macos")]
fn render_macos_dns_setup(primary_service: &str, had_dns: bool) -> String {
    let primary_dns_key = format!("State:/Network/Service/{primary_service}/DNS");
    let mut commands = format!(
        "\
remove State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/DNS
remove State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/SMB
remove {MACOS_STATE_ROOT}/OldDNSState
remove {MACOS_STATE_ROOT}
"
    );

    if had_dns {
        commands.push_str(&format!(
            "\
get {primary_dns_key}
set {MACOS_STATE_ROOT}/OldDNSState
"
        ));
    }

    commands.push_str(&format!(
        "\
d.init
d.add ServerAddresses * {MACOS_LOCAL_DNS}
set {primary_dns_key}
d.init
d.add PrimaryService {primary_service}
d.add HadDNS {}
set {MACOS_STATE_ROOT}
",
        if had_dns { 1 } else { 0 }
    ));

    commands
}

#[cfg(target_os = "macos")]
fn render_macos_dns_repair(primary_service: &str) -> String {
    let primary_dns_key = format!("State:/Network/Service/{primary_service}/DNS");
    format!(
        "\
d.init
d.add ServerAddresses * {MACOS_LOCAL_DNS}
set {primary_dns_key}
"
    )
}

#[cfg(target_os = "macos")]
fn repair_macos_dns(primary_service: &str) -> Result<()> {
    run_scutil(&render_macos_dns_repair(primary_service))?;
    flush_macos_dns_cache();
    Ok(())
}

#[cfg(target_os = "macos")]
fn restore_macos_system_dns() -> Result<()> {
    let state_key_exists = macos_scutil_key_exists(MACOS_STATE_ROOT)?;
    if !state_key_exists {
        let commands = format!(
            "\
remove State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/DNS
remove State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/SMB
"
        );
        run_scutil(&commands)?;
        flush_macos_dns_cache();
        return Ok(());
    }

    let state = run_scutil_capture(&format!("show {MACOS_STATE_ROOT}\n"))?;
    let primary_service = scutil_state_value(&state, "PrimaryService");
    let had_dns = scutil_state_value(&state, "HadDNS").as_deref() == Some("1");

    let Some(primary_service) = primary_service else {
        let commands = render_macos_dns_cleanup(None, false);
        run_scutil(&commands)?;
        flush_macos_dns_cache();
        return Ok(());
    };

    let commands = render_macos_dns_cleanup(Some(&primary_service), had_dns);
    run_scutil(&commands)?;
    flush_macos_dns_cache();
    Ok(())
}

#[cfg(target_os = "macos")]
fn render_macos_dns_cleanup(primary_service: Option<&str>, had_dns: bool) -> String {
    let mut commands = String::new();
    if let Some(primary_service) = primary_service {
        let primary_dns_key = format!("State:/Network/Service/{primary_service}/DNS");
        if had_dns {
            commands.push_str(&format!(
                "\
get {MACOS_STATE_ROOT}/OldDNSState
set {primary_dns_key}
"
            ));
        } else {
            commands.push_str(&format!("remove {primary_dns_key}\n"));
        }
    }

    commands.push_str(&format!(
        "\
remove State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/DNS
remove State:/Network/Service/{MACOS_DNS_SERVICE_KEY}/SMB
remove {MACOS_STATE_ROOT}/OldDNSState
remove {MACOS_STATE_ROOT}
"
    ));
    commands
}

#[cfg(target_os = "macos")]
fn scutil_state_value(output: &str, key: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        (fields.len() == 3 && fields[0] == key && fields[1] == ":").then(|| fields[2].to_string())
    })
}

#[cfg(any(target_os = "macos", test))]
fn scutil_array_contains(output: &str, array_key: &str, expected: &str) -> bool {
    let mut in_array = false;

    for line in output.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() >= 4 && fields[0] == array_key && fields[1] == ":" && fields[2] == "<array>"
        {
            in_array = true;
            continue;
        }

        if in_array {
            if fields.len() >= 2 && fields[0] == "}" {
                return false;
            }

            if fields.len() == 3 && fields[1] == ":" && fields[2] == expected {
                return true;
            }
        }
    }

    false
}

#[cfg(target_os = "macos")]
fn flush_macos_dns_cache() {
    let _ = std::process::Command::new("dscacheutil")
        .arg("-flushcache")
        .output();
    let _ = std::process::Command::new("killall")
        .args(["-HUP", "mDNSResponder"])
        .output();
    let _ = std::process::Command::new("killall")
        .args(["-HUP", "mDNSResponderHelper"])
        .output();
}

#[cfg(target_os = "macos")]
fn run_scutil_capture(commands: &str) -> Result<String> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = std::process::Command::new("scutil")
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

    let mut contents = String::from_utf8_lossy(&output.stdout).into_owned();
    contents.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(contents)
}

#[cfg(target_os = "macos")]
fn run_scutil(commands: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = std::process::Command::new("scutil")
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

    #[cfg(target_os = "macos")]
    #[test]
    fn detects_local_proxy_in_scutil_dns_array() {
        let output = r#"
<dictionary> {
  SearchDomains : <array> {
    0 : openvpn
  }
  ServerAddresses : <array> {
    0 : 127.0.0.1
  }
}
"#;

        assert!(scutil_array_contains(
            output,
            "ServerAddresses",
            "127.0.0.1"
        ));
        assert!(!scutil_array_contains(
            output,
            "ServerAddresses",
            "172.31.0.2"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn renders_macos_dns_repair_without_overwriting_saved_state() {
        let commands = render_macos_dns_repair("C51D613A-60BE-42A3-888D-D15432602660");

        assert!(commands.contains("d.add ServerAddresses * 127.0.0.1"));
        assert!(
            commands
                .contains("set State:/Network/Service/C51D613A-60BE-42A3-888D-D15432602660/DNS")
        );
        assert!(!commands.contains("OldDNSState"));
        assert!(!commands.contains("remove State:/Network/awsvpn"));
    }

    #[test]
    fn stops_macos_dns_monitor_before_restore_and_proxy_after() {
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let monitor_events = std::rc::Rc::clone(&events);
        let restore_events = std::rc::Rc::clone(&events);
        let proxy_events = std::rc::Rc::clone(&events);

        restore_macos_dns_guard_order(
            || monitor_events.borrow_mut().push("monitor"),
            || {
                restore_events.borrow_mut().push("restore");
                Ok(())
            },
            || proxy_events.borrow_mut().push("proxy"),
        )
        .unwrap();

        assert_eq!(*events.borrow(), ["monitor", "restore", "proxy"]);
    }

    #[test]
    fn stops_macos_dns_proxy_after_restore_failure() {
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let monitor_events = std::rc::Rc::clone(&events);
        let restore_events = std::rc::Rc::clone(&events);
        let proxy_events = std::rc::Rc::clone(&events);

        let result = restore_macos_dns_guard_order(
            || monitor_events.borrow_mut().push("monitor"),
            || {
                restore_events.borrow_mut().push("restore");
                Err(Error::DnsConfigurationFailed("restore failed".to_string()))
            },
            || proxy_events.borrow_mut().push("proxy"),
        );

        assert!(result.is_err());
        assert_eq!(*events.borrow(), ["monitor", "restore", "proxy"]);
    }

    #[test]
    fn treats_missing_systemd_resolved_interface_as_already_restored() {
        let error = r#"resolvectl exited with status exit status: 1: Failed to resolve interface "tun0": No such device"#;

        assert!(is_resolvectl_missing_interface_error(error));
    }
}
