use crate::logredact::redact_line;
use crate::{Error, Result, VpnEvent};
use rand::Rng;
use rand::distr::Alphanumeric;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpListener};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;

#[derive(Debug, Clone)]
pub struct OpenVpnLaunchOptions {
    pub binary: PathBuf,
    pub config: PathBuf,
    pub management_host: IpAddr,
    pub management_port: Option<u16>,
    pub configure_dns: bool,
    pub ignore_default_route: bool,
    pub ignore_pushed_routes: bool,
}

#[derive(Debug)]
pub struct OpenVpnPrepared {
    options: OpenVpnLaunchOptions,
    workdir: TempDir,
    management_password: String,
    management_password_file: PathBuf,
    management_addr: SocketAddr,
    dns_scripts: Option<DnsScripts>,
}

#[derive(Debug)]
struct DnsScripts {
    up: PathBuf,
    down: PathBuf,
}

impl OpenVpnPrepared {
    pub fn new(options: OpenVpnLaunchOptions) -> Result<Self> {
        if !options.management_host.is_loopback() {
            return Err(Error::InvalidConfig(
                "management host must be a loopback address".to_string(),
            ));
        }

        let port = match options.management_port {
            Some(port) => port,
            None => reserve_management_port(options.management_host)?,
        };
        let management_addr = SocketAddr::new(options.management_host, port);
        let workdir = tempfile::Builder::new()
            .prefix("awsvpn-")
            .tempdir()
            .map_err(Error::TempFile)?;
        let management_password = generate_management_password();
        let management_password_file = workdir.path().join("management-password");
        write_secret_file(&management_password_file, &management_password)?;
        let dns_scripts = prepare_dns_scripts(&options, workdir.path())?;
        validate_config_does_not_enable_scripts(&options.config)?;

        Ok(Self {
            options,
            workdir,
            management_password,
            management_password_file,
            management_addr,
            dns_scripts,
        })
    }

    pub fn management_addr(&self) -> SocketAddr {
        self.management_addr
    }

    pub fn management_password(&self) -> &str {
        &self.management_password
    }

    pub fn uses_dns_scripts(&self) -> bool {
        self.dns_scripts.is_some()
    }

    pub fn args(&self) -> Vec<String> {
        let mut args = vec![
            "--config".to_string(),
            self.options.config.display().to_string(),
            "--management".to_string(),
            self.management_addr.ip().to_string(),
            self.management_addr.port().to_string(),
            self.management_password_file.display().to_string(),
            "--management-query-passwords".to_string(),
            "--management-hold".to_string(),
            "--auth-nocache".to_string(),
        ];

        if self.options.configure_dns {
            args.extend(self.dns_script_args());
        }

        if self.options.ignore_pushed_routes {
            args.push("--route-nopull".to_string());
        } else if self.options.ignore_default_route {
            args.extend([
                "--pull-filter".to_string(),
                "ignore".to_string(),
                "redirect-gateway".to_string(),
            ]);
        }

        args
    }

    fn dns_script_args(&self) -> Vec<String> {
        let Some(dns_scripts) = &self.dns_scripts else {
            return Vec::new();
        };

        let config_dir = self
            .options
            .config
            .parent()
            .unwrap_or_else(|| Path::new("."));

        vec![
            "--script-security".to_string(),
            "2".to_string(),
            "--setenv".to_string(),
            "TUNNELBLICK_CONFIG_FOLDER".to_string(),
            config_dir.display().to_string(),
            "--setenv".to_string(),
            "CVPN_CONN_PROFILE_NAME".to_string(),
            self.options
                .config
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("awsvpn")
                .to_string(),
            "--up".to_string(),
            dns_scripts.up.display().to_string(),
            "--down".to_string(),
            dns_scripts.down.display().to_string(),
        ]
    }

    pub async fn spawn(
        self,
        event_tx: Option<mpsc::UnboundedSender<VpnEvent>>,
    ) -> Result<OpenVpnProcess> {
        let mut command = Command::new(&self.options.binary);
        command
            .args(self.args())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(Error::OpenVpnSpawnFailed)?;
        let pid = child.id();
        let mut log_tasks = Vec::new();

        if let Some(tx) = &event_tx {
            if let Some(stdout) = child.stdout.take() {
                log_tasks.push(spawn_log_reader("openvpn stdout", stdout, tx.clone()));
            }
            if let Some(stderr) = child.stderr.take() {
                log_tasks.push(spawn_log_reader("openvpn stderr", stderr, tx.clone()));
            }
            if let Some(pid) = pid {
                let _ = tx.send(VpnEvent::OpenVpnStarted { pid });
            }
        }

        Ok(OpenVpnProcess {
            child,
            pid,
            management_addr: self.management_addr,
            management_password: self.management_password,
            log_tasks,
            _workdir: self.workdir,
        })
    }
}

pub struct OpenVpnProcess {
    child: Child,
    pid: Option<u32>,
    management_addr: SocketAddr,
    management_password: String,
    log_tasks: Vec<JoinHandle<()>>,
    _workdir: TempDir,
}

impl OpenVpnProcess {
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub fn management_addr(&self) -> SocketAddr {
        self.management_addr
    }

    pub fn management_password(&self) -> &str {
        &self.management_password
    }

    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        self.child.wait().await.map_err(Error::OpenVpnProcess)
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.child.try_wait().map_err(Error::OpenVpnProcess)
    }

    pub async fn terminate(&mut self, timeout: Duration) -> Result<()> {
        if let Ok(Some(_)) = self.child.try_wait() {
            self.abort_log_tasks();
            return Ok(());
        }

        match time::timeout(timeout, self.child.wait()).await {
            Ok(result) => {
                result.map_err(Error::OpenVpnProcess)?;
            }
            Err(_) => {
                let _ = self.child.start_kill();
                let _ = self.child.kill().await;
            }
        }
        self.abort_log_tasks();
        Ok(())
    }

    fn abort_log_tasks(&mut self) {
        for task in self.log_tasks.drain(..) {
            task.abort();
        }
    }
}

impl std::fmt::Debug for OpenVpnProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenVpnProcess")
            .field("pid", &self.pid)
            .field("management_addr", &self.management_addr)
            .finish_non_exhaustive()
    }
}

pub fn reserve_management_port(host: IpAddr) -> Result<u16> {
    if !host.is_loopback() {
        return Err(Error::InvalidConfig(
            "management host must be a loopback address".to_string(),
        ));
    }

    let listener = TcpListener::bind(SocketAddr::new(host, 0)).map_err(Error::ManagementIo)?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(Error::ManagementIo)
}

fn generate_management_password() -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn write_secret_file(path: &Path, contents: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);

    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path).map_err(Error::TempFile)?;
    file.write_all(contents.as_bytes())
        .map_err(Error::TempFile)?;
    file.write_all(b"\n").map_err(Error::TempFile)?;
    Ok(())
}

fn prepare_dns_scripts(
    options: &OpenVpnLaunchOptions,
    workdir: &Path,
) -> Result<Option<DnsScripts>> {
    if !options.configure_dns {
        return Ok(None);
    }

    let Some(openvpn_dir) = options.binary.parent() else {
        return Ok(None);
    };
    let up_script = openvpn_dir.join("client.up");
    let down_script = openvpn_dir.join("client.down");

    if !up_script.is_file() || !down_script.is_file() {
        return Ok(None);
    }

    let up_link = workdir.join("client-up");
    let down_link = workdir.join("client-down");
    link_script(&up_script, &up_link)?;
    link_script(&down_script, &down_link)?;

    Ok(Some(DnsScripts {
        up: up_link,
        down: down_link,
    }))
}

fn validate_config_does_not_enable_scripts(config: &Path) -> Result<()> {
    let Ok(contents) = std::fs::read_to_string(config) else {
        return Ok(());
    };

    for line in contents.lines() {
        let line = line.trim_start();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with('<')
        {
            continue;
        }

        let directive = line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_start_matches("--")
            .trim_matches('"')
            .trim_matches('\'');

        if is_script_directive(directive) {
            return Err(Error::InvalidConfig(format!(
                "config contains unsupported script directive: {directive}"
            )));
        }
    }

    Ok(())
}

fn is_script_directive(directive: &str) -> bool {
    matches!(
        directive,
        "script-security"
            | "up"
            | "down"
            | "ipchange"
            | "route-up"
            | "route-pre-down"
            | "client-connect"
            | "client-disconnect"
            | "learn-address"
            | "auth-user-pass-verify"
            | "tls-verify"
            | "tls-crypt-v2-verify"
            | "plugin"
    )
}

#[cfg(unix)]
fn link_script(source: &Path, link: &Path) -> Result<()> {
    let source = std::fs::canonicalize(source).map_err(Error::TempFile)?;
    std::os::unix::fs::symlink(source, link).map_err(Error::TempFile)
}

#[cfg(not(unix))]
fn link_script(source: &Path, link: &Path) -> Result<()> {
    let source = std::fs::canonicalize(source).map_err(Error::TempFile)?;
    std::fs::copy(source, link)
        .map(|_| ())
        .map_err(Error::TempFile)
}

fn spawn_log_reader<R>(
    source: &'static str,
    reader: R,
    tx: mpsc::UnboundedSender<VpnEvent>,
) -> JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let line = redact_line(&line);
                    let _ = tx.send(VpnEvent::Log {
                        line: format!("{source}: {line}"),
                    });
                }
                Ok(None) => break,
                Err(err) => {
                    let _ = tx.send(VpnEvent::Warning {
                        message: format!("{source} log stream failed: {err}"),
                    });
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    #[test]
    fn reserves_loopback_management_port() {
        let port = reserve_management_port(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        assert_ne!(port, 0);
    }

    #[test]
    fn refuses_non_loopback_management_port() {
        let err = reserve_management_port(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn refuses_non_loopback_prepared_management_host() {
        let err = OpenVpnPrepared::new(OpenVpnLaunchOptions {
            binary: PathBuf::from("/bin/echo"),
            config: PathBuf::from("/tmp/client.ovpn"),
            management_host: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            management_port: Some(47000),
            configure_dns: true,
            ignore_default_route: false,
            ignore_pushed_routes: false,
        })
        .unwrap_err();

        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn prepares_secure_management_password_file_and_args() {
        let prepared = OpenVpnPrepared::new(OpenVpnLaunchOptions {
            binary: PathBuf::from("/bin/echo"),
            config: PathBuf::from("/tmp/client.ovpn"),
            management_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            management_port: Some(47000),
            configure_dns: true,
            ignore_default_route: false,
            ignore_pushed_routes: false,
        })
        .unwrap();

        assert_eq!(
            fs::read_to_string(&prepared.management_password_file).unwrap(),
            format!("{}\n", prepared.management_password())
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&prepared.management_password_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let args = prepared.args();
        assert!(args.contains(&"--management".to_string()));
        assert!(args.contains(&"127.0.0.1".to_string()));
        assert!(args.contains(&"47000".to_string()));
        assert!(args.contains(&"--management-query-passwords".to_string()));
        assert!(args.contains(&"--management-hold".to_string()));
    }

    #[test]
    fn adds_aws_macos_dns_scripts_when_present() {
        let tempdir = tempfile::tempdir().unwrap();
        let openvpn_dir = tempdir.path().join("openvpn");
        fs::create_dir(&openvpn_dir).unwrap();
        let binary = openvpn_dir.join("acvc-openvpn");
        let up_script = openvpn_dir.join("client.up");
        let down_script = openvpn_dir.join("client.down");
        fs::write(&binary, "").unwrap();
        fs::write(&up_script, "").unwrap();
        fs::write(&down_script, "").unwrap();

        let config_dir = tempdir.path().join("configs");
        fs::create_dir(&config_dir).unwrap();
        let config = config_dir.join("example.ovpn");
        fs::write(&config, "").unwrap();

        let prepared = OpenVpnPrepared::new(OpenVpnLaunchOptions {
            binary,
            config: config.clone(),
            management_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            management_port: Some(47000),
            configure_dns: true,
            ignore_default_route: false,
            ignore_pushed_routes: false,
        })
        .unwrap();

        let args = prepared.args();
        let up_arg = args
            .windows(2)
            .find_map(|pair| (pair[0] == "--up").then_some(pair[1].as_str()))
            .unwrap();
        let down_arg = args
            .windows(2)
            .find_map(|pair| (pair[0] == "--down").then_some(pair[1].as_str()))
            .unwrap();
        assert!(up_arg.ends_with("client-up"));
        assert!(down_arg.ends_with("client-down"));
        assert!(!up_arg.contains(' '));
        assert!(!down_arg.contains(' '));
        assert!(args.contains(&"--script-security".to_string()));

        #[cfg(unix)]
        {
            assert_eq!(
                fs::read_link(up_arg).unwrap(),
                fs::canonicalize(up_script).unwrap()
            );
            assert_eq!(
                fs::read_link(down_arg).unwrap(),
                fs::canonicalize(down_script).unwrap()
            );
        }

        assert!(args.windows(3).any(|window| window
            == [
                "--setenv",
                "TUNNELBLICK_CONFIG_FOLDER",
                config.parent().unwrap().to_str().unwrap()
            ]));
        assert!(
            args.windows(3)
                .any(|window| window == ["--setenv", "CVPN_CONN_PROFILE_NAME", "example"])
        );
    }

    #[test]
    fn dns_script_symlinks_resolve_relative_openvpn_path() {
        let tempdir = tempfile::tempdir().unwrap();
        let openvpn_dir = tempdir.path().join("openvpn");
        fs::create_dir(&openvpn_dir).unwrap();
        fs::write(openvpn_dir.join("acvc-openvpn"), "").unwrap();
        fs::write(openvpn_dir.join("client.up"), "").unwrap();
        fs::write(openvpn_dir.join("client.down"), "").unwrap();

        let previous_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(tempdir.path()).unwrap();

        let prepared = OpenVpnPrepared::new(OpenVpnLaunchOptions {
            binary: PathBuf::from("openvpn/acvc-openvpn"),
            config: PathBuf::from("client.ovpn"),
            management_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            management_port: Some(47000),
            configure_dns: true,
            ignore_default_route: false,
            ignore_pushed_routes: false,
        })
        .unwrap();

        std::env::set_current_dir(previous_dir).unwrap();

        let args = prepared.args();
        let up_arg = args
            .windows(2)
            .find_map(|pair| (pair[0] == "--up").then_some(pair[1].as_str()))
            .unwrap();

        #[cfg(unix)]
        assert!(fs::read_link(up_arg).unwrap().is_absolute());
    }

    #[test]
    fn skips_dns_scripts_when_disabled() {
        let tempdir = tempfile::tempdir().unwrap();
        let openvpn_dir = tempdir.path().join("openvpn");
        fs::create_dir(&openvpn_dir).unwrap();
        let binary = openvpn_dir.join("acvc-openvpn");
        fs::write(&binary, "").unwrap();
        fs::write(openvpn_dir.join("client.up"), "").unwrap();
        fs::write(openvpn_dir.join("client.down"), "").unwrap();

        let prepared = OpenVpnPrepared::new(OpenVpnLaunchOptions {
            binary,
            config: PathBuf::from("/tmp/client.ovpn"),
            management_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            management_port: Some(47000),
            configure_dns: false,
            ignore_default_route: false,
            ignore_pushed_routes: false,
        })
        .unwrap();

        let args = prepared.args();
        assert!(!args.contains(&"--up".to_string()));
        assert!(!args.contains(&"--down".to_string()));
        assert!(!args.contains(&"--script-security".to_string()));
    }

    #[test]
    fn can_ignore_pushed_default_route() {
        let prepared = OpenVpnPrepared::new(OpenVpnLaunchOptions {
            binary: PathBuf::from("/bin/echo"),
            config: PathBuf::from("/tmp/client.ovpn"),
            management_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            management_port: Some(47000),
            configure_dns: false,
            ignore_default_route: true,
            ignore_pushed_routes: false,
        })
        .unwrap();

        assert!(
            prepared
                .args()
                .windows(3)
                .any(|window| window == ["--pull-filter", "ignore", "redirect-gateway"])
        );
    }

    #[test]
    fn can_ignore_all_pushed_routes() {
        let prepared = OpenVpnPrepared::new(OpenVpnLaunchOptions {
            binary: PathBuf::from("/bin/echo"),
            config: PathBuf::from("/tmp/client.ovpn"),
            management_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            management_port: Some(47000),
            configure_dns: false,
            ignore_default_route: false,
            ignore_pushed_routes: true,
        })
        .unwrap();

        let args = prepared.args();
        assert!(args.contains(&"--route-nopull".to_string()));
        assert!(!args.contains(&"--pull-filter".to_string()));
    }

    #[test]
    fn rejects_config_script_directives() {
        let tempdir = tempfile::tempdir().unwrap();
        let config = tempdir.path().join("client.ovpn");
        fs::write(&config, "client\nup /tmp/pwn\n").unwrap();

        let err = OpenVpnPrepared::new(OpenVpnLaunchOptions {
            binary: PathBuf::from("/bin/echo"),
            config,
            management_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            management_port: Some(47000),
            configure_dns: false,
            ignore_default_route: false,
            ignore_pushed_routes: false,
        })
        .unwrap_err();

        assert!(
            matches!(err, Error::InvalidConfig(message) if message.contains("script directive"))
        );
    }

    #[tokio::test]
    async fn streams_redacted_openvpn_output() {
        let script = "printf 'password \"Auth\" CRV1::state::secret\\n'; printf 'SAMLResponse=secret&x=y\\n' >&2";
        let prepared = OpenVpnPrepared::new(OpenVpnLaunchOptions {
            binary: PathBuf::from("/bin/sh"),
            config: PathBuf::from("/tmp/client.ovpn"),
            management_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            management_port: Some(47001),
            configure_dns: true,
            ignore_default_route: false,
            ignore_pushed_routes: false,
        })
        .unwrap();

        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().unwrap();
        let mut process = OpenVpnProcess {
            pid: child.id(),
            management_addr: prepared.management_addr(),
            management_password: prepared.management_password().to_string(),
            log_tasks: vec![
                spawn_log_reader("openvpn stdout", child.stdout.take().unwrap(), tx.clone()),
                spawn_log_reader("openvpn stderr", child.stderr.take().unwrap(), tx),
            ],
            child,
            _workdir: prepared.workdir,
        };

        process.wait().await.unwrap();
        let mut logs = Vec::new();
        while let Ok(Some(event)) = time::timeout(Duration::from_millis(100), rx.recv()).await {
            if let VpnEvent::Log { line } = event {
                logs.push(line);
            }
        }

        assert!(logs.iter().any(|line| line.contains("[REDACTED]")));
        assert!(!logs.iter().any(|line| line.contains("secret")));
    }
}
