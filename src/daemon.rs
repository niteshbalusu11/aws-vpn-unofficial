use crate::{Error, Result};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

const STATE_DIR_PREFIX: &str = "awsvpn";
const SOCKET_FILE: &str = "control.sock";
const STATE_FILE: &str = "state";
const MAX_LINE_LEN: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPaths {
    pub dir: PathBuf,
    pub socket: PathBuf,
    pub state: PathBuf,
}

impl DaemonPaths {
    pub fn default_for_current_user() -> Result<Self> {
        let uid = current_euid();
        let dir = if uid == 0 {
            std::env::temp_dir().join(format!("{STATE_DIR_PREFIX}-{uid}"))
        } else if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join(STATE_DIR_PREFIX)
        } else {
            std::env::temp_dir().join(format!("{STATE_DIR_PREFIX}-{uid}"))
        };
        Ok(Self::new(dir))
    }

    pub fn new(dir: PathBuf) -> Self {
        Self {
            socket: dir.join(SOCKET_FILE),
            state: dir.join(STATE_FILE),
            dir,
        }
    }

    pub fn prepare_dir(&self) -> Result<()> {
        prepare_secure_dir(&self.dir)
    }

    pub fn cleanup(&self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.state);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRequest {
    Status,
    Disconnect,
}

impl ControlRequest {
    fn line(self) -> &'static str {
        match self {
            Self::Status => "STATUS\n",
            Self::Disconnect => "DISCONNECT\n",
        }
    }

    fn parse(line: &str) -> Result<Self> {
        match line.trim_end_matches(['\r', '\n']) {
            "STATUS" => Ok(Self::Status),
            "DISCONNECT" => Ok(Self::Disconnect),
            value => Err(Error::DaemonControl(format!(
                "unknown control request: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    pub state: SessionState,
    pub daemon_pid: u32,
    pub openvpn_pid: Option<u32>,
    pub vpn_ip: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
    Failed,
}

impl SessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Disconnecting => "disconnecting",
            Self::Disconnected => "disconnected",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "connecting" => Ok(Self::Connecting),
            "connected" => Ok(Self::Connected),
            "disconnecting" => Ok(Self::Disconnecting),
            "disconnected" => Ok(Self::Disconnected),
            "failed" => Ok(Self::Failed),
            _ => Err(Error::DaemonControl(format!(
                "unknown daemon state: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlResponse {
    Ok(SessionStatus),
    Disconnected,
    Error(String),
}

impl ControlResponse {
    pub fn render(&self) -> String {
        match self {
            Self::Ok(status) => {
                let mut line = format!(
                    "OK\tstate={}\tdaemon_pid={}",
                    status.state.as_str(),
                    status.daemon_pid
                );
                if let Some(openvpn_pid) = status.openvpn_pid {
                    let _ = write!(line, "\topenvpn_pid={openvpn_pid}");
                }
                if let Some(vpn_ip) = status.vpn_ip {
                    let _ = write!(line, "\tvpn_ip={vpn_ip}");
                }
                line.push('\n');
                line
            }
            Self::Disconnected => "OK\tstate=disconnected\n".to_string(),
            Self::Error(message) => {
                let message = sanitize_control_message(message);
                format!("ERR\t{message}\n")
            }
        }
    }

    pub fn parse(line: &str) -> Result<Self> {
        let line = line.trim_end_matches(['\r', '\n']);
        if let Some(message) = line.strip_prefix("ERR\t") {
            return Ok(Self::Error(message.to_string()));
        }

        let mut fields = line.split('\t');
        match fields.next() {
            Some("OK") => {}
            _ => {
                return Err(Error::DaemonControl("invalid control response".to_string()));
            }
        }

        let mut state = None;
        let mut daemon_pid = None;
        let mut openvpn_pid = None;
        let mut vpn_ip = None;

        for field in fields {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            match key {
                "state" => state = Some(SessionState::parse(value)?),
                "daemon_pid" => {
                    daemon_pid = Some(value.parse().map_err(|_| {
                        Error::DaemonControl("invalid daemon PID in response".to_string())
                    })?)
                }
                "openvpn_pid" => {
                    openvpn_pid = Some(value.parse().map_err(|_| {
                        Error::DaemonControl("invalid OpenVPN PID in response".to_string())
                    })?)
                }
                "vpn_ip" => {
                    vpn_ip = Some(value.parse().map_err(|_| {
                        Error::DaemonControl("invalid VPN IP in response".to_string())
                    })?)
                }
                _ => {}
            }
        }

        if state == Some(SessionState::Disconnected) && daemon_pid.is_none() {
            return Ok(Self::Disconnected);
        }

        Ok(Self::Ok(SessionStatus {
            state: state.ok_or_else(|| {
                Error::DaemonControl("missing daemon state in response".to_string())
            })?,
            daemon_pid: daemon_pid.ok_or_else(|| {
                Error::DaemonControl("missing daemon PID in response".to_string())
            })?,
            openvpn_pid,
            vpn_ip,
        }))
    }
}

pub struct ControlServer {
    listener: UnixListener,
    paths: DaemonPaths,
}

impl ControlServer {
    pub async fn bind_default() -> Result<Self> {
        let paths = DaemonPaths::default_for_current_user()?;
        Self::bind(paths).await
    }

    pub async fn bind(paths: DaemonPaths) -> Result<Self> {
        paths.prepare_dir()?;
        remove_stale_socket(&paths).await?;
        let listener = UnixListener::bind(&paths.socket).map_err(|err| {
            Error::DaemonControl(format!(
                "could not bind daemon control socket {}: {err}",
                paths.socket.display()
            ))
        })?;
        Ok(Self { listener, paths })
    }

    pub fn paths(&self) -> &DaemonPaths {
        &self.paths
    }

    pub async fn accept(&self) -> Result<ControlConnection> {
        let (stream, _) = self.listener.accept().await.map_err(|err| {
            Error::DaemonControl(format!("could not accept daemon control request: {err}"))
        })?;
        Ok(ControlConnection { stream })
    }
}

pub struct ControlConnection {
    stream: UnixStream,
}

impl ControlConnection {
    pub async fn read_request(&mut self) -> Result<ControlRequest> {
        let line = read_limited_line(&mut self.stream).await?;
        ControlRequest::parse(&line)
    }

    pub async fn write_response(mut self, response: &ControlResponse) -> Result<()> {
        self.stream
            .write_all(response.render().as_bytes())
            .await
            .map_err(|err| Error::DaemonControl(format!("could not write daemon response: {err}")))
    }
}

pub async fn send_default(request: ControlRequest) -> Result<ControlResponse> {
    let paths = DaemonPaths::default_for_current_user()?;
    send(&paths, request).await
}

pub async fn send(paths: &DaemonPaths, request: ControlRequest) -> Result<ControlResponse> {
    let mut stream = UnixStream::connect(&paths.socket)
        .await
        .map_err(|err| map_connect_error(err, &paths.socket))?;
    stream
        .write_all(request.line().as_bytes())
        .await
        .map_err(|err| Error::DaemonControl(format!("could not write daemon request: {err}")))?;
    let line = read_limited_line(&mut stream).await?;
    ControlResponse::parse(&line)
}

pub fn write_state(paths: &DaemonPaths, status: &SessionStatus) -> Result<()> {
    paths.prepare_dir()?;

    let mut contents = String::new();
    let _ = writeln!(contents, "state={}", status.state.as_str());
    let _ = writeln!(contents, "daemon_pid={}", status.daemon_pid);
    if let Some(openvpn_pid) = status.openvpn_pid {
        let _ = writeln!(contents, "openvpn_pid={openvpn_pid}");
    }
    if let Some(vpn_ip) = status.vpn_ip {
        let _ = writeln!(contents, "vpn_ip={vpn_ip}");
    }
    let _ = writeln!(contents, "socket={}", paths.socket.display());

    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&paths.state)
        .map_err(|err| Error::DaemonControl(format!("could not write daemon state: {err}")))?;
    file.write_all(contents.as_bytes())
        .map_err(|err| Error::DaemonControl(format!("could not write daemon state: {err}")))
}

async fn remove_stale_socket(paths: &DaemonPaths) -> Result<()> {
    if !paths.socket.exists() {
        return Ok(());
    }

    match send(paths, ControlRequest::Status).await {
        Ok(_) => Err(Error::DaemonControl(
            "a VPN daemon is already running".to_string(),
        )),
        Err(Error::DaemonUnavailable) => {
            let _ = fs::remove_file(&paths.socket);
            let _ = fs::remove_file(&paths.state);
            Ok(())
        }
        Err(err) => Err(err),
    }
}

async fn read_limited_line(stream: &mut UnixStream) -> Result<String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes = reader
        .read_line(&mut line)
        .await
        .map_err(|err| Error::DaemonControl(format!("could not read daemon line: {err}")))?;
    if bytes == 0 {
        return Err(Error::DaemonControl(
            "daemon closed the control connection".to_string(),
        ));
    }
    if line.len() > MAX_LINE_LEN {
        return Err(Error::DaemonControl(
            "daemon control line was too long".to_string(),
        ));
    }
    Ok(line)
}

fn map_connect_error(err: io::Error, socket: &Path) -> Error {
    match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => Error::DaemonUnavailable,
        _ => Error::DaemonControl(format!(
            "could not connect to daemon control socket {}: {err}",
            socket.display()
        )),
    }
}

fn prepare_secure_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(Error::DaemonControl(format!(
                    "daemon state path is not a secure directory: {}",
                    path.display()
                )));
            }
            validate_secure_dir_metadata(path, &metadata)?;
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|err| {
                Error::DaemonControl(format!(
                    "could not create daemon state directory {}: {err}",
                    path.display()
                ))
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|err| {
                Error::DaemonControl(format!(
                    "could not secure daemon state directory {}: {err}",
                    path.display()
                ))
            })?;
            let metadata = fs::symlink_metadata(path).map_err(|err| {
                Error::DaemonControl(format!(
                    "could not inspect daemon state directory {}: {err}",
                    path.display()
                ))
            })?;
            validate_secure_dir_metadata(path, &metadata)?;
        }
        Err(err) => {
            return Err(Error::DaemonControl(format!(
                "could not inspect daemon state directory {}: {err}",
                path.display()
            )));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn validate_secure_dir_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let uid = current_euid();
    if metadata.uid() != uid {
        return Err(Error::DaemonControl(format!(
            "daemon state directory is owned by uid {}, expected {uid}: {}",
            metadata.uid(),
            path.display()
        )));
    }

    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::DaemonControl(format!(
            "daemon state directory must not be group/world accessible: {}",
            path.display()
        )));
    }

    Ok(())
}

fn sanitize_control_message(message: &str) -> String {
    message
        .chars()
        .map(|value| match value {
            '\t' | '\r' | '\n' => ' ',
            value if value.is_control() => ' ',
            value => value,
        })
        .collect()
}

fn current_euid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_control_requests() {
        assert_eq!(
            ControlRequest::parse("STATUS\n").unwrap(),
            ControlRequest::Status
        );
        assert_eq!(
            ControlRequest::parse("DISCONNECT\n").unwrap(),
            ControlRequest::Disconnect
        );
        assert!(ControlRequest::parse("PASSWORD secret\n").is_err());
    }

    #[test]
    fn renders_and_parses_status_response() {
        let response = ControlResponse::Ok(SessionStatus {
            state: SessionState::Connected,
            daemon_pid: 123,
            openvpn_pid: Some(456),
            vpn_ip: Some("10.0.0.10".parse().unwrap()),
        });

        assert_eq!(
            ControlResponse::parse(&response.render()).unwrap(),
            response
        );
    }

    #[test]
    fn sanitizes_error_response_control_characters() {
        let rendered = ControlResponse::Error("bad\tthing\nsecret".to_string()).render();
        assert_eq!(rendered, "ERR\tbad thing secret\n");
    }

    #[test]
    fn prepares_private_state_directory() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("daemon");
        prepare_secure_dir(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
