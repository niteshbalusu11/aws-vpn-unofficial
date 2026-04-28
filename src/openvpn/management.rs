use crate::openvpn::command::ManagementCommand;
use crate::openvpn::parser::{ManagementEvent, parse_management_line};
use crate::{Error, Result};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time;

#[derive(Debug)]
pub struct ManagementClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl ManagementClient {
    pub async fn connect(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(Error::ManagementConnectFailed)?;
        Ok(Self::from_stream(stream))
    }

    pub async fn connect_with_retry(addr: SocketAddr, timeout: Duration) -> Result<Self> {
        let deadline = Instant::now() + timeout;

        loop {
            match Self::connect(addr).await {
                Ok(client) => return Ok(client),
                Err(Error::ManagementConnectFailed(err)) => {
                    if Instant::now() >= deadline {
                        return Err(Error::ManagementConnectFailed(err));
                    }
                    time::sleep(Duration::from_millis(100)).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    pub fn from_stream(stream: TcpStream) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }

    pub async fn send(&mut self, command: &ManagementCommand) -> Result<()> {
        let mut line = command.line();
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(Error::ManagementIo)
    }

    pub async fn send_raw_line(&mut self, line: &str) -> Result<()> {
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(Error::ManagementIo)?;
        self.writer
            .write_all(b"\n")
            .await
            .map_err(Error::ManagementIo)
    }

    pub async fn authenticate(&mut self, password: &str) -> Result<()> {
        loop {
            let Some(line) = self.read_line().await? else {
                return Err(Error::ManagementProtocol(
                    "management socket closed during authentication".to_string(),
                ));
            };

            if line.starts_with("ENTER PASSWORD:") {
                self.send_raw_line(password).await?;
                continue;
            }

            if line.starts_with("SUCCESS:") {
                return Ok(());
            }

            if line.starts_with("ERROR:") {
                return Err(Error::ManagementProtocol(line));
            }
        }
    }

    pub async fn read_line(&mut self) -> Result<Option<String>> {
        let mut line = String::new();
        let bytes = self
            .reader
            .read_line(&mut line)
            .await
            .map_err(Error::ManagementIo)?;

        if bytes == 0 {
            return Ok(None);
        }

        Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
    }

    pub async fn read_event(&mut self) -> Result<Option<ManagementEvent>> {
        loop {
            let Some(line) = self.read_line().await? else {
                return Ok(None);
            };

            let event = parse_management_line(&line)?;
            if event != ManagementEvent::Ignored {
                return Ok(Some(event));
            }
        }
    }

    pub async fn enable_notifications_and_release_hold(&mut self) -> Result<()> {
        self.send(&ManagementCommand::StateOn).await?;
        self.send(&ManagementCommand::LogOn).await?;
        self.send(&ManagementCommand::EchoOn).await?;
        self.send(&ManagementCommand::HoldRelease).await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.send(&ManagementCommand::Signal("SIGTERM".to_string()))
            .await?;
        self.send(&ManagementCommand::Quit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openvpn::command::{acs_password, auth_username};
    use crate::openvpn::parser::SamlChallenge;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use url::Url;

    #[tokio::test]
    async fn sends_management_commands() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut lines = Vec::new();
            for _ in 0..2 {
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                lines.push(line.trim_end().to_string());
            }
            lines
        });

        let mut client = ManagementClient::connect(addr).await.unwrap();
        client.send(&auth_username()).await.unwrap();
        client.send(&acs_password(35001)).await.unwrap();

        assert_eq!(
            server.await.unwrap(),
            vec!["username \"Auth\" N/A", "password \"Auth\" ACS::35001"]
        );
    }

    #[tokio::test]
    async fn reads_parsed_management_event() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(b"INFO:OpenVPN Management Interface\n")
                .await
                .unwrap();
            stream
                .write_all(
                    b">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:state123:b'Ti9B':https://idp.example.com/saml']\n",
                )
                .await
                .unwrap();
        });

        let mut client = ManagementClient::connect(addr).await.unwrap();
        let event = client.read_event().await.unwrap().unwrap();

        assert_eq!(
            event,
            ManagementEvent::SamlChallenge(SamlChallenge {
                state_id: "state123".to_string(),
                url: Url::parse("https://idp.example.com/saml").unwrap(),
            })
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sends_notification_setup_commands() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut lines = Vec::new();
            for _ in 0..4 {
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                lines.push(line.trim_end().to_string());
            }
            lines
        });

        let mut client = ManagementClient::connect(addr).await.unwrap();
        client
            .enable_notifications_and_release_hold()
            .await
            .unwrap();

        assert_eq!(
            server.await.unwrap(),
            vec!["state on", "log on", "echo on", "hold release"]
        );
    }

    #[tokio::test]
    async fn authenticates_management_password_prompt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            reader
                .get_mut()
                .write_all(b"INFO:OpenVPN Management Interface\n")
                .await
                .unwrap();
            reader
                .get_mut()
                .write_all(b"ENTER PASSWORD:\n")
                .await
                .unwrap();

            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            reader
                .get_mut()
                .write_all(b"SUCCESS: password is correct\n")
                .await
                .unwrap();
            line.trim_end().to_string()
        });

        let mut client = ManagementClient::connect(addr).await.unwrap();
        client
            .authenticate("secret-management-password")
            .await
            .unwrap();

        assert_eq!(server.await.unwrap(), "secret-management-password");
    }
}
