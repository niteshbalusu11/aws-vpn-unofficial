use crate::{Error, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time;
use url::form_urlencoded;

pub const MAX_SAML_RESPONSE_BYTES: usize = 131_072;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_FORM_BODY_BYTES: usize = 512 * 1024;
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

#[derive(Debug)]
pub struct SamlAcsServer {
    listener: TcpListener,
    timeout: Duration,
}

impl SamlAcsServer {
    pub async fn bind(host: IpAddr, port: u16, timeout: Duration) -> Result<Self> {
        if !host.is_loopback() {
            return Err(Error::InvalidConfig(
                "ACS host must be a loopback address".to_string(),
            ));
        }

        let listener = TcpListener::bind(SocketAddr::new(host, port))
            .await
            .map_err(Error::AcsBindFailed)?;

        Ok(Self { listener, timeout })
    }

    pub async fn bind_localhost(port: u16, timeout: Duration) -> Result<Self> {
        Self::bind(IpAddr::V4(Ipv4Addr::LOCALHOST), port, timeout).await
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(Error::AcsServer)
    }

    pub async fn receive_once(&self) -> Result<SamlAssertion> {
        time::timeout(self.timeout, self.receive_once_inner())
            .await
            .map_err(|_| Error::SamlTimeout)?
    }

    async fn receive_once_inner(&self) -> Result<SamlAssertion> {
        loop {
            let (mut stream, _) = self.listener.accept().await.map_err(Error::AcsServer)?;

            match read_saml_assertion(&mut stream).await {
                Ok(assertion) => {
                    write_response(&mut stream, 200, "OK", SUCCESS_HTML).await?;
                    return Ok(assertion);
                }
                Err(err) if should_continue_after_error(&err) => {
                    let (status, reason, body) = response_for_error(&err);
                    let _ = write_response(&mut stream, status, reason, body).await;
                    continue;
                }
                Err(err) => {
                    let (status, reason, body) = response_for_error(&err);
                    let _ = write_response(&mut stream, status, reason, body).await;
                    return Err(err);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlAssertion {
    value: String,
}

impl SamlAssertion {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty() {
            return Err(Error::SamlResponseMissing);
        }

        if value.len() > MAX_SAML_RESPONSE_BYTES {
            return Err(Error::SamlResponseTooLarge);
        }

        if value.chars().any(char::is_control) {
            return Err(Error::InvalidConfig(
                "SAML response contains control characters".to_string(),
            ));
        }

        Ok(Self { value })
    }

    pub fn expose_for_openvpn(&self) -> &str {
        &self.value
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

async fn read_saml_assertion(stream: &mut TcpStream) -> Result<SamlAssertion> {
    let mut buffer = Vec::new();
    let header_end = read_headers(stream, &mut buffer).await?;
    let (head, already_read_body) = buffer.split_at(header_end);
    let request = parse_request(head)?;
    validate_request(&request)?;

    let content_length = request
        .headers
        .get("content-length")
        .ok_or_else(|| Error::InvalidConfig("SAML callback missing Content-Length".to_string()))?
        .parse::<usize>()
        .map_err(|err| Error::InvalidConfig(format!("invalid Content-Length: {err}")))?;

    if content_length > MAX_FORM_BODY_BYTES {
        return Err(Error::SamlResponseTooLarge);
    }

    let mut body = already_read_body.to_vec();
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let mut chunk = vec![0; remaining.min(8192)];
        let read = stream.read(&mut chunk).await.map_err(Error::AcsServer)?;
        if read == 0 {
            return Err(Error::InvalidConfig(
                "SAML callback body ended early".to_string(),
            ));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    parse_saml_response(&body)
}

async fn read_headers(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<usize> {
    loop {
        if let Some(offset) = find_header_end(buffer) {
            return Ok(offset);
        }

        if buffer.len() > MAX_HEADER_BYTES {
            return Err(Error::InvalidConfig(
                "SAML callback headers are too large".to_string(),
            ));
        }

        let mut chunk = [0; 2048];
        let read = stream.read(&mut chunk).await.map_err(Error::AcsServer)?;
        if read == 0 {
            return Err(Error::InvalidConfig(
                "SAML callback ended before headers completed".to_string(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(HEADER_TERMINATOR.len())
        .position(|window| window == HEADER_TERMINATOR)
        .map(|position| position + HEADER_TERMINATOR.len())
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

fn parse_request(head: &[u8]) -> Result<HttpRequest> {
    let head = std::str::from_utf8(head)
        .map_err(|err| Error::InvalidConfig(format!("SAML callback was not valid UTF-8: {err}")))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| Error::InvalidConfig("SAML callback missing request line".to_string()))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| Error::InvalidConfig("SAML callback missing method".to_string()))?
        .to_string();
    let path = request_parts
        .next()
        .ok_or_else(|| Error::InvalidConfig("SAML callback missing path".to_string()))?
        .to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
    })
}

fn validate_request(request: &HttpRequest) -> Result<()> {
    if request.method != "POST" {
        return Err(Error::InvalidConfig(
            "SAML callback must use POST".to_string(),
        ));
    }

    if request.path != "/" {
        return Err(Error::InvalidConfig(
            "SAML callback path must be /".to_string(),
        ));
    }

    if let Some(content_type) = request.headers.get("content-type") {
        let content_type = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if content_type != "application/x-www-form-urlencoded" {
            return Err(Error::InvalidConfig(
                "SAML callback content type must be application/x-www-form-urlencoded".to_string(),
            ));
        }
    }

    Ok(())
}

fn parse_saml_response(body: &[u8]) -> Result<SamlAssertion> {
    let response = form_urlencoded::parse(body)
        .find_map(|(key, value)| (key == "SAMLResponse").then(|| value.into_owned()))
        .ok_or(Error::SamlResponseMissing)?;

    SamlAssertion::new(response)
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(Error::AcsServer)
}

fn response_for_error(err: &Error) -> (u16, &'static str, &'static str) {
    match err {
        Error::SamlResponseTooLarge => (413, "Payload Too Large", FAILURE_HTML),
        Error::SamlResponseMissing => (400, "Bad Request", FAILURE_HTML),
        Error::InvalidConfig(message) if message.contains("must use POST") => {
            (200, "OK", WAITING_HTML)
        }
        Error::InvalidConfig(message) if message.contains("path must be /") => {
            (404, "Not Found", WAITING_HTML)
        }
        _ => (400, "Bad Request", FAILURE_HTML),
    }
}

fn should_continue_after_error(err: &Error) -> bool {
    matches!(
        err,
        Error::InvalidConfig(message)
            if message.contains("must use POST") || message.contains("path must be /")
    )
}

const SUCCESS_HTML: &str =
    "<!doctype html><html><body>SAML login received. You can close this window.</body></html>";
const FAILURE_HTML: &str =
    "<!doctype html><html><body>SAML login could not be completed.</body></html>";
const WAITING_HTML: &str =
    "<!doctype html><html><body>Waiting for SAML login response.</body></html>";

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn receives_saml_response() {
        let server = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move { server.receive_once().await });
        let response = post_form(addr, "/", "SAMLResponse=assertion-value")
            .await
            .unwrap();
        let assertion = server_task.await.unwrap().unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(assertion.expose_for_openvpn(), "assertion-value");
    }

    #[tokio::test]
    async fn decodes_form_encoded_saml_response() {
        let server = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move { server.receive_once().await });
        post_form(addr, "/", "RelayState=x&SAMLResponse=hello%2Bworld%3D")
            .await
            .unwrap();
        let assertion = server_task.await.unwrap().unwrap();

        assert_eq!(assertion.expose_for_openvpn(), "hello+world=");
    }

    #[tokio::test]
    async fn rejects_missing_saml_response() {
        let server = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move { server.receive_once().await });
        let response = post_form(addr, "/", "RelayState=x").await.unwrap();
        let err = server_task.await.unwrap().unwrap_err();

        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(matches!(err, Error::SamlResponseMissing));
    }

    #[tokio::test]
    async fn rejects_oversized_decoded_saml_response() {
        let server = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let oversized = "a".repeat(MAX_SAML_RESPONSE_BYTES + 1);
        let body = format!("SAMLResponse={oversized}");

        let server_task = tokio::spawn(async move { server.receive_once().await });
        let response = post_form(addr, "/", &body).await.unwrap();
        let err = server_task.await.unwrap().unwrap_err();

        assert!(response.starts_with("HTTP/1.1 413 Payload Too Large"));
        assert!(matches!(err, Error::SamlResponseTooLarge));
    }

    #[tokio::test]
    async fn rejects_control_characters_in_saml_response() {
        let server = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move { server.receive_once().await });
        let response = post_form(addr, "/", "SAMLResponse=assertion%0D%0Apassword")
            .await
            .unwrap();
        let err = server_task.await.unwrap().unwrap_err();

        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(
            matches!(err, Error::InvalidConfig(message) if message.contains("control characters"))
        );
    }

    #[tokio::test]
    async fn ignores_get_before_valid_post() {
        let server = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move { server.receive_once().await });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let response = read_response(&mut stream).await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"));

        let response = post_form(addr, "/", "SAMLResponse=assertion")
            .await
            .unwrap();
        let assertion = server_task.await.unwrap().unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(assertion.expose_for_openvpn(), "assertion");
    }

    #[tokio::test]
    async fn ignores_wrong_path_before_valid_post() {
        let server = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move { server.receive_once().await });
        let response = post_form(addr, "/callback", "SAMLResponse=assertion")
            .await
            .unwrap();

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));

        let response = post_form(addr, "/", "SAMLResponse=assertion")
            .await
            .unwrap();
        let assertion = server_task.await.unwrap().unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(assertion.expose_for_openvpn(), "assertion");
    }

    #[tokio::test]
    async fn times_out_waiting_for_callback() {
        let server = SamlAcsServer::bind_localhost(0, Duration::from_millis(10))
            .await
            .unwrap();

        let err = server.receive_once().await.unwrap_err();

        assert!(matches!(err, Error::SamlTimeout));
    }

    #[tokio::test]
    async fn refuses_non_loopback_bind_address() {
        let err = SamlAcsServer::bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, Duration::from_secs(5))
            .await
            .unwrap_err();

        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    async fn post_form(addr: SocketAddr, path: &str, body: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect(addr).await?;
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await?;
        read_response(&mut stream).await
    }

    async fn read_response(stream: &mut TcpStream) -> std::io::Result<String> {
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).await?;
        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }
}
