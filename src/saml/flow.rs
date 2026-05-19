use crate::openvpn::command::{
    ManagementCommand, acs_password, auth_username, saml_response_password,
};
use crate::openvpn::management::ManagementClient;
use crate::openvpn::parser::{ManagementEvent, PushedRoute, parse_pushed_options};
use crate::saml::acs::SamlAcsServer;
use crate::saml::browser::{BrowserOpenResult, open_browser};
use crate::{BrowserMode, Error, Result, VpnEvent};
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlAuthOutcome {
    pub vpn_ip: Option<IpAddr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub routes: Vec<PushedRoute>,
}

#[derive(Debug, Default)]
pub(crate) struct SamlFlowState {
    active_state_id: Option<String>,
    saml_response: Option<String>,
    dns_servers: Vec<Ipv4Addr>,
    routes: Vec<PushedRoute>,
}

pub async fn drive_saml_auth(
    management: &mut ManagementClient,
    acs: &SamlAcsServer,
    browser: BrowserMode,
    print_login_url: bool,
    event_tx: Option<mpsc::UnboundedSender<VpnEvent>>,
) -> Result<SamlAuthOutcome> {
    management.enable_notifications_and_release_hold().await?;

    let mut state = SamlFlowState::default();

    loop {
        let Some(event) = management.read_event().await? else {
            return Err(Error::ManagementProtocol(
                "management socket closed before VPN connected".to_string(),
            ));
        };

        if let Some(outcome) = handle_saml_management_event(
            management,
            acs,
            browser,
            print_login_url,
            &event_tx,
            &mut state,
            false,
            event,
        )
        .await?
        {
            tracing::info!(vpn_ip = ?outcome.vpn_ip, "VPN connected");
            return Ok(outcome);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_saml_management_event(
    management: &mut ManagementClient,
    acs: &SamlAcsServer,
    browser: BrowserMode,
    print_login_url: bool,
    event_tx: &Option<mpsc::UnboundedSender<VpnEvent>>,
    state: &mut SamlFlowState,
    allow_auth_failure_reconnect: bool,
    event: ManagementEvent,
) -> Result<Option<SamlAuthOutcome>> {
    let acs_port = acs.local_addr()?.port();

    match event {
        ManagementEvent::AuthPrompt => {
            emit(event_tx, VpnEvent::AuthPromptReceived);
            match (&state.active_state_id, &state.saml_response) {
                (Some(state_id), Some(response)) => {
                    tracing::debug!(
                        "received repeated OpenVPN auth prompt; replaying SAML response"
                    );
                    send_saml_response(management, state_id, response).await?;
                }
                _ => {
                    tracing::debug!("received OpenVPN auth prompt");
                    management.send(&auth_username()).await?;
                    management.send(&acs_password(acs_port)).await?;
                }
            }
        }
        ManagementEvent::SamlChallenge(challenge) => {
            if state.active_state_id.as_deref() == Some(challenge.state_id.as_str())
                && state.saml_response.is_some()
            {
                tracing::debug!("ignoring duplicate SAML challenge after response was sent");
                return Ok(None);
            }

            tracing::info!("received SAML challenge from VPN endpoint");
            emit(event_tx, VpnEvent::SamlChallengeReceived);
            if print_login_url {
                emit(
                    event_tx,
                    VpnEvent::SamlLoginUrl {
                        url: challenge.url.to_string(),
                    },
                );
            }
            if open_browser(&challenge.url, browser)? == BrowserOpenResult::Opened {
                emit(event_tx, VpnEvent::BrowserOpened);
            }
            tracing::debug!("waiting for SAML assertion callback");
            let assertion = acs.receive_once().await?;
            tracing::debug!("received SAML assertion callback");
            emit(event_tx, VpnEvent::SamlAssertionReceived);
            tracing::debug!("sending SAML assertion response to OpenVPN");
            let response = assertion.expose_for_openvpn().to_string();
            send_saml_response(management, &challenge.state_id, &response).await?;
            state.active_state_id = Some(challenge.state_id);
            state.saml_response = Some(response);
        }
        ManagementEvent::Connected { vpn_ip } => {
            let outcome = SamlAuthOutcome {
                vpn_ip,
                dns_servers: state.dns_servers.clone(),
                routes: state.routes.clone(),
            };
            state.active_state_id = None;
            state.saml_response = None;
            return Ok(Some(outcome));
        }
        ManagementEvent::AuthFailed(message) => return Err(Error::AuthFailed(message)),
        ManagementEvent::Fatal(message) => return Err(Error::FatalOpenVpn(message)),
        ManagementEvent::Reconnecting { reason } => {
            emit(
                event_tx,
                VpnEvent::Reconnecting {
                    reason: reason.clone(),
                },
            );
            if reason.as_deref() == Some("auth-failure") {
                if allow_auth_failure_reconnect || state.active_state_id.is_some() {
                    tracing::debug!(
                        "releasing management hold after auth-failure reconnect during SAML flow"
                    );
                    management.send(&ManagementCommand::HoldRelease).await?;
                } else {
                    return Err(Error::AuthFailed("auth-failure".to_string()));
                }
            }
        }
        ManagementEvent::Log(message) => {
            if let Some(options) = parse_pushed_options(&message) {
                tracing::debug!(
                    dns_servers = ?options.dns_servers,
                    routes = ?options.routes,
                    "captured pushed options"
                );
                state.dns_servers = options.dns_servers;
                state.routes = options.routes;
            }
        }
        ManagementEvent::Ignored => {}
    }

    Ok(None)
}

pub(crate) async fn send_saml_response(
    management: &mut ManagementClient,
    state_id: &str,
    saml_response: &str,
) -> Result<()> {
    management.send(&auth_username()).await?;
    management
        .send(&saml_response_password(state_id, saml_response))
        .await
}

fn emit(event_tx: &Option<mpsc::UnboundedSender<VpnEvent>>, event: VpnEvent) {
    if let Some(event_tx) = event_tx {
        let _ = event_tx.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::acs::SamlAcsServer;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn drives_complete_saml_management_flow() {
        let acs = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let acs_addr = acs.local_addr().unwrap();

        let management_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let management_addr = management_listener.local_addr().unwrap();

        let fake_openvpn = tokio::spawn(async move {
            let (stream, _) = management_listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);

            expect_line(&mut stream, "state on").await;
            expect_line(&mut stream, "log on").await;
            expect_line(&mut stream, "echo on").await;
            expect_line(&mut stream, "hold release").await;

            stream
                .get_mut()
                .write_all(b">PASSWORD:Need 'Auth' username/password\n")
                .await
                .unwrap();
            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                &format!("password \"Auth\" ACS::{}", acs_addr.port()),
            )
            .await;

            stream
                .get_mut()
                .write_all(
                    b">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:state123:b'Ti9B':https://idp.example.com/saml']\n",
                )
                .await
                .unwrap();

            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                "password \"Auth\" CRV1::state123::assertion-value",
            )
            .await;

            stream
                .get_mut()
                .write_all(b">STATE:123,CONNECTED,SUCCESS,10.0.0.10,1.2.3.4,443,,\n")
                .await
                .unwrap();
        });

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let mut management = ManagementClient::connect(management_addr).await.unwrap();
        let client_flow = tokio::spawn(async move {
            drive_saml_auth(
                &mut management,
                &acs,
                BrowserMode::Disabled,
                true,
                Some(event_tx),
            )
            .await
        });

        post_saml_response(acs_addr, "assertion-value").await;

        let outcome = client_flow.await.unwrap().unwrap();
        fake_openvpn.await.unwrap();

        assert_eq!(outcome.vpn_ip, Some("10.0.0.10".parse().unwrap()));
        let mut saw_login_url = false;
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_millis(10), event_rx.recv()).await
        {
            if matches!(event, VpnEvent::SamlLoginUrl { url } if url == "https://idp.example.com/saml")
            {
                saw_login_url = true;
            }
        }
        assert!(saw_login_url);
    }

    #[tokio::test]
    async fn ignores_auth_failure_reconnect_after_saml_challenge() {
        let acs = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let acs_addr = acs.local_addr().unwrap();

        let management_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let management_addr = management_listener.local_addr().unwrap();

        let fake_openvpn = tokio::spawn(async move {
            let (stream, _) = management_listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);

            expect_line(&mut stream, "state on").await;
            expect_line(&mut stream, "log on").await;
            expect_line(&mut stream, "echo on").await;
            expect_line(&mut stream, "hold release").await;

            stream
                .get_mut()
                .write_all(b">PASSWORD:Need 'Auth' username/password\n")
                .await
                .unwrap();
            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                &format!("password \"Auth\" ACS::{}", acs_addr.port()),
            )
            .await;

            stream
                .get_mut()
                .write_all(
                    b">LOG:1,,AUTH: Received control message: AUTH_FAILED,CRV1:R:state123:b'Ti9B':https://idp.example.com/saml\n",
                )
                .await
                .unwrap();
            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                "password \"Auth\" CRV1::state123::assertion-value",
            )
            .await;

            stream
                .get_mut()
                .write_all(b">STATE:1,RECONNECTING,auth-failure,,,,,\n")
                .await
                .unwrap();
            expect_line(&mut stream, "hold release").await;

            stream
                .get_mut()
                .write_all(b">STATE:123,CONNECTED,SUCCESS,10.0.0.10,1.2.3.4,443,,\n")
                .await
                .unwrap();
        });

        let mut management = ManagementClient::connect(management_addr).await.unwrap();
        let client_flow = tokio::spawn(async move {
            drive_saml_auth(&mut management, &acs, BrowserMode::Disabled, false, None).await
        });

        post_saml_response(acs_addr, "assertion-value").await;

        let outcome = client_flow.await.unwrap().unwrap();
        fake_openvpn.await.unwrap();

        assert_eq!(outcome.vpn_ip, Some("10.0.0.10".parse().unwrap()));
    }

    #[tokio::test]
    async fn ignores_duplicate_saml_challenge_after_assertion_callback() {
        let acs = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let acs_addr = acs.local_addr().unwrap();

        let management_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let management_addr = management_listener.local_addr().unwrap();

        let fake_openvpn = tokio::spawn(async move {
            let (stream, _) = management_listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);

            expect_line(&mut stream, "state on").await;
            expect_line(&mut stream, "log on").await;
            expect_line(&mut stream, "echo on").await;
            expect_line(&mut stream, "hold release").await;

            stream
                .get_mut()
                .write_all(b">PASSWORD:Need 'Auth' username/password\n")
                .await
                .unwrap();
            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                &format!("password \"Auth\" ACS::{}", acs_addr.port()),
            )
            .await;

            let challenge =
                b">LOG:1,,AUTH: Received control message: AUTH_FAILED,CRV1:R:state123:b'Ti9B':https://idp.example.com/saml\n";
            stream.get_mut().write_all(challenge).await.unwrap();
            stream.get_mut().write_all(challenge).await.unwrap();
            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                "password \"Auth\" CRV1::state123::assertion-value",
            )
            .await;

            stream
                .get_mut()
                .write_all(b">STATE:1,RECONNECTING,auth-failure,,,,,\n")
                .await
                .unwrap();
            expect_line(&mut stream, "hold release").await;

            stream
                .get_mut()
                .write_all(b">STATE:123,CONNECTED,SUCCESS,10.0.0.10,1.2.3.4,443,,\n")
                .await
                .unwrap();
        });

        let mut management = ManagementClient::connect(management_addr).await.unwrap();
        let client_flow = tokio::spawn(async move {
            drive_saml_auth(&mut management, &acs, BrowserMode::Disabled, false, None).await
        });

        post_saml_response(acs_addr, "assertion-value").await;

        let outcome = client_flow.await.unwrap().unwrap();
        fake_openvpn.await.unwrap();

        assert_eq!(outcome.vpn_ip, Some("10.0.0.10".parse().unwrap()));
    }

    #[tokio::test]
    async fn replays_saml_response_when_openvpn_prompts_after_reconnect() {
        let acs = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let acs_addr = acs.local_addr().unwrap();

        let management_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let management_addr = management_listener.local_addr().unwrap();

        let fake_openvpn = tokio::spawn(async move {
            let (stream, _) = management_listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);

            expect_line(&mut stream, "state on").await;
            expect_line(&mut stream, "log on").await;
            expect_line(&mut stream, "echo on").await;
            expect_line(&mut stream, "hold release").await;

            stream
                .get_mut()
                .write_all(b">PASSWORD:Need 'Auth' username/password\n")
                .await
                .unwrap();
            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                &format!("password \"Auth\" ACS::{}", acs_addr.port()),
            )
            .await;

            stream
                .get_mut()
                .write_all(
                    b">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:state123:b'Ti9B':https://idp.example.com/saml']\n",
                )
                .await
                .unwrap();
            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                "password \"Auth\" CRV1::state123::assertion-value",
            )
            .await;

            stream
                .get_mut()
                .write_all(b">STATE:1,RECONNECTING,auth-failure,,,,,\n")
                .await
                .unwrap();
            expect_line(&mut stream, "hold release").await;

            stream
                .get_mut()
                .write_all(b">PASSWORD:Need 'Auth' username/password\n")
                .await
                .unwrap();
            expect_line(&mut stream, "username \"Auth\" N/A").await;
            expect_line(
                &mut stream,
                "password \"Auth\" CRV1::state123::assertion-value",
            )
            .await;

            stream
                .get_mut()
                .write_all(b">STATE:123,CONNECTED,SUCCESS,10.0.0.10,1.2.3.4,443,,\n")
                .await
                .unwrap();
        });

        let mut management = ManagementClient::connect(management_addr).await.unwrap();
        let client_flow = tokio::spawn(async move {
            drive_saml_auth(&mut management, &acs, BrowserMode::Disabled, false, None).await
        });

        post_saml_response(acs_addr, "assertion-value").await;

        let outcome = client_flow.await.unwrap().unwrap();
        fake_openvpn.await.unwrap();

        assert_eq!(outcome.vpn_ip, Some("10.0.0.10".parse().unwrap()));
    }

    #[tokio::test]
    async fn maps_fatal_management_event_to_error() {
        let acs = SamlAcsServer::bind_localhost(0, Duration::from_secs(5))
            .await
            .unwrap();
        let management_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let management_addr = management_listener.local_addr().unwrap();

        let fake_openvpn = tokio::spawn(async move {
            let (mut stream, _) = management_listener.accept().await.unwrap();
            stream.write_all(b">FATAL:bad tun\n").await.unwrap();
        });

        let mut management = ManagementClient::connect(management_addr).await.unwrap();
        let err = drive_saml_auth(&mut management, &acs, BrowserMode::Disabled, false, None)
            .await
            .unwrap_err();

        fake_openvpn.await.unwrap();
        assert!(matches!(err, Error::FatalOpenVpn(message) if message == "bad tun"));
    }

    async fn expect_line(reader: &mut BufReader<TcpStream>, expected: &str) {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line.trim_end(), expected);
    }

    async fn post_saml_response(addr: std::net::SocketAddr, assertion: &str) {
        let body = format!("SAMLResponse={assertion}");
        let request = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
    }
}
