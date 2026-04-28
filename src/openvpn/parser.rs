use crate::{Error, Result};
use std::net::IpAddr;
use url::Url;

const AUTH_PROMPT: &str = ">PASSWORD:Need 'Auth' username/password";
const CRV1_PREFIX: &str = ">PASSWORD:Verification Failed: 'Auth' ['";
const CRV1_SUFFIX: &str = "']";
const CRV1_INNER_PREFIX: &str = "CRV1:R:";
const CRV1_STATE_SENTINEL: &str = ":b'Ti9B':";
const AUTH_FAILED_CRV1_PREFIX: &str = "AUTH_FAILED,CRV1:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementEvent {
    AuthPrompt,
    SamlChallenge(SamlChallenge),
    Connected { vpn_ip: Option<IpAddr> },
    Reconnecting { reason: Option<String> },
    AuthFailed(String),
    Fatal(String),
    Log(String),
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlChallenge {
    pub state_id: String,
    pub url: Url,
}

pub fn parse_management_line(line: &str) -> Result<ManagementEvent> {
    if line == AUTH_PROMPT {
        return Ok(ManagementEvent::AuthPrompt);
    }

    if line.starts_with(CRV1_PREFIX) {
        return parse_crv1_challenge(line).map(ManagementEvent::SamlChallenge);
    }

    if line.contains(AUTH_FAILED_CRV1_PREFIX) {
        return parse_auth_failed_crv1_challenge(line).map(ManagementEvent::SamlChallenge);
    }

    if let Some(event) = parse_state(line) {
        return Ok(event);
    }

    if let Some(message) = line.strip_prefix(">FATAL:") {
        return Ok(ManagementEvent::Fatal(message.trim().to_string()));
    }

    if line.contains("AUTH_FAILED") {
        return Ok(ManagementEvent::AuthFailed(line.to_string()));
    }

    if let Some(message) = line.strip_prefix(">LOG:") {
        return Ok(ManagementEvent::Log(message.to_string()));
    }

    Ok(ManagementEvent::Ignored)
}

pub fn parse_crv1_challenge(line: &str) -> Result<SamlChallenge> {
    let inner = line
        .strip_prefix(CRV1_PREFIX)
        .and_then(|value| value.strip_suffix(CRV1_SUFFIX))
        .ok_or_else(|| Error::ManagementProtocol("malformed CRV1 challenge wrapper".to_string()))?;

    parse_crv1_body(inner)
}

pub fn parse_auth_failed_crv1_challenge(line: &str) -> Result<SamlChallenge> {
    let start = line.find(AUTH_FAILED_CRV1_PREFIX).ok_or_else(|| {
        Error::ManagementProtocol("AUTH_FAILED CRV1 challenge is missing".to_string())
    })?;
    let body = &line[start + "AUTH_FAILED,".len()..];
    parse_crv1_body(body)
}

fn parse_crv1_body(body: &str) -> Result<SamlChallenge> {
    let body = body.strip_prefix(CRV1_INNER_PREFIX).ok_or_else(|| {
        Error::ManagementProtocol("CRV1 challenge is not response-required".to_string())
    })?;

    let Some((state_id, raw_url)) = body.split_once(CRV1_STATE_SENTINEL) else {
        return Err(Error::ManagementProtocol(
            "CRV1 challenge is missing state or URL".to_string(),
        ));
    };

    if state_id.is_empty() {
        return Err(Error::ManagementProtocol(
            "CRV1 challenge state is empty".to_string(),
        ));
    }

    let url = validate_saml_url(raw_url)?;

    Ok(SamlChallenge {
        state_id: state_id.to_string(),
        url,
    })
}

pub fn validate_saml_url(raw_url: &str) -> Result<Url> {
    let url = Url::parse(raw_url).map_err(|err| Error::InvalidSamlUrl(err.to_string()))?;

    if url.scheme() != "https" {
        return Err(Error::InvalidSamlUrl(
            "expected an absolute https URL".to_string(),
        ));
    }

    if url.host_str().is_none() {
        return Err(Error::InvalidSamlUrl(
            "expected SAML URL to include a host".to_string(),
        ));
    }

    Ok(url)
}

fn parse_state(line: &str) -> Option<ManagementEvent> {
    let payload = line.strip_prefix(">STATE:")?;
    let fields = payload.split(',').collect::<Vec<_>>();
    let state = fields.get(1)?;

    match *state {
        "CONNECTED" if fields.get(2) == Some(&"SUCCESS") => {
            let vpn_ip = fields.get(3).and_then(|value| value.parse::<IpAddr>().ok());
            Some(ManagementEvent::Connected { vpn_ip })
        }
        "RECONNECTING" => {
            let reason = fields
                .get(2)
                .filter(|value| !value.is_empty())
                .map(|value| (*value).to_string());
            Some(ManagementEvent::Reconnecting { reason })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_auth_prompt() {
        let event = parse_management_line(">PASSWORD:Need 'Auth' username/password").unwrap();
        assert_eq!(event, ManagementEvent::AuthPrompt);
    }

    #[test]
    fn parses_crv1_saml_challenge() {
        let event = parse_management_line(
            ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:state123:b'Ti9B':https://idp.example.com/saml?x=1']",
        )
        .unwrap();

        assert_eq!(
            event,
            ManagementEvent::SamlChallenge(SamlChallenge {
                state_id: "state123".to_string(),
                url: Url::parse("https://idp.example.com/saml?x=1").unwrap(),
            })
        );
    }

    #[test]
    fn parses_auth_failed_crv1_log_saml_challenge() {
        let event = parse_management_line(
            ">LOG:123,,AUTH: Received control message: AUTH_FAILED,CRV1:R:instance-2/abc/uuid:b'Ti9B':https://accounts.google.com/o/saml2/idp?SAMLRequest=abc%3D",
        )
        .unwrap();

        assert_eq!(
            event,
            ManagementEvent::SamlChallenge(SamlChallenge {
                state_id: "instance-2/abc/uuid".to_string(),
                url: Url::parse("https://accounts.google.com/o/saml2/idp?SAMLRequest=abc%3D")
                    .unwrap(),
            })
        );
    }

    #[test]
    fn rejects_non_https_crv1_url() {
        let err = parse_management_line(
            ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:state123:b'Ti9B':http://idp.example.com/saml']",
        )
        .unwrap_err();

        assert!(matches!(err, Error::InvalidSamlUrl(_)));
    }

    #[test]
    fn rejects_malformed_crv1_challenge() {
        let err = parse_management_line(
            ">PASSWORD:Verification Failed: 'Auth' ['CRV1:E:state123:b'Ti9B':https://idp.example.com/saml']",
        )
        .unwrap_err();

        assert!(matches!(err, Error::ManagementProtocol(_)));
    }

    #[test]
    fn parses_connected_state() {
        let event =
            parse_management_line(">STATE:123,CONNECTED,SUCCESS,10.0.0.10,1.2.3.4,443,,").unwrap();

        assert_eq!(
            event,
            ManagementEvent::Connected {
                vpn_ip: Some("10.0.0.10".parse().unwrap())
            }
        );
    }

    #[test]
    fn parses_reconnecting_state() {
        let event = parse_management_line(">STATE:123,RECONNECTING,auth-failure,,,,").unwrap();

        assert_eq!(
            event,
            ManagementEvent::Reconnecting {
                reason: Some("auth-failure".to_string())
            }
        );
    }

    #[test]
    fn parses_fatal_line() {
        let event = parse_management_line(">FATAL:cannot allocate tun").unwrap();
        assert_eq!(
            event,
            ManagementEvent::Fatal("cannot allocate tun".to_string())
        );
    }
}
