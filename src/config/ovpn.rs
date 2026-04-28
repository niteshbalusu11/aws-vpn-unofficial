use crate::{Error, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OvpnConfigSummary {
    pub remotes: Vec<Remote>,
    pub has_auth_user_pass: bool,
    pub has_auth_federate: bool,
}

impl OvpnConfigSummary {
    pub fn parse_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|err| {
            Error::InvalidConfig(format!("could not read {}: {err}", path.display()))
        })?;
        Self::parse(&contents)
    }

    pub fn parse(contents: &str) -> Result<Self> {
        let mut remotes = Vec::new();
        let mut has_auth_user_pass = false;
        let mut has_auth_federate = false;

        for raw_line in contents.lines() {
            let Some(line) = clean_line(raw_line) else {
                continue;
            };

            let mut fields = line.split_whitespace();
            let Some(key) = fields.next() else {
                continue;
            };

            match key {
                "remote" => {
                    let host = fields.next().ok_or_else(|| {
                        Error::InvalidConfig("remote directive is missing host".to_string())
                    })?;
                    let port = fields.next().ok_or_else(|| {
                        Error::InvalidConfig("remote directive is missing port".to_string())
                    })?;
                    let port = port.parse::<u16>().map_err(|err| {
                        Error::InvalidConfig(format!("invalid remote port '{port}': {err}"))
                    })?;
                    remotes.push(Remote {
                        host: host.to_string(),
                        port,
                    });
                }
                "auth-user-pass" => has_auth_user_pass = true,
                "auth-federate" => has_auth_federate = true,
                _ => {}
            }
        }

        Ok(Self {
            remotes,
            has_auth_user_pass,
            has_auth_federate,
        })
    }

    pub fn supports_saml_auth_flow(&self) -> bool {
        self.has_auth_user_pass || self.has_auth_federate
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub host: String,
    pub port: u16,
}

fn clean_line(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aws_client_vpn_config_summary() {
        let config = r#"
client
dev tun
proto udp
remote cvpn-endpoint-123.prod.clientvpn.us-east-1.amazonaws.com 443
remote-random-hostname
auth-user-pass
auth-retry interact
"#;

        let summary = OvpnConfigSummary::parse(config).unwrap();

        assert_eq!(
            summary.remotes,
            vec![Remote {
                host: "cvpn-endpoint-123.prod.clientvpn.us-east-1.amazonaws.com".to_string(),
                port: 443
            }]
        );
        assert!(summary.has_auth_user_pass);
        assert!(!summary.has_auth_federate);
        assert!(summary.supports_saml_auth_flow());
    }

    #[test]
    fn parses_auth_federate_config() {
        let summary = OvpnConfigSummary::parse(
            r#"
remote example.com 443
auth-federate
"#,
        )
        .unwrap();

        assert!(summary.has_auth_federate);
        assert!(summary.supports_saml_auth_flow());
    }

    #[test]
    fn rejects_remote_without_port() {
        let err = OvpnConfigSummary::parse("remote example.com").unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn rejects_invalid_remote_port() {
        let err = OvpnConfigSummary::parse("remote example.com nope").unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
