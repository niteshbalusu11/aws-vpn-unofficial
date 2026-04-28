#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementCommand {
    StateOn,
    LogOn,
    EchoOn,
    HoldRelease,
    Username { name: String, value: String },
    Password { name: String, value: String },
    Signal(String),
    Quit,
}

impl ManagementCommand {
    pub fn line(&self) -> String {
        match self {
            Self::StateOn => "state on".to_string(),
            Self::LogOn => "log on".to_string(),
            Self::EchoOn => "echo on".to_string(),
            Self::HoldRelease => "hold release".to_string(),
            Self::Username { name, value } => {
                format!("username {} {}", quote(name), quote_if_needed(value))
            }
            Self::Password { name, value } => {
                format!("password {} {}", quote(name), quote_if_needed(value))
            }
            Self::Signal(signal) => format!("signal {}", quote_if_needed(signal)),
            Self::Quit => "quit".to_string(),
        }
    }
}

pub fn auth_username() -> ManagementCommand {
    ManagementCommand::Username {
        name: "Auth".to_string(),
        value: "N/A".to_string(),
    }
}

pub fn acs_password(port: u16) -> ManagementCommand {
    ManagementCommand::Password {
        name: "Auth".to_string(),
        value: format!("ACS::{port}"),
    }
}

pub fn saml_response_password(state_id: &str, saml_response: &str) -> ManagementCommand {
    ManagementCommand::Password {
        name: "Auth".to_string(),
        value: format!("CRV1::{state_id}::{saml_response}"),
    }
}

fn quote_if_needed(value: &str) -> String {
    if value.bytes().all(is_unquoted_byte) && !value.is_empty() {
        value.to_string()
    } else {
        quote(value)
    }
}

fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn is_unquoted_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() && byte != b'"' && byte != b'\\'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_initial_saml_auth_commands() {
        assert_eq!(auth_username().line(), "username \"Auth\" N/A");
        assert_eq!(acs_password(35001).line(), "password \"Auth\" ACS::35001");
    }

    #[test]
    fn formats_saml_response_password() {
        let command = saml_response_password("state123", "assertion");
        assert_eq!(
            command.line(),
            "password \"Auth\" CRV1::state123::assertion"
        );
    }

    #[test]
    fn quotes_values_with_spaces() {
        let command = ManagementCommand::Password {
            name: "Auth".to_string(),
            value: "value with spaces".to_string(),
        };

        assert_eq!(command.line(), "password \"Auth\" \"value with spaces\"");
    }

    #[test]
    fn escapes_quoted_values() {
        let command = ManagementCommand::Username {
            name: "A\"uth".to_string(),
            value: "N\\A".to_string(),
        };

        assert_eq!(command.line(), "username \"A\\\"uth\" \"N\\\\A\"");
    }
}
