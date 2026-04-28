const REDACTED: &str = "[REDACTED]";

pub fn redact_line(line: &str) -> String {
    let line = redact_auth_password_command(line);
    let line = redact_saml_response_param(&line);
    redact_crv1_assertion(&line)
}

fn redact_auth_password_command(line: &str) -> String {
    let Some(start) = line.find("password \"Auth\" ") else {
        return line.to_string();
    };

    let prefix_end = start + "password \"Auth\" ".len();
    let mut redacted = String::with_capacity(prefix_end + REDACTED.len());
    redacted.push_str(&line[..prefix_end]);
    redacted.push_str(REDACTED);
    redacted
}

fn redact_saml_response_param(line: &str) -> String {
    redact_query_like_value(line, "SAMLResponse=")
}

fn redact_crv1_assertion(line: &str) -> String {
    let Some(start) = line.find("CRV1::") else {
        return line.to_string();
    };

    let after_prefix = start + "CRV1::".len();
    let Some(relative_sep) = line[after_prefix..].find("::") else {
        return line.to_string();
    };
    let assertion_start = after_prefix + relative_sep + "::".len();

    let mut redacted = String::with_capacity(assertion_start + REDACTED.len());
    redacted.push_str(&line[..assertion_start]);
    redacted.push_str(REDACTED);
    redacted
}

fn redact_query_like_value(line: &str, key: &str) -> String {
    let Some(start) = line.find(key) else {
        return line.to_string();
    };

    let value_start = start + key.len();
    let value_end = line[value_start..]
        .find('&')
        .map(|offset| value_start + offset)
        .unwrap_or(line.len());

    let mut redacted = String::with_capacity(line.len() + REDACTED.len());
    redacted.push_str(&line[..value_start]);
    redacted.push_str(REDACTED);
    redacted.push_str(&line[value_end..]);
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_auth_password_command() {
        let line = "password \"Auth\" CRV1::state::very-secret-assertion";
        assert_eq!(redact_line(line), "password \"Auth\" [REDACTED]");
    }

    #[test]
    fn redacts_saml_response_form_param() {
        let line = "RelayState=abc&SAMLResponse=very-secret-assertion&other=value";
        assert_eq!(
            redact_line(line),
            "RelayState=abc&SAMLResponse=[REDACTED]&other=value"
        );
    }

    #[test]
    fn redacts_crv1_assertion() {
        let line = "auth failed CRV1::state123::very-secret-assertion";
        assert_eq!(redact_line(line), "auth failed CRV1::state123::[REDACTED]");
    }
}
