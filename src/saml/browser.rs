use crate::{BrowserMode, Error, Result};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserOpenResult {
    Opened,
    Disabled,
}

pub fn open_browser(url: &Url, mode: BrowserMode) -> Result<BrowserOpenResult> {
    if mode == BrowserMode::Disabled {
        return Ok(BrowserOpenResult::Disabled);
    }

    tracing::info!("opening SAML login URL in default browser");
    webbrowser::open(url.as_str()).map_err(Error::BrowserLaunchFailed)?;

    Ok(BrowserOpenResult::Opened)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_mode_does_not_launch() {
        let url = Url::parse("https://idp.example.com/saml").unwrap();
        let result = open_browser(&url, BrowserMode::Disabled).unwrap();

        assert_eq!(result, BrowserOpenResult::Disabled);
    }
}
