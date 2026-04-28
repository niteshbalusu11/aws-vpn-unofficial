use crate::{BrowserMode, Error, Result};
use std::process::Command;
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

    let mut command = browser_command(url);
    command
        .spawn()
        .map_err(Error::BrowserLaunchFailed)?
        .wait()
        .map_err(Error::BrowserLaunchFailed)?;

    Ok(BrowserOpenResult::Opened)
}

#[cfg(target_os = "macos")]
fn browser_command(url: &Url) -> Command {
    let mut command = Command::new("open");
    command.arg(url.as_str());
    command
}

#[cfg(target_os = "linux")]
fn browser_command(url: &Url) -> Command {
    let mut command = Command::new("xdg-open");
    command.arg(url.as_str());
    command
}

#[cfg(target_os = "windows")]
fn browser_command(url: &Url) -> Command {
    let mut command = Command::new("rundll32");
    command.arg("url.dll,FileProtocolHandler").arg(url.as_str());
    command
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn browser_command(url: &Url) -> Command {
    let mut command = Command::new("xdg-open");
    command.arg(url.as_str());
    command
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
