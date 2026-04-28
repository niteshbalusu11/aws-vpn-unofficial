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

    match mode {
        BrowserMode::System => {
            tracing::info!("opening SAML login URL in default browser");
            open_system_browser(url.as_str()).map_err(Error::BrowserLaunchFailed)?;
        }
        BrowserMode::Specific(browser) => {
            tracing::info!(?browser, "opening SAML login URL in requested browser");
            webbrowser::open_browser(browser, url.as_str()).map_err(Error::BrowserLaunchFailed)?;
        }
        BrowserMode::Disabled => unreachable!("disabled browser mode returned before opening"),
    }

    Ok(BrowserOpenResult::Opened)
}

#[cfg(not(target_os = "linux"))]
fn open_system_browser(url: &str) -> std::io::Result<()> {
    webbrowser::open(url)
}

#[cfg(target_os = "linux")]
fn open_system_browser(url: &str) -> std::io::Result<()> {
    let mut last_error = None;
    for browser in ["/snap/bin/brave", "brave", "brave-browser", "xdg-open"] {
        tracing::debug!(program = browser, "trying browser launcher");
        match spawn_linux_browser(browser, url) {
            Ok(()) => return Ok(()),
            Err(err) => {
                tracing::debug!(program = browser, error = %err, "browser launcher failed");
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no browser launcher found")
    }))
}

#[cfg(target_os = "linux")]
fn spawn_linux_browser(browser: &str, url: &str) -> std::io::Result<()> {
    let mut command = std::process::Command::new(browser);
    command
        .arg(url)
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin",
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    apply_sudo_user(&mut command);
    command.spawn().map(|_| ())
}

#[cfg(target_os = "linux")]
fn apply_sudo_user(command: &mut std::process::Command) {
    let Ok(uid) = std::env::var("SUDO_UID").and_then(|value| {
        value
            .parse::<u32>()
            .map_err(|_| std::env::VarError::NotPresent)
    }) else {
        return;
    };

    use std::os::unix::process::CommandExt;

    tracing::debug!(uid, "running browser launcher as sudo desktop user");
    command.uid(uid);
    if let Ok(gid) = std::env::var("SUDO_GID").and_then(|value| {
        value
            .parse::<u32>()
            .map_err(|_| std::env::VarError::NotPresent)
    }) {
        command.gid(gid);
    }
    command.env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"));
    command.env(
        "DBUS_SESSION_BUS_ADDRESS",
        format!("unix:path=/run/user/{uid}/bus"),
    );
    if let Some(value) = std::env::var_os("DISPLAY") {
        command.env("DISPLAY", value);
    }
    if let Some(value) = std::env::var_os("WAYLAND_DISPLAY") {
        command.env("WAYLAND_DISPLAY", value);
    }
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
