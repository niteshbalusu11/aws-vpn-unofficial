use crate::{Error, Result};
use std::env;
use std::path::{Path, PathBuf};

const OPENVPN_ENV: &str = "AWSVPN_OPENVPN";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnRuntime {
    pub binary: PathBuf,
    pub source: OpenVpnRuntimeSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenVpnRuntimeSource {
    Explicit,
    Environment,
    Bundled,
}

impl OpenVpnRuntime {
    pub fn discover(explicit: Option<&Path>) -> Result<Self> {
        if let Some(path) = explicit {
            return runtime_from_path(path, OpenVpnRuntimeSource::Explicit);
        }

        if let Some(path) = env::var_os(OPENVPN_ENV) {
            return runtime_from_path(Path::new(&path), OpenVpnRuntimeSource::Environment);
        }

        for candidate in bundled_candidates()? {
            if candidate.is_file() {
                return runtime_from_path(&candidate, OpenVpnRuntimeSource::Bundled);
            }
        }

        Err(Error::OpenVpnNotFound)
    }
}

pub fn bundled_candidates() -> Result<Vec<PathBuf>> {
    let exe = env::current_exe().map_err(Error::OpenVpnProcess)?;
    let exe_dir = exe.parent().ok_or_else(|| {
        Error::InvalidConfig(format!(
            "could not determine executable directory for {}",
            exe.display()
        ))
    })?;

    Ok(runtime_dirs(exe_dir)
        .into_iter()
        .flat_map(|dir| binary_names().into_iter().map(move |name| dir.join(name)))
        .collect())
}

fn runtime_dirs(exe_dir: &Path) -> Vec<PathBuf> {
    vec![
        exe_dir.join("openvpn"),
        exe_dir.join("resources").join("openvpn"),
        exe_dir.join("runtime").join("openvpn"),
        exe_dir.join("..").join("libexec").join("awsvpn").join("openvpn"),
    ]
}

fn binary_names() -> Vec<&'static str> {
    if cfg!(windows) {
        vec!["acvc-openvpn.exe", "openvpn.exe"]
    } else {
        vec!["acvc-openvpn", "openvpn"]
    }
}

fn runtime_from_path(path: &Path, source: OpenVpnRuntimeSource) -> Result<OpenVpnRuntime> {
    if !path.exists() {
        return Err(Error::InvalidConfig(format!(
            "OpenVPN binary does not exist: {}",
            path.display()
        )));
    }

    if !path.is_file() {
        return Err(Error::InvalidConfig(format!(
            "OpenVPN binary is not a file: {}",
            path.display()
        )));
    }

    Ok(OpenVpnRuntime {
        binary: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_path_wins() {
        let tempdir = tempfile::tempdir().unwrap();
        let binary = tempdir.path().join("acvc-openvpn");
        std::fs::write(&binary, "").unwrap();

        let runtime = OpenVpnRuntime::discover(Some(&binary)).unwrap();

        assert_eq!(runtime.binary, binary);
        assert_eq!(runtime.source, OpenVpnRuntimeSource::Explicit);
    }

    #[test]
    fn explicit_path_must_exist() {
        let err = OpenVpnRuntime::discover(Some(Path::new("/definitely/missing/openvpn")))
            .unwrap_err();

        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
