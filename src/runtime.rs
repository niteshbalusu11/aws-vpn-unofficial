use crate::{Error, Result};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenVpnRuntime {
    Bundled,
    External(PathBuf),
}

impl OpenVpnRuntime {
    pub fn external(path: impl Into<PathBuf>) -> Self {
        Self::External(path.into())
    }
}

#[derive(Debug)]
pub(crate) struct RuntimeDeployment {
    binary: PathBuf,
    _tempdir: Option<TempDir>,
}

impl RuntimeDeployment {
    pub(crate) fn binary(&self) -> &Path {
        &self.binary
    }

    pub(crate) fn external(path: PathBuf) -> Self {
        Self {
            binary: path,
            _tempdir: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct BundledRuntime {
    pub(crate) target: &'static str,
    pub(crate) id: &'static str,
    pub(crate) files: &'static [BundledRuntimeFile],
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct BundledRuntimeFile {
    pub(crate) relative_path: &'static str,
    pub(crate) bytes: &'static [u8],
    pub(crate) executable: bool,
}

include!(concat!(env!("OUT_DIR"), "/bundled_runtime.rs"));

pub fn bundled_runtime_target() -> &'static str {
    BUNDLED_RUNTIME_TARGET
}

pub fn bundled_runtime_available() -> bool {
    BUNDLED_RUNTIME.is_some()
}

pub(crate) fn deploy_openvpn_runtime(runtime: &OpenVpnRuntime) -> Result<RuntimeDeployment> {
    match runtime {
        OpenVpnRuntime::External(path) => Ok(RuntimeDeployment::external(path.clone())),
        OpenVpnRuntime::Bundled => {
            let runtime = BUNDLED_RUNTIME.ok_or(Error::BundledOpenVpnUnavailable {
                target: BUNDLED_RUNTIME_TARGET,
            })?;
            extract_bundled_runtime(runtime)
        }
    }
}

fn extract_bundled_runtime(runtime: BundledRuntime) -> Result<RuntimeDeployment> {
    let tempdir = tempfile::Builder::new()
        .prefix("awsvpn-openvpn-")
        .tempdir()
        .map_err(Error::TempFile)?;
    let runtime_dir = tempdir.path().join("openvpn");

    for file in runtime.files {
        let destination = checked_destination(&runtime_dir, file.relative_path)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(Error::TempFile)?;
        }

        let mut output = fs::File::create(&destination).map_err(Error::TempFile)?;
        output.write_all(file.bytes).map_err(Error::TempFile)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if file.executable { 0o755 } else { 0o644 };
            fs::set_permissions(&destination, fs::Permissions::from_mode(mode))
                .map_err(Error::TempFile)?;
        }
    }

    let binary = runtime_dir.join("acvc-openvpn");
    if !binary.is_file() {
        return Err(Error::BundledOpenVpnInvalid(
            "bundled runtime did not contain acvc-openvpn".to_string(),
        ));
    }

    tracing::debug!(
        target = runtime.target,
        id = runtime.id,
        path = %binary.display(),
        "extracted bundled OpenVPN runtime"
    );

    Ok(RuntimeDeployment {
        binary,
        _tempdir: Some(tempdir),
    })
}

fn checked_destination(root: &Path, relative_path: &str) -> Result<PathBuf> {
    let relative = Path::new(relative_path);
    if relative.is_absolute() {
        return Err(Error::BundledOpenVpnInvalid(format!(
            "bundled runtime path is absolute: {relative_path}"
        )));
    }

    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(Error::BundledOpenVpnInvalid(format!(
                "bundled runtime path is invalid: {relative_path}"
            )));
        }
    }

    Ok(root.join(relative))
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_RUNTIME: BundledRuntime = BundledRuntime {
        target: "test-target",
        id: "test-id",
        files: &[
            BundledRuntimeFile {
                relative_path: "acvc-openvpn",
                bytes: b"#!/bin/sh\n",
                executable: true,
            },
            BundledRuntimeFile {
                relative_path: "client.up",
                bytes: b"#!/bin/sh\n",
                executable: true,
            },
        ],
    };

    #[test]
    fn extracts_bundled_runtime_to_tempdir() {
        let deployment = extract_bundled_runtime(TEST_RUNTIME).unwrap();
        assert!(deployment.binary().is_file());
        assert_eq!(
            fs::read_to_string(deployment.binary()).unwrap(),
            "#!/bin/sh\n"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(deployment.binary())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755);
        }
    }

    #[test]
    fn rejects_invalid_bundled_runtime_paths() {
        let err = checked_destination(Path::new("/tmp/root"), "../acvc-openvpn").unwrap_err();
        assert!(matches!(err, Error::BundledOpenVpnInvalid(_)));
    }
}
