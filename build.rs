use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn main() {
    let target = env::var("TARGET").expect("TARGET is set by Cargo");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let generated = out_dir.join("bundled_runtime.rs");
    let runtime_dir = PathBuf::from("assets")
        .join("openvpn-runtime")
        .join(&target)
        .join("openvpn");

    println!("cargo:rerun-if-changed=assets/openvpn-runtime");

    let result = if runtime_dir.is_dir() {
        generate_runtime(&target, &runtime_dir)
    } else {
        Ok(format!(
            "pub(crate) const BUNDLED_RUNTIME: Option<crate::runtime::BundledRuntime> = None;\n\
             pub(crate) const BUNDLED_RUNTIME_TARGET: &str = {target:?};\n"
        ))
    };

    match result {
        Ok(contents) => fs::write(generated, contents).expect("write bundled runtime module"),
        Err(err) => panic!("could not generate bundled runtime module: {err}"),
    }
}

fn generate_runtime(target: &str, runtime_dir: &Path) -> io::Result<String> {
    let mut files = Vec::new();
    collect_files(runtime_dir, runtime_dir, &mut files)?;
    files.sort_by(|left, right| left.relative.cmp(&right.relative));

    let mut hash = FNV_OFFSET;
    for file in &files {
        hash_bytes(&mut hash, file.relative.as_bytes());
        hash_bytes(&mut hash, &fs::read(&file.absolute)?);
    }
    let id = format!("{hash:016x}");

    let mut output = String::new();
    output.push_str(&format!(
        "pub(crate) const BUNDLED_RUNTIME_TARGET: &str = {target:?};\n"
    ));
    output.push_str(
        "pub(crate) const BUNDLED_RUNTIME: Option<crate::runtime::BundledRuntime> = Some(crate::runtime::BundledRuntime {\n",
    );
    output.push_str(&format!("    target: {target:?},\n"));
    output.push_str(&format!("    id: {id:?},\n"));
    output.push_str("    files: &[\n");

    for file in files {
        output.push_str("        crate::runtime::BundledRuntimeFile {\n");
        output.push_str(&format!(
            "            relative_path: {:?},\n",
            file.relative
        ));
        output.push_str(&format!(
            "            bytes: include_bytes!({:?}),\n",
            file.absolute.display().to_string()
        ));
        output.push_str(&format!("            executable: {},\n", file.executable));
        output.push_str("        },\n");
    }

    output.push_str("    ],\n");
    output.push_str("});\n");
    Ok(output)
}

fn collect_files(root: &Path, dir: &Path, files: &mut Vec<RuntimeFile>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files)?;
            continue;
        }
        if !path.is_file() {
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .expect("collected path is under root")
            .to_string_lossy()
            .replace('\\', "/");
        let executable = is_executable(&path, &relative)?;

        files.push(RuntimeFile {
            absolute: fs::canonicalize(path)?,
            relative,
            executable,
        });
    }

    Ok(())
}

fn is_executable(path: &Path, relative: &str) -> io::Result<bool> {
    if matches!(relative, "acvc-openvpn" | "client.up" | "client.down") {
        return Ok(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(fs::metadata(path)?.permissions().mode() & 0o111 != 0)
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(false)
    }
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}

struct RuntimeFile {
    absolute: PathBuf,
    relative: String,
    executable: bool,
}
