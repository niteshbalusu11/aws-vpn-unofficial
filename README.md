# AWS VPN Unofficial

Unofficial Rust library and CLI for AWS Client VPN SAML profiles.

This is not an official Amazon Web Services project. It is not affiliated with,
endorsed by, maintained by, or supported by AWS. Use it at your own risk; you are
responsible for reviewing the code, complying with your organization's security
policies, and validating that it is appropriate for your environment.

The crate is library-first. The `awsvpn` binary is a thin wrapper over public
types such as `VpnClient`, `ConnectOptions`, and `collect_diagnostics`.

## Install

From a GitHub release, download the `awsvpn` binary for your platform, place it
somewhere on your `PATH`, and run:

```bash
mkdir -p ~/.awsvpnunofficial
cp ~/path/to/your/config/file ~/.awsvpnunofficial/vpnconfig.ovpn
sudo awsvpn connect
```

To build from source:

```bash
git clone https://github.com/niteshbalusu11/aws-vpn-unofficial.git
cd aws-vpn-unofficial
cargo install --path .
sudo awsvpn connect
```

## Connect with the Bundled Runtime

Build as your normal user, then run only the built binary with `sudo`.
Do not use `sudo cargo run`: Cargo will compile as root, which loses the Nix
SDK/linker environment and can fail to find the macOS SDK or `libiconv`.

```bash
cargo build

sudo -E target/debug/awsvpn connect --debug
```

When no config path is passed, `connect` reads
`~/.awsvpnunofficial/vpnconfig.ovpn`. When run through `sudo`, the `~` resolves
to the invoking desktop user, not root.

By default, the CLI uses the AWS-patched OpenVPN runtime embedded in the Rust
binary. It extracts that runtime to a private temporary directory for the life
of the VPN process, then runs OpenVPN as a child process. Use `--openvpn <path>`
only when you want to override the bundled runtime for development or debugging.

By default, the CLI uses `--dns openvpn`. When the bundled runtime contains
`client.up` and `client.down`, the launcher passes temporary no-space symlinks
to OpenVPN so helper scripts can install pushed DNS and restore it on
disconnect. When those scripts are not present, the CLI captures pushed DNS
from OpenVPN and installs a temporary native macOS DNS resolver with `scutil`.
On Linux, the native fallback uses `systemd-resolved` through `resolvectl` when
available, then falls back to `resolvconf`.

Use `--dns disabled` to skip those scripts. User-provided OpenVPN configs with
script or plugin directives are rejected because this CLI is commonly run with
elevated privileges.

## Refresh the Embedded OpenVPN Runtime

```bash
nix develop -c env EMBED_RUNTIME=1 packaging/openvpn/build-openvpn.sh
cargo build
```

This rebuilds the AWS-patched OpenVPN runtime for the current target and stages
it under `assets/openvpn-runtime/<target>/openvpn`, which Cargo embeds into the
single `awsvpn` binary at compile time.

To refresh all committed runtime assets, run the manual GitHub Actions workflow
`Build OpenVPN Runtime Assets`. It builds OpenVPN for each supported target and
uploads `runtime-<target>` artifacts. Download those artifacts, copy each
`openvpn/` directory into `assets/openvpn-runtime/<target>/openvpn/`, validate,
and commit the result.

After a connection reaches `vpn connected`, `awsvpn diagnose` should report the
pushed VPN DNS server.

## Diagnose

```bash
cargo run -- diagnose
```

On macOS, the diagnostic command reports active DNS servers, whether private
VPN DNS is present, `utun` route count, and whether AWS script logs exist. It
does not read or print SAML responses, management passwords, or login URLs.

## Release Builds

GitHub Actions builds native self-contained binaries for:

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

Each CI job builds `awsvpn` with the runtime from the committed
`assets/openvpn-runtime/<target>/openvpn` directory embedded in the binary. The
regular CI workflow does not rebuild OpenVPN on every push.

To publish a release, push a version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds all four binaries, creates a GitHub Release, and
uploads `.tar.gz` archives plus SHA-256 checksum files.

## Licensing

This repository is licensed as GPL-2.0-only because release binaries can embed
and redistribute OpenVPN. See `THIRD_PARTY_NOTICES.md` for runtime source and
third-party details.
