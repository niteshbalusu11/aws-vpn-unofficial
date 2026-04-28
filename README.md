# awsvpn

Unofficial Rust library and CLI for AWS Client VPN SAML profiles.

The crate is library-first. The `awsvpn` binary is a thin wrapper over public
types such as `VpnClient`, `ConnectOptions`, and `collect_diagnostics`.

## Install

From a published crate:

```bash
cargo install aws-vpn-unofficial
sudo awsvpn connect ~/.config/AWSVPNClient/OpenVpnConfigs/example
```

From a release artifact, place the downloaded `awsvpn` binary somewhere on your
`PATH` and run the same command.

## Connect with the Bundled Runtime

Build as your normal user, then run only the built binary with `sudo`.
Do not use `sudo cargo run`: Cargo will compile as root, which loses the Nix
SDK/linker environment and can fail to find the macOS SDK or `libiconv`.

```bash
cargo build

sudo -E target/debug/awsvpn connect ~/.config/AWSVPNClient/OpenVpnConfigs/example \
  --debug
```

By default, the CLI uses the AWS-patched OpenVPN runtime embedded in the Rust
binary. It extracts that runtime to a private temporary directory for the life
of the VPN process, then runs OpenVPN as a child process. Use `--openvpn <path>`
only when you want to override the bundled runtime for development or debugging.

By default, the CLI uses `--dns openvpn`. When the bundled runtime contains
`client.up` and `client.down`, the launcher passes temporary no-space symlinks
to OpenVPN so helper scripts can install pushed DNS and restore it on
disconnect. When those scripts are not present, the CLI captures pushed DNS
from OpenVPN and installs a temporary native macOS DNS resolver with `scutil`.
On other platforms this fallback currently fails explicitly instead of silently
leaving DNS unconfigured.

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

Each CI job builds the AWS-patched OpenVPN runtime for that target, stages it
under `assets/openvpn-runtime/<target>/openvpn`, and then compiles `awsvpn` with
that runtime embedded.

## Licensing

This repository is licensed as GPL-2.0-only because release binaries can embed
and redistribute OpenVPN. See `THIRD_PARTY_NOTICES.md` for runtime source and
third-party details.
