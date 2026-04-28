# awsvpn

Unofficial Rust library and CLI for AWS Client VPN SAML profiles.

The crate is library-first. The `awsvpn` binary is a thin wrapper over public
types such as `VpnClient`, `ConnectOptions`, and `collect_diagnostics`.

## Connect on macOS with the AWS OpenVPN Bundle

Build as your normal user, then run only the built binary with `sudo`.
Do not use `sudo cargo run`: Cargo will compile as root, which loses the Nix
SDK/linker environment and can fail to find the macOS SDK or `libiconv`.

```bash
cargo build

sudo -E target/debug/awsvpn connect ~/.config/AWSVPNClient/OpenVpnConfigs/example \
  --openvpn "/Applications/AWS VPN Client/AWS VPN Client.app/Contents/Resources/openvpn/acvc-openvpn" \
  --debug
```

By default, the CLI uses `--dns openvpn`. When `client.up` and `client.down`
exist next to `acvc-openvpn`, the launcher passes temporary no-space symlinks
to OpenVPN so helper scripts can install pushed DNS and restore it on disconnect.
When those scripts are not present, the CLI captures pushed DNS from OpenVPN
and installs a temporary native macOS DNS resolver with `scutil`. On other
platforms this fallback currently fails explicitly instead of silently leaving
DNS unconfigured.

Use `--dns disabled` to skip those scripts. User-provided OpenVPN configs with
script or plugin directives are rejected because this CLI is commonly run with
elevated privileges.

## Connect on macOS with the Self-Built OpenVPN Runtime

```bash
nix develop -c packaging/openvpn/build-openvpn.sh
cargo build

sudo -E target/debug/awsvpn connect ~/.config/AWSVPNClient/OpenVpnConfigs/example \
  --openvpn target/openvpn-runtime/aarch64-apple-darwin/openvpn/acvc-openvpn \
  --debug
```

After the connection reaches `vpn connected`, `awsvpn diagnose` should report
the pushed VPN DNS server.

## Diagnose

```bash
cargo run -- diagnose
```

On macOS, the diagnostic command reports active DNS servers, whether private
VPN DNS is present, `utun` route count, and whether AWS script logs exist. It
does not read or print SAML responses, management passwords, or login URLs.
