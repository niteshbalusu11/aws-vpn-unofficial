# awsvpn

Unofficial Rust library and CLI for AWS Client VPN SAML profiles.

The crate is library-first. The `awsvpn` binary is a thin wrapper over public
types such as `VpnClient`, `ConnectOptions`, and `collect_diagnostics`.

## Connect on macOS with the AWS OpenVPN Bundle

```bash
sudo cargo run -- connect ~/.config/AWSVPNClient/OpenVpnConfigs/zbd \
  --openvpn "/Applications/AWS VPN Client/AWS VPN Client.app/Contents/Resources/openvpn/acvc-openvpn" \
  --debug
```

By default, the CLI uses `--dns openvpn`. When `client.up` and `client.down`
exist next to `acvc-openvpn`, the launcher passes temporary no-space symlinks
to OpenVPN so AWS's scripts can install pushed DNS and restore it on disconnect.

Use `--dns disabled` to skip those scripts.

## Diagnose

```bash
cargo run -- diagnose
```

The diagnostic command reports active DNS servers, whether private VPN DNS is
present, `utun` route count, and whether AWS script logs exist. It does not read
or print SAML responses, management passwords, or login URLs.
