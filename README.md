# AWS VPN Unofficial

Unofficial Rust library and CLI for AWS Client VPN SAML profiles.

This is not an official Amazon Web Services project. It is not affiliated with,
endorsed by, maintained by, or supported by AWS. Use it at your own risk; review
the code and validate it against your organization's security policies.

## Install

Download the `awsvpn` binary for your platform, place it on your `PATH`, and
copy your AWS Client VPN profile to the default location:

```bash
mkdir -p ~/.awsvpnunofficial
cp ~/path/to/client-config.ovpn ~/.awsvpnunofficial/vpnconfig.ovpn
sudo awsvpn connect
```

To build from source:

```bash
git clone https://github.com/niteshbalusu11/aws-vpn-unofficial.git
cd aws-vpn-unofficial
cargo install --path .
sudo awsvpn connect
```

## Usage

Most commands need `sudo` because OpenVPN configures tunnel interfaces, routes,
and DNS. When run through `sudo`, the default config path still resolves to the
invoking desktop user's home directory.

```bash
sudo awsvpn connect
sudo awsvpn status
sudo awsvpn reconnect
sudo awsvpn disconnect
```

Short aliases are available for the common commands:

```bash
sudo awsvpn c   # connect
sudo awsvpn r   # reconnect
sudo awsvpn d   # disconnect
```

Pass a profile path when you do not want the default
`~/.awsvpnunofficial/vpnconfig.ovpn`:

```bash
sudo awsvpn connect ./client-config.ovpn
```

By default, `connect` runs in daemon mode: it streams startup output until the
tunnel is connected, then returns control of the terminal. Use foreground mode
when you want the VPN attached to the current terminal:

```bash
sudo awsvpn connect --foreground
```

Useful flags:

```bash
sudo awsvpn connect --debug
sudo awsvpn connect --dns disabled
sudo awsvpn connect --no-browser --print-login-url
sudo awsvpn connect --openvpn /path/to/acvc-openvpn
```

Run diagnostics after connecting:

```bash
sudo awsvpn diagnose
```

## DNS

Yes, `--dns` is still supported.

`--dns openvpn` is the default. On macOS, the CLI captures VPN-pushed DNS,
starts a loopback-only DNS proxy on `127.0.0.1`, and temporarily points macOS
DNS at that proxy. The proxy forwards DNS through the tunnel, which avoids
binding the VPN DNS server to the physical `en0` service. DNS state is restored
when the VPN disconnects.

Use `--dns disabled` only when another tool owns DNS or when another local
service is already bound to `127.0.0.1:53`.

User-provided OpenVPN configs with script or plugin directives are rejected
because this CLI is commonly run with elevated privileges.

## Development

Build as your normal user, then run only the built binary with `sudo`. Do not
use `sudo cargo run`: Cargo will compile as root, which loses the Nix
SDK/linker environment and can fail to find the macOS SDK or `libiconv`.

```bash
cargo build
sudo -E target/debug/awsvpn connect --debug
```

Refresh the embedded OpenVPN runtime:

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

`awsvpn diagnose` reports active DNS servers, VPN DNS, and tunnel routes without
printing SAML responses, management passwords, or login URLs.

## Licensing

This repository is licensed as GPL-2.0-only because release binaries can embed
and redistribute OpenVPN. See `THIRD_PARTY_NOTICES.md` for runtime source and
third-party details.
