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

## Commands

Most commands need `sudo` because OpenVPN configures tunnel interfaces, routes,
and DNS. When run through `sudo`, the default config path still resolves to the
invoking desktop user's home directory.

Connect with the default config and return after the tunnel is established:

```bash
sudo awsvpn connect
```

Connect with an explicit AWS Client VPN config:

```bash
sudo awsvpn connect ./client-config.ovpn
```

Show the background session state:

```bash
sudo awsvpn status
```

Disconnect the background session and restore DNS:

```bash
sudo awsvpn disconnect
```

Keep the VPN attached to the current terminal until Ctrl-C or OpenVPN exits:

```bash
sudo awsvpn connect --foreground
```

Print verbose, redacted startup logs:

```bash
sudo awsvpn connect --debug
```

Disable automatic browser launch and print the SAML login URL instead:

```bash
sudo awsvpn connect --no-browser --print-login-url
```

Skip VPN DNS configuration when another tool manages DNS:

```bash
sudo awsvpn connect --dns disabled
```

Route a private DNS suffix to the VPN DNS resolver when the endpoint does not
push a usable search domain:

```bash
sudo awsvpn connect --dns-domain zebedee.io
```

You can make DNS suffixes persistent by listing them one per line in
`~/.awsvpnunofficial/dns-domains`:

```text
zebedee.io
```

Keep normal internet routing even if the VPN endpoint pushes a default route:

```bash
sudo awsvpn connect --no-default-route
```

Ignore all VPN-pushed routes while debugging route-related hangs:

```bash
sudo awsvpn connect --no-pushed-routes
```

Use an explicit AWS-patched OpenVPN binary instead of the bundled runtime:

```bash
sudo awsvpn connect --openvpn /path/to/acvc-openvpn
```

Run diagnostics after connecting:

```bash
sudo awsvpn diagnose
```

## Troubleshooting Networking Hangs

If public networking hangs while the VPN is connected, first separate routing
from DNS:

```bash
ping 1.1.1.1
ping github.com
```

If `ping 1.1.1.1` hangs, the VPN endpoint probably pushed a default route and
your internet traffic is going through the VPN. Reconnect with:

```bash
sudo awsvpn disconnect
sudo awsvpn connect --no-default-route
```

If public networking still hangs, check whether the endpoint pushed broad route
directives. Reconnect with all VPN-pushed routes disabled:

```bash
sudo awsvpn disconnect
sudo awsvpn connect --no-pushed-routes
```

If `ping 1.1.1.1` works but `ping github.com` hangs, the issue is DNS. Reconnect
without VPN DNS while debugging:

```bash
sudo awsvpn disconnect
sudo awsvpn connect --dns disabled
```

If internal names do not resolve but direct queries to the VPN DNS server do,
add the internal DNS suffix explicitly:

```bash
dig @172.31.0.2 grafana.lightning.zebedee.io
sudo awsvpn disconnect
sudo awsvpn connect --dns-domain zebedee.io
```

On macOS, you can inspect the active resolver state with:

```bash
scutil --dns
netstat -rn -f inet
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

By default, `connect` runs the VPN session in daemon mode. The command streams
startup output until the tunnel is connected, then returns control of the
terminal. Use `status` and `disconnect` to manage the background session:

```bash
sudo awsvpn status
sudo awsvpn disconnect
```

Use `--foreground` when you want the old attached behavior where the shell stays
occupied until Ctrl-C or OpenVPN exits:

```bash
sudo awsvpn connect --foreground
```

By default, the CLI uses the AWS-patched OpenVPN runtime embedded in the Rust
binary. It extracts that runtime to a private temporary directory for the life
of the VPN process, then runs OpenVPN as a child process. Use `--openvpn <path>`
only when you want to override the bundled runtime for development or debugging.

By default, the CLI uses `--dns openvpn`. On macOS, bundled helper scripts
install pushed VPN DNS as a scoped resolver for the pushed search/domain suffixes
so public DNS stays on the normal network resolver. When those scripts are not
present, the CLI captures pushed DNS from OpenVPN and installs a temporary
scoped native macOS DNS resolver with `scutil`. On Linux, the native fallback
uses `systemd-resolved` through `resolvectl` when available, then falls back to
`resolvconf`.

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

## Licensing

This repository is licensed as GPL-2.0-only because release binaries can embed
and redistribute OpenVPN. See `THIRD_PARTY_NOTICES.md` for runtime source and
third-party details.
