# AWS VPN Unofficial: Rust Library + CLI Implementation Plan

Date: 2026-04-28

This document turns the reverse-engineering notes in `awsvpn-cli-reverse-engineering-plan.md` into an implementation plan for a Rust crate that exposes reusable library APIs plus a thin CLI.

## Current Status

Completed so far:

- Rust library crate and thin `awsvpn` CLI are implemented.
- SAML ACS server, browser launch, OpenVPN management protocol handling, CRV1 challenge parsing, and fake management tests are implemented.
- Real OpenVPN process orchestration works with the AWS-compatible OpenVPN management flow.
- `--openvpn` remains as an override, but the default runtime is now bundled and embedded into the Rust binary.
- Runtime assets are committed under `assets/openvpn-runtime/<target>/openvpn` for:
  - `aarch64-apple-darwin`
  - `x86_64-apple-darwin`
  - `aarch64-unknown-linux-gnu`
  - `x86_64-unknown-linux-gnu`
- macOS DNS is handled by original bundled `client.up` / `client.down` scripts, with Rust fallback for pushed DNS when scripts are absent.
- Linux OpenVPN runtimes are packaged, but Linux DNS integration is still pending.
- CI is split into regular CI and a manual runtime-refresh workflow:
  - regular CI validates committed runtime assets and builds self-contained binaries,
  - `Build OpenVPN Runtime Assets` is manual-only and rebuilds raw OpenVPN runtime assets when the source version changes.
- GPL-2.0-only licensing and third-party notices are documented.

The goal is to make the VPN/SAML/OpenVPN orchestration usable from:

```bash
sudo awsvpn connect ./client-config.ovpn
```

and also reusable from another application or CLI through a stable Rust API.

## Product Shape

Build one Rust package with both:

1. A library crate named `awsvpn`.
2. A binary crate named `awsvpn`.

The CLI should be a small adapter over the library. Core behavior must live in the library so another CLI can depend on this crate and call the same connection workflow directly.

Desired local usage:

```bash
sudo awsvpn connect ./client-config.ovpn
```

Desired embedded usage:

```rust
use awsvpn::{ConnectOptions, VpnClient};

#[tokio::main]
async fn main() -> awsvpn::Result<()> {
    let client = VpnClient::new();
    let session = client.connect(ConnectOptions::new("./client-config.ovpn")).await?;
    session.wait_until_interrupted().await?;
    Ok(())
}
```

## Core Principle

Do not implement this as a GUI-first app and do not scrape OpenVPN stdout as the primary protocol.

The reference repo at `/tmp/openaws-vpn-client` is useful proof that the SAML credential shape works, but our implementation should follow the cleaner architecture from the reverse-engineering plan:

- Start AWS-patched OpenVPN as a child process.
- Control OpenVPN through its management interface.
- Run a localhost SAML ACS server.
- Open the browser with the SAML URL returned by the VPN endpoint.
- Send the resulting SAML assertion back through OpenVPN's dynamic challenge/response path.

## Why Library First

A reusable library gives us:

- One tested implementation of the OpenVPN/SAML flow.
- A CLI that stays thin and easy to replace.
- A clean path for alternate frontends, daemon/service wrappers, Tauri apps, or distro-specific CLIs.
- Better integration tests because fake OpenVPN management servers can call library components directly.

The CLI should contain only:

- Argument parsing.
- Terminal/log formatting.
- Mapping CLI flags into library options.
- Signal handling policy where appropriate.
- Exit code mapping.

Everything else belongs in `src/lib.rs` and internal modules.

## Proposed Crate Layout

```text
aws-vpn-unofficial/
  Cargo.toml
  src/
    lib.rs
    main.rs
    client.rs
    error.rs
    event.rs
    config/
      mod.rs
      ovpn.rs
      profile.rs
    openvpn/
      mod.rs
      process.rs
      management.rs
      parser.rs
      command.rs
    saml/
      mod.rs
      acs.rs
      browser.rs
      flow.rs
    platform/
      mod.rs
      browser.rs
      dns.rs
      dns_linux.rs
      dns_macos.rs
      dns_windows.rs
      privilege.rs
    logredact/
      mod.rs
    package/
      mod.rs
      openvpn_locator.rs
  tests/
    management_parser.rs
    redaction.rs
    fake_management_flow.rs
  testdata/
    management/
      password_prompt.txt
      crv1_challenge.txt
      connected_state.txt
      auth_failed.txt
  packaging/
    openvpn/
    linux/
    macos/
  docs/
    protocol.md
    packaging.md
```

The exact names can change, but these boundaries should stay intact.

## Public Library API

The public API should be intentionally small at first.

### `VpnClient`

Primary entry point.

Responsibilities:

- Validate options.
- Start and coordinate the SAML/OpenVPN flow.
- Emit structured events.
- Return a live session handle.

Sketch:

```rust
pub struct VpnClient {
    // later: logger, runtime handles, platform implementation hooks
}

impl VpnClient {
    pub fn new() -> Self;

    pub async fn connect(&self, options: ConnectOptions) -> Result<VpnSession>;
}
```

### `ConnectOptions`

Configuration passed by the CLI or another caller.

Sketch:

```rust
pub struct ConnectOptions {
    pub config_path: PathBuf,
    pub openvpn_runtime: OpenVpnRuntime,
    pub management_host: IpAddr,
    pub management_port: Option<u16>,
    pub acs_host: IpAddr,
    pub acs_port: u16,
    pub auth_timeout: Duration,
    pub browser: BrowserMode,
    pub log_level: LogLevel,
    pub dns_mode: DnsMode,
}
```

Defaults:

- `management_host`: `127.0.0.1`
- `management_port`: random available local port
- `acs_host`: `127.0.0.1`
- `acs_port`: `35001`
- `auth_timeout`: 10 minutes
- `browser`: open system browser
- `openvpn_runtime`: bundled runtime
- `dns_mode`: initially `OpenVpnDefault`

### `VpnSession`

Handle returned after a connection is established or while it is being established, depending on the final API design.

Responsibilities:

- Wait for connection lifecycle changes.
- Disconnect cleanly.
- Expose event stream.
- Report OpenVPN process state.

Sketch:

```rust
pub struct VpnSession {
    // owns OpenVPN process handle, management connection, cleanup guards
}

impl VpnSession {
    pub async fn wait(&mut self) -> Result<ExitReason>;
    pub async fn disconnect(&mut self) -> Result<()>;
    pub fn events(&self) -> impl Stream<Item = VpnEvent>;
}
```

### `VpnEvent`

Structured events should be exposed instead of requiring callers to parse logs.

Initial events:

```rust
pub enum VpnEvent {
    OpenVpnStarted { pid: u32 },
    ManagementConnected,
    AuthPromptReceived,
    SamlChallengeReceived,
    BrowserOpened,
    SamlAssertionReceived,
    Connected { vpn_ip: Option<IpAddr> },
    Reconnecting { reason: Option<String> },
    Disconnected,
    Warning { message: String },
    Log { line: String },
}
```

Event payloads must never contain `SAMLResponse`, management passwords, or full auth commands.

### `Error`

Use a project error enum. Avoid returning raw strings from library functions.

Suggested crate:

- `thiserror` for error definitions.
- `anyhow` only in the CLI if desired.

Initial errors:

```rust
pub enum Error {
    ConfigNotFound(PathBuf),
    InvalidConfig(String),
    OpenVpnNotFound,
    OpenVpnSpawnFailed(std::io::Error),
    ManagementConnectFailed(std::io::Error),
    ManagementProtocol(String),
    AcsBindFailed(std::io::Error),
    InvalidSamlUrl(String),
    BrowserLaunchFailed(std::io::Error),
    SamlTimeout,
    SamlResponseMissing,
    SamlResponseTooLarge,
    AuthFailed(String),
    FatalOpenVpn(String),
    Interrupted,
}
```

## CLI Design

Initial command:

```bash
awsvpn connect <config.ovpn>
```

Useful early flags:

```bash
awsvpn connect <config.ovpn> \
  --openvpn /path/to/acvc-openvpn \
  --debug \
  --no-browser \
  --print-login-url \
  --dns openvpn
```

Commands to add later:

```bash
awsvpn disconnect
awsvpn status
awsvpn import <config.ovpn> --name <name>
awsvpn profiles
awsvpn doctor
awsvpn version
```

Use `clap` for argument parsing.

CLI responsibilities:

- Convert flags into `ConnectOptions`.
- Install Ctrl-C handler.
- Print sanitized status and logs.
- Return meaningful exit codes.
- Keep root-specific messaging understandable.

## Main Connection Flow

The library connection flow should be:

1. Validate the `.ovpn` file exists and is readable.
2. Create a temporary working directory with restrictive permissions.
3. Generate a management password file with `0600` permissions.
4. Start the ACS server on `127.0.0.1:35001`.
5. Start AWS-patched OpenVPN as a child process with management enabled.
6. Connect to the OpenVPN management socket.
7. Authenticate to management if needed.
8. Enable management notifications:

```text
state on
log on
echo on
hold release
```

9. On initial `Auth` password prompt, send:

```text
username "Auth" N/A
password "Auth" ACS::35001
```

10. Parse the CRV1 challenge:

```text
CRV1:R:<state_id>:b'Ti9B':<saml_url>
```

11. Validate the SAML URL is absolute and `https`.
12. Open the browser.
13. Wait for `SAMLResponse` POST to the ACS server.
14. On the next auth prompt, send:

```text
username "Auth" N/A
password "Auth" CRV1::<state_id>::<SAMLResponse>
```

15. Wait for `CONNECTED,SUCCESS`.
16. Keep the session alive until the caller disconnects or OpenVPN exits.
17. On disconnect, send OpenVPN management shutdown commands and clean up temp files.

## Important Difference From `openaws-vpn-client`

The cloned reference implementation:

- starts a local SAML server,
- launches a browser,
- captures `SAMLResponse`,
- sends `CRV1::<state>::<assertion>` to OpenVPN,
- uses patched OpenVPN.

That is useful.

But it also:

- binds the SAML server to `0.0.0.0:35001`,
- logs part of the SAML assertion,
- scrapes stdout for `AUTH_FAILED,CRV1`,
- starts OpenVPN twice,
- writes auth credentials into a temp file,
- relies on `pkexec`,
- kills OpenVPN by PID inspection.

Our implementation should avoid those choices. The management interface gives us a cleaner and more controllable lifecycle.

## Dependencies

Recommended initial dependencies:

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
thiserror = "2"
tokio = { version = "1", features = ["macros", "net", "process", "rt-multi-thread", "signal", "time", "io-util", "fs"] }
tokio-stream = "0.1"
tracing = "0.1"
tracing-subscriber = "0.3"
url = "2"
tempfile = "3"
rand = "0.9"
zeroize = "1"
```

Possible later dependencies:

```toml
hyper = "1"
hyper-util = "0.1"
http-body-util = "0.1"
form_urlencoded = "1"
dirs = "6"
nix = "0.30"
```

For the ACS server, use a small direct HTTP implementation or `hyper`. Avoid a large web framework unless it buys us something concrete.

## Security Requirements

These are hard requirements:

- Bind ACS only to `127.0.0.1`.
- Accept only `POST /` for SAML callback.
- Reject missing `SAMLResponse`.
- Enforce a 128 KiB max SAML response size.
- Never log `SAMLResponse`.
- Never log management password.
- Redact all `password "Auth" ...` management commands.
- Validate SAML login URL is absolute HTTPS before opening it.
- Pass browser URL as an argument, never through shell interpolation.
- Create temp directories/files with restrictive permissions.
- Delete management password files on exit.
- Stop ACS after one valid response or timeout.
- Do not store SAML assertions after use.
- Avoid printing the SAML URL unless `--print-login-url` is explicitly set.

Use `zeroize` for in-memory assertion/password buffers where practical.

## Patched OpenVPN Strategy

MVP should allow an explicit OpenVPN path:

```bash
awsvpn connect ./client.ovpn --openvpn /path/to/acvc-openvpn
```

Then add OpenVPN discovery:

1. `--openvpn` flag.
2. `AWSVPN_OPENVPN` environment variable.
3. Packaged project OpenVPN binary.
4. Platform-specific fallback paths for development only.

For development on macOS, we can test with the official app's bundled binary if installed:

```text
/Applications/AWS VPN Client/AWS VPN Client.app/Contents/Resources/openvpn/acvc-openvpn
```

For distribution, build/package AWS-patched OpenVPN from:

```text
https://amazon-source-code-downloads.s3.amazonaws.com/aws/clientvpn/openvpn-2.6.12-aws-1.tar.gz
```

Do not base the final packaged binary on the older `samm-git` OpenVPN 2.5.x patch unless we intentionally support a legacy path.

### Self-Contained OpenVPN Packaging Plan

Goal: users should not need the AWS VPN desktop app installed. The released CLI should include, or be able to locate, our own AWS-compatible OpenVPN runtime and platform DNS helpers.

#### Runtime Layout

Runtime assets are committed under `assets/openvpn-runtime/<target>/openvpn`
and embedded by `build.rs` into the Rust binary for the matching Cargo target.
At runtime, the library extracts the embedded files into a private temporary
directory and runs `acvc-openvpn` as a child process.

The embedded runtime layout is:

```text
assets/openvpn-runtime/<target>/openvpn/
  acvc-openvpn
  client.up        # only where script-based DNS is used
  client.down      # only where script-based DNS is used
  openssl.cnf      # if required by the OpenVPN build
  README.runtime.txt
```

Future package-manager layouts may still install the runtime under:

```text
libexec/awsvpn/openvpn/
```

The Rust runtime resolver currently supports:

1. `--openvpn <path>`
2. embedded bundled runtime

Potential future resolver sources:

1. `AWSVPN_OPENVPN=<path>`
2. package-manager runtime under `libexec/awsvpn/openvpn`
3. development-only AWS VPN app fallback, gated so it is never the packaged default

#### Source and Build Strategy

Build our runtime from AWS's published patched OpenVPN source:

```text
https://amazon-source-code-downloads.s3.amazonaws.com/aws/clientvpn/openvpn-2.6.12-aws-1.tar.gz
```

Do not rely on the installed AWS VPN app for distribution. Treat the app-bundled binary as a local development fixture only.

The `aws-vpn-client/aws-vpn-client` repository has extracted patch files for
OpenVPN 2.6.12 and OpenSSL 3.0.14. Its `extract.sh` confirms those patches can
be regenerated from AWS's source tarball by diffing against upstream OpenVPN.
Use that patch workflow for auditing and rebasing, but keep the first build
pipeline tarball-based so we are building exactly what AWS published.

Build outputs needed:

- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- optionally `x86_64-unknown-linux-musl` after OpenSSL/plugin feasibility is confirmed

#### DNS Strategy

Short term:

- macOS can use script helpers when packaged with the runtime.
- Linux must get native DNS handling in Rust rather than relying on AWS desktop scripts.

Medium term:

- Implement `DnsMode::SystemdResolved`.
- Implement `DnsMode::Resolvconf`.
- Keep `DnsMode::Disabled` for users who manage DNS externally.
- Keep OpenVPN routes managed by OpenVPN unless a platform requires extra route reconciliation.

#### Packaging TODOs

- [x] Add bundled runtime abstraction with explicit external override.
- [x] Make `--openvpn` optional once bundled runtime is implemented.
- [x] Embed runtime assets at compile time from `assets/openvpn-runtime/<target>/openvpn`.
- [x] Extract embedded runtime into a private temporary runtime directory.
- [x] Add tests for bundled runtime extraction and path validation.
- [x] Add `packaging/openvpn/README.md` with source URL, build prerequisites, and expected artifact layout.
- [x] Add `packaging/openvpn/build-openvpn.sh` skeleton for local and CI builds.
- [x] Add checksum verification for downloaded OpenVPN source tarballs.
- [x] Decide whether to vendor source tarballs, download in CI, or use release assets only. Current decision: commit built runtime assets and use a manual CI workflow to regenerate them from AWS's published source tarball.
- [x] Build Linux amd64 AWS-patched OpenVPN artifact.
- [x] Build Linux arm64 AWS-patched OpenVPN artifact.
- [x] Build macOS amd64 AWS-patched OpenVPN artifact.
- [x] Build macOS arm64 AWS-patched OpenVPN artifact.
- [x] Package DNS helper scripts after license review. Current macOS helpers are original project scripts.
- [x] Replace macOS AWS script dependency with our own scripts and Rust fallback.
- [x] Add regular CI matrix that builds self-contained binaries from committed runtime assets.
- [x] Add manual `Build OpenVPN Runtime Assets` CI workflow for OpenVPN runtime refreshes.
- [x] Add committed runtime asset validation script.
- [x] Add GPL-2.0-only license and third-party notices.
- [ ] Add optional patch-regeneration script based on the `aws-vpn-client/aws-vpn-client` `extract.sh` workflow.
- [ ] Implement Linux DNS through `systemd-resolved`.
- [ ] Implement Linux DNS through `resolvconf`.
- [ ] Add release archive layout tests.
- [ ] Document unsupported distros and required privileges.
- [ ] Add CLI output that logs which OpenVPN runtime source was used without exposing sensitive paths in normal mode.
- [ ] Add optional package-manager runtime resolver.

## Module TODOs

### Library Root

- [x] Add `src/lib.rs`.
- [x] Export `VpnClient`, `ConnectOptions`, `VpnSession`, `VpnEvent`, `Error`, and `Result`.
- [x] Export `OpenVpnRuntime` and bundled runtime availability helpers.
- [x] Keep internal modules private until their API is proven.
- [x] Add crate-level docs explaining the library-first purpose.
- [ ] Add fuller crate-level docs explaining the SAML/OpenVPN management flow at a high level.

### CLI

- [x] Replace `src/main.rs` hello-world with `clap` parser.
- [x] Implement `connect <config.ovpn>`.
- [x] Add `--openvpn <path>`.
- [x] Make `--openvpn` optional by defaulting to bundled runtime.
- [x] Add `--debug`.
- [x] Add `--no-browser`.
- [x] Add `--browser`.
- [x] Add `--print-login-url`.
- [x] Add `--dns`.
- [x] Add `diagnose`.
- [x] Add signal handling for Ctrl-C, SIGTERM, and SIGHUP.
- [x] Map common library errors to actionable CLI messages.
- [x] Ensure CLI logs are redacted by default.

### Config Parsing

- [x] Validate config path exists.
- [x] Parse `remote` host and port.
- [x] Detect `auth-user-pass`.
- [x] Detect `auth-federate`.
- [x] Preserve original config without destructive rewrites.
- [x] Accept `auth-user-pass` or `auth-federate` for MVP.
- [x] Reject config script/plugin directives before running OpenVPN as root.
- [x] Add tests for representative AWS Client VPN configs.

### OpenVPN Process

- [x] Locate OpenVPN binary from explicit path or bundled runtime.
- [x] Create temp work directory.
- [x] Generate management password.
- [x] Write management password file with `0600` permissions.
- [x] Spawn OpenVPN with management arguments.
- [x] Pipe stdout/stderr into sanitized event/log stream.
- [x] Track process ID.
- [x] Implement graceful shutdown.
- [x] Kill child only after graceful shutdown timeout.
- [x] Delete temp files on drop.
- [x] Stage trusted DNS helper scripts next to OpenVPN when present.
- [x] Avoid enabling `--script-security 2` unless trusted helper scripts are staged.

OpenVPN args for MVP:

```text
--config <config>
--management 127.0.0.1 <port> <password-file>
--management-query-passwords
--management-hold
--auth-nocache
--script-security 2
```

### Management Client

- [x] Connect to management TCP socket.
- [x] Handle management password prompt if emitted.
- [x] Send `state on`.
- [x] Send `log on`.
- [x] Send `echo on`.
- [x] Send `hold release`.
- [x] Implement line-based reader.
- [x] Implement command writer with safe quoting.
- [x] Support `username "Auth" ...`.
- [x] Support `password "Auth" ...`.
- [x] Support `signal SIGTERM`.
- [x] Support `quit`.
- [x] Handle auth-failure reconnect during SAML flow.
- [x] Report management socket close as a protocol error.
- [ ] Add broader reconnect/error handling for unexpected management socket close after connection.

### Management Parser

- [x] Parse `>PASSWORD:Need 'Auth' username/password`.
- [x] Parse CRV1 SAML challenge.
- [x] Parse CRV1 challenge from `AUTH_FAILED` log lines.
- [x] Parse `>STATE:...,CONNECTED,SUCCESS,...`.
- [x] Parse `>STATE:...,RECONNECTING,...`.
- [x] Parse `AUTH_FAILED`.
- [x] Parse `>FATAL:`.
- [x] Parse pushed DNS from useful `PUSH_REPLY` log lines.
- [x] Reject malformed CRV1 messages.
- [x] Validate CRV1 challenge type is response-required.
- [x] Extract opaque `state_id` exactly.
- [x] Extract SAML URL exactly.
- [x] Unit test valid and invalid parser fixtures.
- [ ] Fuzz CRV1 parser after MVP.

### SAML ACS Server

- [x] Bind `127.0.0.1:35001` by default.
- [x] Support configurable loopback ACS host/port.
- [x] Return clear error if port is in use.
- [x] Accept only `POST /`.
- [x] Parse `application/x-www-form-urlencoded`.
- [x] Extract `SAMLResponse`.
- [x] Enforce 128 KiB max.
- [x] Reject control characters in assertions before writing to management socket.
- [x] Send one assertion through a one-shot receive path.
- [x] Return minimal success HTML.
- [x] Return minimal failure HTML.
- [x] Stop after one valid assertion.
- [x] Stop after timeout.
- [x] Do not log assertion value.
- [x] Add tests for valid POST, missing response, oversized response, wrong method, wrong path, and control characters.

### Browser Opener

- [x] Validate URL with `url` crate.
- [x] Require `https`.
- [x] Use `webbrowser` crate for platform browser launching.
- [x] Never use shell interpolation.
- [x] Support `BrowserMode::Disabled` for tests/headless usage.
- [x] Support explicit URL printing only when requested.

### SAML Flow Orchestrator

- [x] Coordinate ACS server, management events, browser opener, and assertion delivery.
- [x] Track pending CRV1 `state_id`.
- [x] Ignore duplicate SAML challenges after assertion callback.
- [x] Replay SAML response when OpenVPN prompts again after auth-failure reconnect.
- [x] Refuse malformed ACS submissions before a valid POST.
- [x] Apply 10 minute auth timeout.
- [x] Redact sensitive OpenVPN output in events/logs.
- [ ] Ensure assertion is zeroized/dropped after sending.
- [x] Handle user interruption while waiting for browser login through CLI signal path.

### DNS and Routing

- [x] For MVP, let OpenVPN manage routes.
- [x] Document DNS limitations clearly.
- [ ] Add Linux `systemd-resolved` support.
- [ ] Add Linux `resolvconf` support.
- [ ] Add NixOS-specific notes or mode.
- [x] Add macOS DNS setup via scripts or direct `scutil`.
- [x] Ensure disconnect restores DNS.
- [x] Add `DnsMode` enum to public options before exposing behavior.
- [x] Add reusable route/DNS diagnostics API.
- [x] Add `awsvpn diagnose` CLI command.
- [x] Make non-macOS native DNS fallback fail explicitly instead of silently ignoring pushed DNS.
- [x] Make diagnostics platform-specific; currently implemented on macOS.

### Logging and Redaction

- [x] Implement `logredact::redact_line`.
- [x] Redact `password "Auth" ...`.
- [x] Redact `CRV1::<state>::<assertion>`.
- [x] Redact `SAMLResponse=...`.
- [x] Avoid logging management password file content.
- [ ] Consider redacting SAML login URL by default.
- [x] Unit test common sensitive line shapes.

### Tests

- [x] Unit test management parser.
- [x] Unit test ACS form parsing.
- [x] Unit test URL validation.
- [x] Unit test log redaction.
- [x] Unit test command quoting.
- [x] Integration test with fake OpenVPN management server.
- [x] Integration test browser-disabled SAML flow.
- [x] Manual real AWS Client VPN test on macOS.
- [x] Package validation via `cargo package`.
- [x] Runtime asset validation script.

### Fake Management Server

- [x] Build test helper that listens on a local port.
- [x] Expect `state on`, `log on`, `echo on`, `hold release`.
- [x] Emit `>PASSWORD:Need 'Auth' username/password`.
- [x] Expect `username "Auth" N/A`.
- [x] Expect `password "Auth" ACS::<port>`.
- [x] Emit CRV1 challenge with fake HTTPS URL.
- [x] Trigger fake ACS POST in test.
- [x] Emit second password prompt where needed.
- [x] Expect `password "Auth" CRV1::<state>::<assertion>`.
- [x] Emit connected state.
- [x] Assert session reaches connected.

## Milestones

### Milestone 1: Rust Library Skeleton

Goal: establish the public API and CLI wrapper.

TODO:

- [x] Add library crate.
- [x] Add `clap` CLI.
- [x] Add `Error` and `Result`.
- [x] Add `ConnectOptions`.
- [x] Add `VpnClient::connect`.
- [x] Add CI-ready `cargo test`.

Acceptance:

- `cargo test` passes.
- `cargo run -- connect ./client-config.ovpn` reaches the library path and validates the config.

### Milestone 2: Protocol Parser and Redaction

Goal: make the risky string-handling parts testable before process orchestration.

TODO:

- [x] Implement management parser.
- [x] Implement CRV1 extraction.
- [x] Implement URL validation.
- [x] Implement redaction.
- [x] Add fixtures.

Acceptance:

- Parser tests cover password prompts, CRV1, connected, auth failed, fatal, and malformed input.
- Redaction tests prove SAML assertions and passwords do not appear in output.

### Milestone 3: ACS Server and Browser

Goal: receive SAML responses safely.

TODO:

- [x] Implement localhost-only ACS server.
- [x] Implement one-shot assertion delivery.
- [x] Implement timeout.
- [x] Implement browser opener.
- [x] Add browser-disabled mode for tests.

Acceptance:

- Tests can POST a fake `SAMLResponse`.
- Server rejects wrong method/path/missing field.
- Oversized assertion is rejected.

### Milestone 4: OpenVPN Management Flow

Goal: prove the full auth state machine without a real VPN.

TODO:

- [x] Implement management client.
- [x] Implement fake management integration test.
- [x] Implement SAML flow orchestrator.
- [x] Implement event stream.

Acceptance:

- Fake management test reaches `Connected`.
- No test logs contain fake SAML assertion values.

### Milestone 5: Real OpenVPN Process

Goal: start and control a patched OpenVPN binary.

TODO:

- [x] Implement process spawning.
- [x] Implement management port selection.
- [x] Implement secure temp files.
- [x] Implement graceful shutdown.
- [x] Add bundled OpenVPN runtime extraction.
- [x] Add `--openvpn` override flag.

Acceptance:

- CLI starts bundled or explicitly supplied patched OpenVPN.
- Management socket connects.
- Ctrl-C shuts down OpenVPN and cleans temp files.

### Milestone 6: Real AWS Client VPN Test

Goal: connect to a real SAML Client VPN endpoint.

TODO:

- [x] Test with an actual AWS Client VPN `.ovpn`.
- [x] Confirm browser opens.
- [x] Confirm SAML login posts to ACS.
- [x] Confirm management sends CRV1 assertion.
- [x] Confirm `CONNECTED,SUCCESS`.
- [x] Confirm Ctrl-C disconnects.

Acceptance:

- `sudo awsvpn connect ./client-config.ovpn` reaches connected state with the bundled runtime.
- `sudo awsvpn connect ./client-config.ovpn --openvpn <patched-openvpn>` remains available for local debugging.

### Milestone 7: Linux Usability

Goal: make the MVP useful on target Linux distros.

TODO:

- [x] Build AWS-patched OpenVPN for Linux amd64.
- [x] Build AWS-patched OpenVPN for Linux arm64.
- [x] Add packaging layout.
- [ ] Add DNS support for `systemd-resolved`.
- [ ] Add DNS support for `resolvconf`.
- [ ] Test Fedora.
- [ ] Test Arch.
- [ ] Test Debian/Ubuntu.
- [ ] Test NixOS.

Acceptance:

- Private DNS works after connect.
- DNS/routes restore after disconnect.

### Milestone 8: Profile Management

Goal: stop requiring a config path every time.

TODO:

- [ ] Add `awsvpn import`.
- [ ] Store profiles under `~/.config/awsvpn/profiles`.
- [ ] Add `awsvpn profiles`.
- [ ] Add `awsvpn connect <profile-name>`.
- [ ] Validate file permissions.

Acceptance:

- Multiple profiles work.
- Imported configs are not world-readable.

### Milestone 9: macOS Support

Goal: support macOS without relying on AWS's installed app.

TODO:

- [x] Build AWS-patched OpenVPN for darwin-amd64.
- [x] Build AWS-patched OpenVPN for darwin-arm64.
- [x] Implement macOS DNS setup via bundled `client.up` / `client.down` scripts.
- [x] Define current privilege story in README: macOS connect requires `sudo` when OpenVPN configures `utun`, routes, and DNS scripts.
- [ ] Test Intel Mac.
- [x] Test Apple Silicon.

Acceptance:

- CLI connects on macOS with packaged OpenVPN.
- DNS/routes restore after disconnect.

## Open Questions

Resolved:

1. The package is `aws-vpn-unofficial`; the library crate and binary expose `awsvpn`.
2. `VpnClient::connect` returns a connected session after the tunnel reaches `CONNECTED,SUCCESS`.
3. Signal handling is owned by the CLI; the library exposes explicit session cleanup.
4. SAML login URLs are only printed behind `--print-login-url`.
5. The ACS server uses a tiny purpose-built parser, keeping dependencies and attack surface small.
6. Bundled runtime is the default; `--openvpn` remains as an explicit external override.
7. The project is GPL-2.0-only because it ships AWS/OpenVPN-derived runtime artifacts and helper scripts.

Still open:

1. Should profile management live in the core library or a separate optional feature?
2. What should the default Linux DNS strategy be when both `systemd-resolved` and `resolvconf` are available?
3. Should we support alternate ACS ports experimentally, or hard-code `35001` for AWS compatibility?
4. Should SAML assertions be explicitly zeroized after management handoff?
5. Should the SAML login URL be redacted by default in debug logs even before authentication?

## Immediate Next Steps

1. Commit the organized runtime assets and workflow split.
2. Re-run the PR CI and confirm the package crate job passes with committed assets.
3. Implement Linux DNS, starting with `systemd-resolved` and falling back to `resolvconf`.
4. Add release archive layout tests for the self-contained binary path.
5. Add runtime-source logging so debug output clearly shows whether bundled or external OpenVPN is being used.
6. Add distro documentation for privileges, DNS modes, and unsupported Linux setups.
