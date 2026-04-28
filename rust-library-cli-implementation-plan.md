# AWS VPN Unofficial: Rust Library + CLI Implementation Plan

Date: 2026-04-28

This document turns the reverse-engineering notes in `awsvpn-cli-reverse-engineering-plan.md` into an implementation plan for a Rust crate that exposes reusable library APIs plus a thin CLI.

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
    pub openvpn_binary: Option<PathBuf>,
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

## Module TODOs

### Library Root

- [ ] Add `src/lib.rs`.
- [ ] Export `VpnClient`, `ConnectOptions`, `VpnSession`, `VpnEvent`, `Error`, and `Result`.
- [ ] Keep internal modules private until their API is proven.
- [ ] Add crate-level docs explaining the SAML/OpenVPN management flow at a high level.

### CLI

- [ ] Replace `src/main.rs` hello-world with `clap` parser.
- [ ] Implement `connect <config.ovpn>`.
- [ ] Add `--openvpn <path>`.
- [ ] Add `--debug`.
- [ ] Add `--no-browser`.
- [ ] Add `--print-login-url`.
- [x] Add signal handling for Ctrl-C.
- [ ] Map library errors to actionable CLI messages.
- [x] Ensure CLI logs are redacted by default.

### Config Parsing

- [ ] Validate config path exists.
- [ ] Parse `remote` host and port.
- [ ] Detect `auth-user-pass`.
- [ ] Detect `auth-federate`.
- [ ] Preserve original config without destructive rewrites.
- [ ] Decide whether MVP requires `auth-user-pass` or normalizes `auth-federate`.
- [ ] Add tests for representative AWS Client VPN configs.

### OpenVPN Process

- [ ] Locate OpenVPN binary.
- [x] Create temp work directory.
- [x] Generate management password.
- [x] Write management password file with `0600` permissions.
- [x] Spawn OpenVPN with management arguments.
- [x] Pipe stdout/stderr into sanitized event/log stream.
- [x] Track process ID.
- [x] Implement graceful shutdown.
- [x] Kill child only after graceful shutdown timeout.
- [x] Delete temp files on drop.

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
- [ ] Add reconnect/error handling for management socket close.

### Management Parser

- [ ] Parse `>PASSWORD:Need 'Auth' username/password`.
- [ ] Parse CRV1 SAML challenge.
- [ ] Parse `>STATE:...,CONNECTED,SUCCESS,...`.
- [ ] Parse `>STATE:...,RECONNECTING,...`.
- [ ] Parse `AUTH_FAILED`.
- [ ] Parse `>FATAL:`.
- [ ] Parse useful `>LOG:` lines.
- [ ] Reject malformed CRV1 messages.
- [ ] Validate CRV1 challenge type is response-required.
- [ ] Extract opaque `state_id` exactly.
- [ ] Extract SAML URL exactly.
- [ ] Unit test valid and invalid parser fixtures.
- [ ] Fuzz CRV1 parser after MVP.

### SAML ACS Server

- [ ] Bind `127.0.0.1:35001`.
- [ ] Return clear error if port is in use.
- [ ] Accept only `POST /`.
- [ ] Parse `application/x-www-form-urlencoded`.
- [ ] Extract `SAMLResponse`.
- [ ] Enforce 128 KiB max.
- [ ] Send one assertion through a one-shot channel.
- [ ] Return minimal success HTML.
- [ ] Return minimal failure HTML.
- [ ] Stop after one valid assertion.
- [ ] Stop after timeout.
- [ ] Do not log assertion value.
- [ ] Add tests for valid POST, missing response, oversized response, wrong method, wrong path.

### Browser Opener

- [ ] Validate URL with `url` crate.
- [ ] Require `https`.
- [ ] Implement macOS `open`.
- [ ] Implement Linux `xdg-open`.
- [ ] Implement Windows `rundll32 url.dll,FileProtocolHandler`.
- [ ] Never use shell interpolation.
- [ ] Support `BrowserMode::Disabled` for tests/headless usage.
- [ ] Support explicit URL printing only when requested.

### SAML Flow Orchestrator

- [x] Coordinate ACS server, management events, browser opener, and assertion delivery.
- [x] Track pending CRV1 `state_id`.
- [ ] Refuse unexpected ACS submissions before a challenge is active.
- [x] Apply 10 minute auth timeout.
- [ ] Redact all sensitive data in errors/events.
- [ ] Ensure assertion is zeroized/dropped after sending.
- [ ] Handle user interruption while waiting for browser login.

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

### Logging and Redaction

- [x] Implement `logredact::redact_line`.
- [x] Redact `password "Auth" ...`.
- [x] Redact `CRV1::<state>::<assertion>`.
- [x] Redact `SAMLResponse=...`.
- [ ] Redact management password file content.
- [ ] Consider redacting SAML login URL by default.
- [x] Unit test common sensitive line shapes.

### Tests

- [ ] Unit test management parser.
- [ ] Unit test ACS form parsing.
- [ ] Unit test URL validation.
- [ ] Unit test log redaction.
- [ ] Unit test command quoting.
- [ ] Integration test with fake OpenVPN management server.
- [ ] Integration test browser-disabled SAML flow.
- [ ] Manual real AWS Client VPN test.

### Fake Management Server

- [ ] Build test helper that listens on a local port.
- [ ] Emit initial management greeting.
- [ ] Expect `state on`, `log on`, `echo on`, `hold release`.
- [ ] Emit `>PASSWORD:Need 'Auth' username/password`.
- [ ] Expect `username "Auth" N/A`.
- [ ] Expect `password "Auth" ACS::35001`.
- [ ] Emit CRV1 challenge with fake HTTPS URL.
- [ ] Trigger fake ACS POST in test.
- [ ] Emit second password prompt.
- [ ] Expect `password "Auth" CRV1::<state>::<assertion>`.
- [ ] Emit connected state.
- [ ] Assert session reaches connected.

## Milestones

### Milestone 1: Rust Library Skeleton

Goal: establish the public API and CLI wrapper.

TODO:

- [ ] Add library crate.
- [ ] Add `clap` CLI.
- [ ] Add `Error` and `Result`.
- [ ] Add `ConnectOptions`.
- [ ] Add no-op `VpnClient::connect` placeholder.
- [ ] Add CI-ready `cargo test`.

Acceptance:

- `cargo test` passes.
- `cargo run -- connect ./x.ovpn` reaches the library path and returns a clear not-implemented error.

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

- [ ] Implement management client.
- [ ] Implement fake management integration test.
- [ ] Implement SAML flow orchestrator.
- [ ] Implement event stream.

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
- [x] Add `--openvpn` flag.

Acceptance:

- CLI starts patched OpenVPN.
- Management socket connects.
- Ctrl-C shuts down OpenVPN and cleans temp files.

### Milestone 6: Real AWS Client VPN Test

Goal: connect to a real SAML Client VPN endpoint.

TODO:

- [ ] Test with an actual AWS Client VPN `.ovpn`.
- [ ] Confirm browser opens.
- [ ] Confirm SAML login posts to ACS.
- [ ] Confirm management sends CRV1 assertion.
- [ ] Confirm `CONNECTED,SUCCESS`.
- [ ] Confirm Ctrl-C disconnects.

Acceptance:

- `sudo awsvpn connect ./client-config.ovpn --openvpn <patched-openvpn>` reaches connected state.

### Milestone 7: Linux Usability

Goal: make the MVP useful on target Linux distros.

TODO:

- [ ] Build AWS-patched OpenVPN for Linux amd64.
- [ ] Build AWS-patched OpenVPN for Linux arm64.
- [ ] Add packaging layout.
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

- [ ] Build AWS-patched OpenVPN for darwin-amd64.
- [ ] Build AWS-patched OpenVPN for darwin-arm64.
- [x] Implement macOS DNS setup via AWS `client.up` / `client.down` scripts when using the installed AWS OpenVPN bundle.
- [x] Define current privilege story in README: macOS connect requires `sudo` when OpenVPN configures `utun`, routes, and DNS scripts.
- [ ] Test Intel Mac.
- [ ] Test Apple Silicon.

Acceptance:

- CLI connects on macOS with packaged OpenVPN.
- DNS/routes restore after disconnect.

## Open Questions

1. Should the public crate name be `awsvpn`, `aws_vpn_unofficial`, or something else?
2. Should `VpnClient::connect` return only after connected, or return immediately with a session that emits progress events?
3. Should the library own signal handling, or should only the CLI install Ctrl-C handlers?
4. Should SAML login URL ever be emitted as a public event, or only printed behind `--print-login-url`?
5. Should profile management live in the core library or a separate optional feature?
6. Should DNS management be enabled by default once implemented, or remain opt-in per platform?
7. Should we support alternate ACS ports experimentally, or hard-code `35001` for AWS compatibility?
8. Should we use `hyper` for ACS or a tiny purpose-built HTTP parser?

## Immediate Next Steps

1. Convert `Cargo.toml` into a library-plus-binary crate with real dependencies.
2. Add `src/lib.rs`, `src/error.rs`, `src/client.rs`, and basic public types.
3. Implement `clap` CLI with a `connect` command.
4. Implement parser and redaction first, before process spawning.
5. Add fake management server tests before testing against a real AWS endpoint.

The first useful deliverable should be a tested protocol core, not a working process wrapper. Once the parser, ACS server, and fake management flow are solid, wiring in real OpenVPN becomes much lower risk.
