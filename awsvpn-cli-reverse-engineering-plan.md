# AWS Client VPN CLI: Reverse-Engineering Notes and Engineering Plan

Date: 2026-04-28

This document summarizes what was found by inspecting the installed AWS VPN Client for macOS, comparing AWS's patched OpenVPN source to upstream OpenVPN, and checking AWS Client VPN documentation. It is intended as an implementation brief for building a small cross-platform CLI that can connect to AWS Client VPN endpoints using SAML authentication.

The desired user experience is:

```bash
sudo awsvpn connect ./client-config.ovpn
```

The CLI may start helper processes internally, but the user should only interact with one command.

## Problem

AWS Client VPN is OpenVPN-based, but SAML-authenticated Client VPN endpoints do not work with ordinary OpenVPN clients. AWS only ships its official client for selected platforms, which creates friction on non-Ubuntu Linux distros and other unsupported environments.

AWS documents this limitation directly:

- Generic OpenVPN clients cannot connect to Client VPN endpoints configured with SAML federated authentication.
- The AWS-provided client supports SAML authentication, Client Route Enforcement, device settings monitoring, and some AWS-specific behaviors.

Relevant AWS docs:

- SAML federated auth workflow: https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/federated-authentication.html
- AWS-provided client and supported OpenVPN directives: https://docs.aws.amazon.com/vpn/latest/clientvpn-user/connect-aws-client-vpn-connect.html
- Generic OpenVPN client limitation for SAML endpoints: https://docs.aws.amazon.com/vpn/latest/clientvpn-user/linux.html
- macOS client release notes: https://docs.aws.amazon.com/vpn/latest/clientvpn-user/client-vpn-connect-macos-release-notes.html

## Key Finding

AWS is not using a completely different VPN protocol. It is using OpenVPN with a SAML wrapper flow.

The official AWS VPN Client:

1. Starts a patched OpenVPN binary.
2. Controls OpenVPN through the OpenVPN management interface.
3. Opens a browser for SAML login.
4. Runs a localhost Assertion Consumer Service (ACS) HTTP server.
5. Receives the SAML response from the browser.
6. Sends that SAML response back to the Client VPN endpoint through OpenVPN's dynamic challenge/response authentication path.

The OpenVPN patches are mostly size-related. They allow a large SAML response to fit through fields that were originally sized for usernames, passwords, and small challenge responses.

## Local macOS Inspection Summary

Installed app:

```text
/Applications/AWS VPN Client/AWS VPN Client.app
```

Observed version:

```text
5.3.4
```

Main bundle identifier:

```text
com.amazonaws.acvc.osx
```

The app is a Xamarin/Mono-style macOS application. The orchestration logic lives largely in managed assemblies under:

```text
/Applications/AWS VPN Client/AWS VPN Client.app/Contents/MonoBundle/
```

Important assemblies:

```text
AWS VPN Client.dll
AWSVPNClient.Core.dll
```

The bundled OpenVPN binary is:

```text
/Applications/AWS VPN Client/AWS VPN Client.app/Contents/Resources/openvpn/acvc-openvpn
```

Observed OpenVPN version:

```text
OpenVPN 2.6.12
OpenSSL 3.0.18
```

The installed app includes a third-party license file that references AWS's OpenVPN source package:

```text
https://amazon-source-code-downloads.s3.amazonaws.com/aws/clientvpn/openvpn-2.6.12-aws-1.tar.gz
```

The old-looking URL in the license file using `downloads.s3.amazonaws.com` returned `403`; the `amazon-source-code-downloads.s3.amazonaws.com` host worked.

## Observed Runtime Shape

While connected, AWS VPN Client was running its OpenVPN binary with arguments structurally like this:

```text
acvc-openvpn
  --config <generated-temp-config>
  --management 127.0.0.1 <port> <management-password-file>
  --management-query-passwords
  --management-hold
  --push-peer-info
  --setenv UV_AWS_CLIENT_APP_VER 5.3.4
  --setenv UV_AWS_CLIENT_PLATFORM mac
  --script-security 2
  --up <client.up>
  --down <client.down>
```

The official app wraps OpenVPN. It does not require the user to start OpenVPN manually.

For our CLI, this means `awsvpn connect` can start OpenVPN as a child process internally. The user still sees one command.

## Imported Profile Shape

The imported `.ovpn` profile was ordinary OpenVPN configuration plus the auth options needed for AWS SAML:

```text
client
dev tun
proto udp
remote cvpn-endpoint-... 443
remote-random-hostname
resolv-retry infinite
nobind
remote-cert-tls server
cipher AES-256-GCM
verb 3
<ca>
...
</ca>
auth-user-pass
auth-retry interact
auth-nocache
reneg-sec 0
```

Important point: the SAML login URL and SAML response are not statically stored in the `.ovpn` file. They are exchanged at connection time through OpenVPN's authentication challenge flow.

AWS also supports an `auth-federate` directive in AWS-provided client profiles, but the observed imported profile used `auth-user-pass` with the management-driven SAML flow.

## SAML Authentication Flow

AWS documents the high-level SAML flow:

1. User starts connection.
2. Client VPN endpoint sends an IdP URL and auth request to the client.
3. AWS client opens the browser.
4. User authenticates with the IdP.
5. IdP sends a signed SAML assertion back to the client.
6. Client sends the SAML assertion to the Client VPN endpoint.
7. Endpoint validates and allows or denies access.

AWS documents these SAML constraints:

- ACS URL: `http://127.0.0.1:35001`
- Audience URI: `urn:amazon:webservices:clientvpn`
- SAML response max size: `128 KB`
- AuthN request uses HTTP Redirect binding.
- Browser posts the SAML response back to localhost.

## Actual OpenVPN Management Flow

The managed AWS code shows this flow.

First, start a local ACS server:

```text
http://127.0.0.1:35001/
```

Then send initial auth data to OpenVPN through the management interface:

```text
username "Auth" N/A
password "Auth" ACS::35001
```

The AWS Client VPN endpoint responds with an OpenVPN CRV1 challenge. It looks structurally like:

```text
>PASSWORD:Verification Failed: 'Auth' ['CRV1:R:<state_id>:b'Ti9B':<saml_url>']
```

Where:

- `R` means a response is required.
- `<state_id>` is opaque and must be returned later.
- `b'Ti9B'` corresponds to the placeholder username `N/A`.
- `<saml_url>` is an HTTPS URL that starts the IdP/browser flow.

The client must:

1. Validate the SAML URL is well-formed and uses `https`.
2. Open the URL in the browser.
3. Wait for the browser/IdP to POST to `http://127.0.0.1:35001/`.
4. Extract `SAMLResponse` from the form body.
5. Wait for OpenVPN's next auth prompt.
6. Send:

```text
username "Auth" N/A
password "Auth" CRV1::<state_id>::<SAMLResponse>
```

The SAML response should be treated as sensitive. Do not log it.

## AWS Managed Code Details

Decompiled class names from `AWSVPNClient.Core.dll`:

```text
ACVC.Core.Auth.SamlAuthenticator
ACVC.Core.Saml.SamlAcs
ACVC.Core.Saml.SamlManager
ACVC.Core.Utils.SamlUtils
ACVC.Core.OpenVpn.OvpnManagement
```

Important constants and behavior found in the managed code:

```text
SamlPortRange = [35001]
SamlUsernameOvpnMsg = username "Auth" N/A
SamlPortStringOvpnMsgFormat = password "Auth" ACS::{port}
SamlAssertionOvpnMsgFormat = password "Auth" CRV1::{stateId}::{rawSamlAssertion}
MaxSamlAssertionLenBytes = 131072
SAML timeout = 600000 ms
```

The local ACS server:

- Listens on `http://127.0.0.1:35001/`.
- Accepts only `POST /`.
- Reads form body.
- Extracts `SAMLResponse=(.*?)(?:&|$)`.
- Returns a small success/failure HTML page to the browser.
- Raises an event to the SAML manager with the extracted assertion.

The SAML URL is validated before opening:

- Must be an absolute URI.
- Must be well-formed.
- Must use `https`.

## AWS OpenVPN Patch Summary

Compared AWS's `openvpn-2.6.12-aws-1` source against upstream OpenVPN `2.6.12`.

The relevant patches are mostly larger buffers and payload lengths.

### User/Password Size

File:

```text
src/openvpn/misc.h
```

Upstream:

```c
#define USER_PASS_LEN 128
```

AWS:

```c
#define USER_PASS_LEN 1 << 17
```

That is `131072` bytes, matching AWS's documented SAML response max.

### OpenVPN Option/Management Buffers

Files:

```text
src/openvpn/options.h
src/openvpn/manage.h
src/openvpn/manage.c
```

AWS changes option parameter and management buffers to scale with `USER_PASS_LEN`, not small fixed values such as `256` or `1024`.

Examples:

```c
#define OPTION_PARM_SIZE USER_PASS_LEN
#define OPTION_LINE_SIZE OPTION_PARM_SIZE
#define COMMAND_LINE_OPTION_BUFFER_SIZE OPTION_PARM_SIZE
#define MANAGEMENT_SOCKET_READ_BUFFER_SIZE OPTION_PARM_SIZE
```

Management output write size hint changed from `1024` to `8192`.

### TLS/Error Buffers

Files:

```text
src/openvpn/common.h
src/openvpn/error.h
src/openvpn/buffer.h
```

AWS expands sizes such as:

```c
#define TLS_CHANNEL_BUF_SIZE 1 << 18
#define ERR_BUF_SIZE 1 << 18
#define BUF_SIZE_MAX 1 << 21
```

### Auth Payload Length Encoding

File:

```text
src/openvpn/ssl.c
```

AWS changes auth string length writes from 16-bit to 32-bit:

```c
buf_write_u16(...)
```

to:

```c
buf_write_u32(...)
```

AWS also writes the key/auth payload length into the first 4 octets of the buffer.

This appears necessary because a large SAML assertion can exceed the assumptions in the standard username/password encoding path.

## Architecture Recommendation

Build a CLI wrapper around AWS-patched OpenVPN, rather than trying to embed OpenVPN into the CLI process.

Recommended structure:

```text
awsvpn
  starts local ACS server on 127.0.0.1:35001
  starts patched OpenVPN as a child process
  connects to OpenVPN management socket
  drives SAML auth
  streams/sanitizes logs
  handles signals and cleanup
```

The user only runs:

```bash
sudo awsvpn connect ./client-config.ovpn
```

Internally starting OpenVPN as a child process is the least invasive and most maintainable design.

Avoid trying to put the SAML browser flow directly inside OpenVPN C code for v1. That would work, but it would:

- Increase merge burden against future OpenVPN releases.
- Mix browser/HTTP/UI behavior into a VPN daemon.
- Make cross-platform behavior harder.
- Make security review more complicated.

## Recommended Language

Go is the pragmatic choice for v1.

Reasons:

- Good subprocess control.
- Simple local HTTP server.
- Easy cross-platform browser launching.
- Good signal handling.
- Easy static-ish CLI distribution.
- Fast implementation for system-wrapper tools.

Rust is also viable, but Go is likely faster for the first working version.

## CLI Design

Initial commands:

```bash
awsvpn connect <config.ovpn>
awsvpn connect <profile-name>
awsvpn disconnect
awsvpn status
awsvpn version
```

Optional later commands:

```bash
awsvpn import <config.ovpn> --name <name>
awsvpn profiles
awsvpn logs
awsvpn doctor
```

MVP can skip persistent profile storage and accept a config path directly.

## MVP Behavior

`awsvpn connect ./client-config.ovpn` should:

1. Validate the `.ovpn` file exists.
2. Create a temp working directory with restrictive permissions.
3. Generate a management password file.
4. Start ACS server on `127.0.0.1:35001`.
5. Start patched OpenVPN with:

```text
--config <config>
--management 127.0.0.1 <random-management-port> <password-file>
--management-query-passwords
--management-hold
--auth-nocache
--script-security 2
```

6. Connect to management interface.
7. Authenticate to management interface if prompted.
8. Enable useful management notifications:

```text
state on
log on
echo on
hold release
```

9. On first `>PASSWORD:Need 'Auth' username/password`, send:

```text
username "Auth" N/A
password "Auth" ACS::35001
```

10. On CRV1 SAML challenge:

```text
>PASSWORD:Verification Failed: 'Auth' ['CRV1:R:<state_id>:b'Ti9B':<saml_url>']
```

Extract:

- `state_id`
- `saml_url`

11. Validate `saml_url`.
12. Open browser.
13. Wait for SAML response POST to ACS server.
14. On next `>PASSWORD:Need`, send:

```text
username "Auth" N/A
password "Auth" CRV1::<state_id>::<SAMLResponse>
```

15. Watch for:

```text
CONNECTED,SUCCESS
AUTH_FAILED
EXITING
FATAL
```

16. Keep running until user interrupts.
17. On SIGINT/SIGTERM:

```text
signal SIGTERM
quit
```

Then wait for OpenVPN to exit and clean temp files.

## Management Interface Notes

OpenVPN management commands are line-based. Values containing spaces or special characters may need quoting/escaping. The SAML response is URL-encoded form data and usually safe as a single token, but implementation should still use a robust management-command escaping function.

Useful parser events:

```text
>PASSWORD:Need 'Auth' username/password
>PASSWORD:Verification Failed: 'Auth' ['CRV1:R:...']
SUCCESS: 'Auth' username entered, but not yet verified
SUCCESS: 'Auth' password entered, but not yet verified
>STATE:...,CONNECTED,SUCCESS,...
>STATE:...,RECONNECTING,auth-failure,...
>FATAL:
```

The SAML CRV1 regex used by AWS is structurally:

```regex
>PASSWORD:Verification Failed: 'Auth' \['CRV1:R:(.+):b'Ti9B':(.+)'\]
```

Use a stricter parser if possible:

- Prefix must match exactly.
- State ends before `:b'Ti9B':`.
- URL is the remaining content before closing `']`.
- URL must be HTTPS.

## Local ACS Server

Bind only to loopback:

```text
127.0.0.1:35001
```

Do not bind to `0.0.0.0`.

Accept:

```text
POST /
Content-Type: application/x-www-form-urlencoded
```

Extract:

```text
SAMLResponse
```

Rules:

- Reject or fail if missing.
- Enforce max length `131072`.
- Do not log the value.
- Return a tiny HTML success/failure page.
- Stop the listener after receiving one valid response or on timeout.
- Timeout after 10 minutes.

Note: AWS uses fixed port `35001`. This means only one SAML auth flow can reliably be active at a time unless you implement deeper compatibility testing with alternate ports. AWS's code has a `SamlPortRange`, but the observed value is only `[35001]`.

## Browser Launch

Platform commands:

```text
macOS:   open <url>
Linux:   xdg-open <url>
Windows: rundll32 url.dll,FileProtocolHandler <url>
```

Prefer native APIs where easy:

- Go: `exec.Command` is enough for MVP.
- Ensure the URL is passed as an argument, not shell-interpolated.
- Do not use `sh -c`.

## Patched OpenVPN Build Plan

Use AWS's source package:

```text
https://amazon-source-code-downloads.s3.amazonaws.com/aws/clientvpn/openvpn-2.6.12-aws-1.tar.gz
```

Initial build targets:

```text
linux-amd64
linux-arm64
darwin-amd64
darwin-arm64
```

Later:

```text
windows-amd64
windows-arm64
```

OpenVPN itself has platform-specific dependencies and driver needs, so packaging the binary is more involved than packaging the Go CLI.

For Linux MVP:

- Build AWS-patched OpenVPN.
- Depend on existing system TUN support.
- Run as root or with capabilities sufficient for TUN/routes.
- Use OpenVPN native route setup initially.
- DNS support can be minimal at first, then improved.

For macOS MVP:

- You can temporarily test against the installed AWS `acvc-openvpn`.
- For distribution, build/package your own OpenVPN binary.
- Need route/DNS handling similar to Tunnelblick scripts or a simpler `scutil` implementation.

## DNS and Routing Plan

The SAML handshake is the interesting part, but DNS/routes are what make the VPN actually usable.

### Linux

Start simple:

- Let OpenVPN add routes.
- Use `--script-security 2`.
- Provide an up/down script for DNS.

Handle DNS integrations in phases:

1. No DNS management; document limitation.
2. `resolvconf` support.
3. `systemd-resolved` support via `resolvectl`.
4. NetworkManager integration if needed.

For systemd-resolved:

```bash
resolvectl dns <tun-iface> <dns-ip>
resolvectl domain <tun-iface> ~.
```

For split DNS, apply pushed search domains when available.

### macOS

AWS uses Tunnelblick-derived scripts and `scutil` state keys.

MVP options:

1. Reuse/adapt Tunnelblick-style up/down scripts.
2. Implement direct `scutil` DNS setup in the CLI.

For a CLI, scripts are likely faster for v1, but direct implementation is cleaner long-term.

### Windows

Windows should not be v1 unless required.

Needs:

- TAP or Wintun adapter strategy.
- Elevated route/DNS changes.
- Service or privileged helper for better UX.
- Careful cleanup on process crash.

## Security Requirements

Treat these as hard requirements:

- Never log `SAMLResponse`.
- Never log management password.
- Create temp files with `0600` permissions.
- Bind ACS only to `127.0.0.1`.
- Validate SAML login URL is HTTPS.
- Do not shell-interpolate browser command.
- Redact `password "Auth" ...` in logs.
- Redact `AUTH_FAILED,CRV1:...:<url>` if logs may leave the machine.
- Delete temp management password files on exit.
- Handle SIGINT/SIGTERM and cleanup OpenVPN.
- Avoid storing SAML assertions or auth tokens.

Potential local threat:

- A local process could race to bind `127.0.0.1:35001`.
- A local process could attempt to POST to the ACS endpoint.

Mitigations:

- Start ACS immediately before auth.
- Accept only one POST.
- Validate there is an active pending state.
- Use short timeout.
- Do not accept non-loopback requests.

AWS's official client appears to rely primarily on the fixed localhost ACS behavior as documented.

## Legal and Licensing Notes

OpenVPN is GPL-licensed. AWS's patched OpenVPN source is distributed as OpenVPN source. If this project distributes a patched OpenVPN binary, it must comply with OpenVPN's license obligations.

Simplest compliance approach:

- Keep patched OpenVPN source in a separate package or submodule.
- Publish exact source and build instructions for the bundled OpenVPN binary.
- Include OpenVPN license notices.
- Keep the CLI wrapper separate if you want its license to differ, but get legal review if distributing a combined package.

Do not redistribute AWS proprietary application code or assets.

The implementation should be based on:

- Official AWS documentation.
- AWS-published OpenVPN source package.
- Observable protocol behavior.
- Independently written wrapper code.

## Project Layout Proposal

```text
awsvpn/
  cmd/awsvpn/
    main.go
  internal/config/
    ovpn.go
  internal/openvpn/
    process.go
    management.go
    parser.go
  internal/saml/
    acs.go
    browser.go
    flow.go
  internal/platform/
    browser_darwin.go
    browser_linux.go
    browser_windows.go
    dns_linux.go
    dns_darwin.go
  internal/logredact/
    redact.go
  packaging/
    openvpn/
    linux/
    macos/
  testdata/
    management/
```

## Implementation Milestones

### Milestone 1: Protocol Prototype

Goal: prove the SAML/OpenVPN management flow works.

Tasks:

- Implement local ACS server.
- Implement browser launch.
- Implement OpenVPN management socket client.
- Implement parser for:
  - password prompt
  - CRV1 SAML challenge
  - connected state
  - auth failure
  - fatal errors
- Start OpenVPN as child process.
- Drive the auth flow.
- Redact logs.

Accept criteria:

- `sudo awsvpn connect ./client.ovpn` opens browser.
- Browser login completes.
- VPN reaches `CONNECTED,SUCCESS`.
- Ctrl-C disconnects cleanly.

### Milestone 2: Linux Usability

Goal: make it usable on non-Ubuntu Linux.

Tasks:

- Build AWS-patched OpenVPN for Linux.
- Package CLI + OpenVPN binary.
- Add DNS handling for common environments.
- Add route cleanup verification.
- Add `awsvpn status`.
- Add robust signal handling.

Accept criteria:

- Works on at least Fedora, Arch, NixOS, and Debian/Ubuntu.
- DNS resolves private AWS hostnames after connect.
- DNS/routes restore after disconnect.

### Milestone 3: Profile Management

Goal: remove need to pass config paths every time.

Tasks:

- `awsvpn import config.ovpn --name prod`
- Store profiles under:

```text
~/.config/awsvpn/profiles/
```

- `awsvpn profiles`
- `awsvpn connect prod`
- Validate profile permissions.

Accept criteria:

- Multiple profiles can be stored.
- Profile names are stable and shell-friendly.
- Imported configs are not accidentally world-readable.

### Milestone 4: macOS Support

Goal: support macOS without depending on the installed AWS app.

Tasks:

- Build/package patched OpenVPN for macOS.
- Implement or package route/DNS scripts.
- Handle privilege escalation story.
- Support Apple Silicon.

Accept criteria:

- Works on macOS arm64 and x64.
- DNS/routes restore after disconnect.

### Milestone 5: Hardening

Tasks:

- Unit tests for management parser.
- Unit tests for log redaction.
- Integration test using fake OpenVPN management server.
- Fuzz CRV1 parser.
- Add `awsvpn doctor`.
- Add structured debug bundle that redacts secrets.

Accept criteria:

- Debug logs are useful without leaking SAML responses.
- Failure modes produce actionable CLI errors.

## Testing Strategy

### Unit Tests

Parser fixtures:

```text
>PASSWORD:Need 'Auth' username/password
>PASSWORD:Verification Failed: 'Auth' ['CRV1:R:state123:b'Ti9B':https://idp.example.com/saml?...']
>STATE:123,CONNECTED,SUCCESS,10.0.0.10,1.2.3.4,443,,
>FATAL:...
```

Test:

- CRV1 extraction.
- HTTPS URL validation.
- Invalid URL rejection.
- Assertion max size enforcement.
- Redaction of management commands.

### Fake Management Server

Build a small test server that emulates OpenVPN management:

1. Accept connection.
2. Prompt for auth.
3. Expect `ACS::35001`.
4. Send CRV1 challenge.
5. Prompt again.
6. Expect `CRV1::<state>::<assertion>`.
7. Send connected state.

This allows testing the CLI without hitting AWS.

### Real Integration Test

Requires an actual AWS Client VPN endpoint configured with SAML.

Run manually first:

```bash
sudo awsvpn connect ./client-config.ovpn --debug
```

Verify:

- Browser opens.
- SAML login succeeds.
- VPN gets an IP.
- Routes are present.
- DNS resolves private names.
- Disconnect restores DNS/routes.

## Failure Modes and CLI Messages

Examples:

### Port 35001 in Use

```text
error: cannot start SAML callback server on 127.0.0.1:35001
hint: another AWS VPN/SAML login flow may already be running
```

### Invalid SAML URL

```text
error: VPN endpoint returned an invalid SAML URL
hint: expected an absolute https URL
```

### Browser Launch Failed

```text
error: could not open browser
hint: open this URL manually: <redacted-or-expiring-url-policy>
```

Be careful with printing the SAML URL. It may be sensitive. A `--print-login-url` explicit flag is safer.

### SAML Timeout

```text
error: SAML login timed out after 10 minutes
```

### SAML Response Too Large

```text
error: SAML response exceeded 128 KB limit
```

### OpenVPN Auth Failed

```text
error: VPN authentication failed
hint: check IdP login, group authorization rules, and Client VPN endpoint configuration
```

## Open Questions

1. Should v1 support only profiles that contain `auth-user-pass`, or also normalize/import `auth-federate` profiles?
2. Can alternate ACS ports work in practice, or is `35001` effectively mandatory because of IdP configuration?
3. How much Client Route Enforcement behavior should be implemented?
4. Should Linux package use system OpenVPN if it is patched, or always bundle project OpenVPN?
5. What is the cleanest DNS strategy for NixOS?
6. Should the CLI maintain a privileged daemon for better UX, or require `sudo awsvpn connect`?

## Initial Build Checklist

1. Create Go CLI skeleton.
2. Implement `connect <ovpn>`.
3. Implement ACS server.
4. Implement browser opener.
5. Implement OpenVPN child process wrapper.
6. Implement management socket client.
7. Implement CRV1 parser.
8. Wire SAML flow.
9. Build AWS-patched OpenVPN for Linux.
10. Test against real AWS Client VPN endpoint.
11. Add DNS handling.
12. Add cleanup and signal handling.
13. Add packaging.

## Minimal Pseudocode

```go
func connect(configPath string) error {
    workdir := secureTempDir()
    defer cleanup(workdir)

    mgmtPasswordFile := writeManagementPassword(workdir)

    acs := saml.NewACS("127.0.0.1:35001", 10*time.Minute)
    defer acs.Stop()
    if err := acs.Start(); err != nil {
        return err
    }

    ovpn := openvpn.Start(openvpn.Args{
        Binary: patchedOpenVPNPath(),
        Config: configPath,
        ManagementHost: "127.0.0.1",
        ManagementPort: randomLocalPort(),
        ManagementPasswordFile: mgmtPasswordFile,
        QueryPasswords: true,
        Hold: true,
    })
    defer ovpn.Stop()

    mgmt := openvpn.DialManagement(ovpn.ManagementAddr())
    defer mgmt.Close()

    mgmt.EnableState()
    mgmt.EnableLog()
    mgmt.ReleaseHold()

    var samlState string
    var assertionCh <-chan string

    for event := range mgmt.Events() {
        switch e := event.(type) {
        case openvpn.PasswordPrompt:
            if samlState == "" {
                mgmt.SendUsername("Auth", "N/A")
                mgmt.SendPassword("Auth", "ACS::35001")
            } else {
                assertion := <-assertionCh
                mgmt.SendUsername("Auth", "N/A")
                mgmt.SendPassword("Auth", "CRV1::"+samlState+"::"+assertion)
            }

        case openvpn.SAMLChallenge:
            samlState = e.State
            if err := validateHTTPS(e.URL); err != nil {
                return err
            }
            assertionCh = acs.WaitForAssertion()
            browser.Open(e.URL)

        case openvpn.Connected:
            return waitUntilInterruptedThenDisconnect(ovpn, mgmt)

        case openvpn.Fatal:
            return e.Err
        }
    }

    return nil
}
```

## Bottom Line

The CLI is feasible.

The hard requirement is not a complex SAML library. The key requirement is using AWS-patched OpenVPN, because AWS sends a large SAML assertion through OpenVPN's username/password challenge path. The wrapper CLI should own the browser flow, localhost ACS server, OpenVPN management conversation, process lifecycle, and OS DNS/route setup.

For v1, build a Linux-first CLI that bundles AWS-patched OpenVPN and drives the exact management flow described above.
