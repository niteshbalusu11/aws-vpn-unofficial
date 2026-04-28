# AGENTS.md

## Project

AWS VPN Unofficial is a Rust library plus thin CLI for AWS Client VPN SAML
profiles. The CLI embeds an AWS-compatible OpenVPN runtime, drives the OpenVPN
management protocol, handles browser-based SAML auth, and configures temporary
DNS where supported.

## Important Crates

- `tokio`: async networking, process management, signal handling, and tests.
- `clap`: CLI argument parsing.
- `tracing` / `tracing-subscriber`: logs and debug output.
- `url`: SAML URL validation.
- `webbrowser`: browser launch for SAML auth.
- `thiserror`: public error types.

## Important Files

- `src/lib.rs`: public library exports.
- `src/main.rs`: CLI wrapper over the library.
- `src/client.rs`: connection orchestration and session cleanup.
- `src/openvpn/`: OpenVPN process, management protocol, commands, and parsers.
- `src/saml/`: ACS callback server, browser launcher, and SAML flow.
- `src/dns.rs`: macOS/Linux DNS setup and restore guards.
- `src/runtime.rs`: bundled OpenVPN runtime extraction.
- `assets/openvpn-runtime/`: committed runtime assets embedded into release binaries.
- `packaging/openvpn/`: scripts/docs for rebuilding OpenVPN runtimes.
- `scripts/validate-runtime-assets.sh`: validates committed runtime asset layout.

## Notes

Keep the library-first API intact. Do not log SAML assertions, management
passwords, or private config contents. User OpenVPN configs run under elevated
privileges, so script/plugin directives should remain rejected unless the trust
model is deliberately changed.
