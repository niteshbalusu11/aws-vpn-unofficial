# Reliability Notes

This note records the local AWS VPN Client comparison used to harden `awsvpn`.
The installed AWS app inspected on this machine is:

- App: `/Applications/AWS VPN Client/AWS VPN Client.app`
- Version: `5.3.5`
- OpenVPN runtime: `Contents/Resources/openvpn/acvc-openvpn`
- Helper: `Contents/Resources/AWS VPN Client/Contents/MacOS/ACVCHelperTool`

## AWS Behaviors Observed

The installed app contains these reliability mechanisms:

- OpenVPN management reconnect handling. The managed assemblies include
  `RECONNECTING`, `BeginSoftReconnect`, `ReconnectImpl`, `ping-restart`, and
  auth-failure handling paths.
- Process liveness supervision. The helper exposes `--isAlive`, logs
  `Helper app - starting isAlive monitoring for OVPN PID`, and the managed code
  has `IsOpenVpnAlive`, `OvpnProcessDiedException`, and process-died de-duping.
- DNS drift repair. The OpenVPN scripts write DNS state under
  `/Library/Application Support/AWSVPNClient`, and `fix-dns.sh` restores the
  OpenVPN DNS settings when the app detects DNS drift.
- Route drift validation and repair. The helper exposes `--scanRoutingTable`
  and `--validateRouteChange`, tracks route backup checksums, and can restore
  missing VPN routes.

## Implemented Safeguards

`awsvpn` now implements the non-privileged equivalents needed for the common
"VPN goes down and I need to reconnect" failure modes:

- Keeps the OpenVPN management socket supervised after the initial connection.
  Reconnect auth prompts reuse the SAML flow instead of leaving OpenVPN waiting.
- Reports management socket closure or monitor failure without terminating
  OpenVPN. This avoids false-positive liveness failures causing repeated SAML
  browser launches.
- Keeps daemon mode alive after unexpected OpenVPN exits and reconnects with
  capped exponential backoff.
- On macOS native DNS mode, monitors whether the active network service still
  points at the VPN DNS proxy and reapplies it if DNS drifts.
- Captures pushed IPv4 routes from `PUSH_REPLY`. On macOS, if expected pushed
  routes disappear from `utun`, emits a warning instead of restarting the
  session.

The route strategy intentionally differs from AWS. AWS can repair routes in a
privileged helper with route checksums. This project currently avoids adding a
new privileged helper and does not restart automatically from route drift alone,
because route-table parsing can false-positive and repeatedly reopen SAML auth.

## Verification

Automated gates:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
bash -n scripts/reliability-soak.sh
```

Manual soak test before claiming production parity:

1. Start daemon mode with debug logs:

   ```bash
   sudo -E target/debug/awsvpn connect --debug
   ```

2. Confirm status remains connected:

   ```bash
   sudo -E target/debug/awsvpn status
   sudo -E target/debug/awsvpn diagnose
   ```

3. Leave the session running through the failure window that previously caused
   disconnects. Check that `status` returns to `connected` without a manual
   `reconnect`.

4. Exercise recovery paths where safe:

   - Kill the child OpenVPN process and confirm daemon mode reconnects.
   - Temporarily change macOS DNS and confirm `diagnose` returns to VPN DNS.
   - If a test profile pushes routes, remove or disturb a pushed route and
     confirm a warning is emitted without reopening the SAML browser.

5. Finish with:

   ```bash
   sudo -E target/debug/awsvpn disconnect
   ```

Completion requires the soak test to show automatic recovery without leaking
SAML assertions, management passwords, private configs, DNS state, or routes.

The manual status/process-restart portions can be run with:

```bash
cargo build
scripts/reliability-soak.sh --duration 3600 --exercise-process-restart -- --debug
```
