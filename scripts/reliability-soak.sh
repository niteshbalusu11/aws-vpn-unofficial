#!/usr/bin/env bash
set -euo pipefail

duration_seconds=1800
interval_seconds=30
exercise_process_restart=0
config_args=()

usage() {
  cat <<'USAGE'
Usage: scripts/reliability-soak.sh [OPTIONS] [-- awsvpn connect args...]

Runs a sudo-backed reliability soak against the local awsvpn binary.

Options:
  --duration SECONDS          How long to watch status after connect. Default: 1800.
  --interval SECONDS          Status polling interval. Default: 30.
  --exercise-process-restart  Kill the OpenVPN child once and require daemon recovery.
  -h, --help                  Show this help.

Examples:
  cargo build
  scripts/reliability-soak.sh --duration 3600 --exercise-process-restart -- --debug
  scripts/reliability-soak.sh -- --debug --dns disabled
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      duration_seconds="${2:?missing value for --duration}"
      shift 2
      ;;
    --interval)
      interval_seconds="${2:?missing value for --interval}"
      shift 2
      ;;
    --exercise-process-restart)
      exercise_process_restart=1
      shift
      ;;
    --)
      shift
      config_args=("$@")
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! [[ "$duration_seconds" =~ ^[0-9]+$ ]] || [[ "$duration_seconds" -eq 0 ]]; then
  printf 'duration must be a positive integer\n' >&2
  exit 2
fi

if ! [[ "$interval_seconds" =~ ^[0-9]+$ ]] || [[ "$interval_seconds" -eq 0 ]]; then
  printf 'interval must be a positive integer\n' >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
awsvpn="$repo_root/target/debug/awsvpn"

if [[ ! -x "$awsvpn" ]]; then
  printf 'missing %s; run `cargo build` first\n' "$awsvpn" >&2
  exit 1
fi

require_connected() {
  local status
  status="$(sudo -E "$awsvpn" status)"
  printf '%s\n' "$status"
  if ! grep -q '^state: connected$' <<<"$status"; then
    printf 'VPN is not connected\n' >&2
    exit 1
  fi
}

openvpn_pid() {
  sudo -E "$awsvpn" status | awk '/^openvpn pid:/ { print $3; exit }'
}

cleanup() {
  sudo -E "$awsvpn" disconnect >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf 'starting awsvpn daemon session\n'
sudo -E "$awsvpn" connect "${config_args[@]}"
require_connected >/dev/null

if [[ "$exercise_process_restart" -eq 1 ]]; then
  pid="$(openvpn_pid)"
  if [[ -z "$pid" ]]; then
    printf 'could not determine OpenVPN PID for process restart exercise\n' >&2
    exit 1
  fi

  printf 'terminating OpenVPN child %s to verify daemon auto-reconnect\n' "$pid"
  sudo kill -TERM "$pid"

  deadline=$((SECONDS + 180))
  recovered=0
  while [[ "$SECONDS" -lt "$deadline" ]]; do
    sleep 5
    if sudo -E "$awsvpn" status | grep -q '^state: connected$'; then
      new_pid="$(openvpn_pid)"
      if [[ -n "$new_pid" && "$new_pid" != "$pid" ]]; then
        printf 'daemon recovered with OpenVPN child %s\n' "$new_pid"
        recovered=1
        break
      fi
    fi
  done

  if [[ "$recovered" -ne 1 ]]; then
    printf 'daemon did not reconnect within 180 seconds\n' >&2
    exit 1
  fi
fi

printf 'watching VPN status for %s seconds\n' "$duration_seconds"
end=$((SECONDS + duration_seconds))
while [[ "$SECONDS" -lt "$end" ]]; do
  require_connected >/dev/null
  sleep "$interval_seconds"
done

printf 'running final diagnostics\n'
sudo -E "$awsvpn" diagnose
printf 'reliability soak completed\n'
