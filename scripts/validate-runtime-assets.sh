#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -gt 0 ]]; then
  TARGETS=("$@")
else
  TARGETS=(
    aarch64-apple-darwin
    x86_64-apple-darwin
    aarch64-unknown-linux-gnu
    x86_64-unknown-linux-gnu
  )
fi

fail_arch() {
  printf 'runtime binary architecture mismatch for %s: %s\n' "$1" "$2" >&2
  exit 1
}

require_helper() {
  if [[ ! -f "$1" ]]; then
    printf 'missing macOS DNS helper for %s: %s\n' "$2" "$1" >&2
    exit 1
  fi
}

for target in "${TARGETS[@]}"; do
  runtime_dir="$ROOT_DIR/assets/openvpn-runtime/$target/openvpn"
  binary="$runtime_dir/acvc-openvpn"
  readme="$runtime_dir/README.runtime.txt"
  openssl_config="$runtime_dir/openssl.cnf"

  if [[ ! -d "$runtime_dir" ]]; then
    printf 'missing runtime directory: %s\n' "$runtime_dir" >&2
    exit 1
  fi

  for required in "$binary" "$readme" "$openssl_config"; do
    if [[ ! -f "$required" ]]; then
      printf 'missing runtime file for %s: %s\n' "$target" "$required" >&2
      exit 1
    fi
  done

  if ! grep -q "Target: $target" "$readme"; then
    printf 'runtime README has wrong target for %s: %s\n' "$target" "$readme" >&2
    exit 1
  fi

  file_output="$(file "$binary")"
  case "$target" in
    aarch64-apple-darwin)
      [[ "$file_output" == *"Mach-O 64-bit executable arm64"* ]] || fail_arch "$target" "$file_output"
      require_helper "$runtime_dir/client.up" "$target"
      require_helper "$runtime_dir/client.down" "$target"
      ;;
    x86_64-apple-darwin)
      [[ "$file_output" == *"Mach-O 64-bit executable x86_64"* ]] || fail_arch "$target" "$file_output"
      require_helper "$runtime_dir/client.up" "$target"
      require_helper "$runtime_dir/client.down" "$target"
      ;;
    aarch64-unknown-linux-gnu)
      [[ "$file_output" == *"ELF 64-bit"* && "$file_output" == *"ARM aarch64"* ]] || fail_arch "$target" "$file_output"
      ;;
    x86_64-unknown-linux-gnu)
      [[ "$file_output" == *"ELF 64-bit"* && "$file_output" == *"x86-64"* ]] || fail_arch "$target" "$file_output"
      ;;
    *)
      printf 'unknown target: %s\n' "$target" >&2
      exit 1
      ;;
  esac

  printf 'validated runtime asset for %s\n' "$target"
done
