#!/usr/bin/env bash
set -euo pipefail

SOURCE_URL="${SOURCE_URL:-https://amazon-source-code-downloads.s3.amazonaws.com/aws/clientvpn/openvpn-2.6.12-aws-1.tar.gz}"
SOURCE_SHA256="${SOURCE_SHA256:-a80ac3825bef9e97d717bc027663169903e25d86d2631e68f1100fcb2a9de702}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

TARGET="${TARGET:-}"
JOBS="${JOBS:-}"
WORK_DIR="${WORK_DIR:-}"
DIST_DIR="${DIST_DIR:-}"
TARBALL=""
SRC_DIR=""
OPENSSL_PREFIX=""
OPENSSL_BUILD_DIR=""
OPENVPN_BUILD_DIR=""

main() {
  case "${1:-}" in
    -h|--help)
      usage
      return 0
      ;;
  esac

  init_paths

  require_tool curl
  require_tool tar
  require_tool make
  require_tool perl
  require_tool shasum
  require_tool autoreconf
  require_tool pkg-config

  mkdir -p "$WORK_DIR/source" "$SRC_DIR" "$OPENSSL_PREFIX" "$DIST_DIR"

  download_source
  verify_source
  extract_source
  build_openssl
  build_openvpn
  stage_runtime

  printf 'OpenVPN runtime staged at %s\n' "$DIST_DIR"
}

usage() {
  cat <<EOF
Build AWS-compatible OpenVPN runtime.

Usage:
  packaging/openvpn/build-openvpn.sh

Environment overrides:
  SOURCE_URL              AWS source tarball URL
  SOURCE_SHA256           expected tarball checksum, empty disables verification
  TARGET                  runtime target triple
  WORK_DIR                build work directory
  DIST_DIR                staged runtime output directory
  OPENSSL_TARGET          OpenSSL Configure target override
  OPENVPN_CONFIGURE_ARGS  extra OpenVPN ./configure arguments
  JOBS                    make parallelism
EOF
}

init_paths() {
  TARGET="${TARGET:-$(detect_target)}"
  JOBS="${JOBS:-$(detect_jobs)}"
  WORK_DIR="${WORK_DIR:-$REPO_ROOT/target/openvpn-build/$TARGET}"
  DIST_DIR="${DIST_DIR:-$REPO_ROOT/target/openvpn-runtime/$TARGET/openvpn}"
  TARBALL="$WORK_DIR/source/openvpn-aws.tar.gz"
  SRC_DIR="$WORK_DIR/src"
  OPENSSL_PREFIX="$WORK_DIR/openssl-prefix"
  OPENSSL_BUILD_DIR="$WORK_DIR/build-openssl"
  OPENVPN_BUILD_DIR="$WORK_DIR/build-openvpn"
}

detect_target() {
  local machine system
  machine="$(uname -m)"
  system="$(uname -s)"

  case "$system:$machine" in
    Darwin:x86_64) printf 'x86_64-apple-darwin' ;;
    Darwin:arm64) printf 'aarch64-apple-darwin' ;;
    Linux:x86_64) printf 'x86_64-unknown-linux-gnu' ;;
    Linux:aarch64|Linux:arm64) printf 'aarch64-unknown-linux-gnu' ;;
    *) printf '%s-%s' "$machine" "$system" ;;
  esac
}

detect_jobs() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu
  else
    printf '2'
  fi
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$1" >&2
    exit 1
  fi
}

download_source() {
  if [[ -f "$TARBALL" ]]; then
    return
  fi

  printf 'Downloading %s\n' "$SOURCE_URL"
  curl -L --fail --show-error -o "$TARBALL" "$SOURCE_URL"
}

verify_source() {
  if [[ -z "$SOURCE_SHA256" ]]; then
    printf 'SOURCE_SHA256 is empty; skipping source checksum verification\n' >&2
    return
  fi

  local actual
  actual="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
  if [[ "$actual" != "$SOURCE_SHA256" ]]; then
    printf 'source checksum mismatch\nexpected: %s\nactual:   %s\n' "$SOURCE_SHA256" "$actual" >&2
    exit 1
  fi
}

extract_source() {
  if [[ -d "$SRC_DIR/openvpn" && -d "$SRC_DIR/openssl" ]]; then
    return
  fi

  rm -rf "$SRC_DIR"
  mkdir -p "$SRC_DIR"
  tar -xzf "$TARBALL" -C "$SRC_DIR"
}

build_openssl() {
  if [[ -f "$OPENSSL_PREFIX/lib/libssl.a" && -f "$OPENSSL_PREFIX/lib/libcrypto.a" ]]; then
    return
  fi

  rm -rf "$OPENSSL_BUILD_DIR" "$OPENSSL_PREFIX"
  cp -R "$SRC_DIR/openssl" "$OPENSSL_BUILD_DIR"

  pushd "$OPENSSL_BUILD_DIR" >/dev/null
  ./Configure "$(openssl_target)" \
    no-shared \
    no-tests \
    --prefix="$OPENSSL_PREFIX" \
    --openssldir="$OPENSSL_PREFIX/ssl"
  make -j"$JOBS"
  make install_sw install_ssldirs
  popd >/dev/null
}

openssl_target() {
  if [[ -n "${OPENSSL_TARGET:-}" ]]; then
    printf '%s' "$OPENSSL_TARGET"
    return
  fi

  case "$TARGET" in
    x86_64-apple-darwin) printf 'darwin64-x86_64-cc' ;;
    aarch64-apple-darwin) printf 'darwin64-arm64-cc' ;;
    x86_64-unknown-linux-gnu) printf 'linux-x86_64' ;;
    aarch64-unknown-linux-gnu) printf 'linux-aarch64' ;;
    *) printf 'Unsupported TARGET for OpenSSL auto mapping: %s\nSet OPENSSL_TARGET explicitly.\n' "$TARGET" >&2; exit 1 ;;
  esac
}

build_openvpn() {
  rm -rf "$OPENVPN_BUILD_DIR"
  cp -R "$SRC_DIR/openvpn" "$OPENVPN_BUILD_DIR"

  pushd "$OPENVPN_BUILD_DIR" >/dev/null
  autoreconf -fi

  local configure_args=(
    "--with-crypto-library=openssl"
    "--disable-dco"
    "--disable-lzo"
    "--disable-lz4"
    "--enable-comp-stub"
    "--disable-plugins"
    "--disable-plugin-auth-pam"
  )

  if [[ "$TARGET" == *linux* ]]; then
    configure_args+=("--enable-iproute2")
  fi

  PKG_CONFIG_PATH="$OPENSSL_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" \
    ./configure "${configure_args[@]}" ${OPENVPN_CONFIGURE_ARGS:-}

  make -j"$JOBS"
  popd >/dev/null
}

stage_runtime() {
  local openvpn_bin
  openvpn_bin="$(find "$OPENVPN_BUILD_DIR" -type f -path '*/src/openvpn/openvpn' -perm -111 | head -n 1)"
  if [[ -z "$openvpn_bin" ]]; then
    printf 'could not find built OpenVPN binary under %s\n' "$OPENVPN_BUILD_DIR" >&2
    exit 1
  fi

  rm -rf "$DIST_DIR"
  mkdir -p "$DIST_DIR"
  cp "$openvpn_bin" "$DIST_DIR/acvc-openvpn"
  cp "$OPENSSL_BUILD_DIR/apps/openssl.cnf" "$DIST_DIR/openssl.cnf"

  cat > "$DIST_DIR/README.runtime.txt" <<EOF
This runtime was built from AWS's patched OpenVPN source tarball.

Source: $SOURCE_URL
Source SHA256: $SOURCE_SHA256
Target: $TARGET
EOF
}

main "$@"
