# AWS-Compatible OpenVPN Runtime

This directory contains build tooling for the OpenVPN executable that `awsvpn`
will bundle in self-contained releases.

## Source Strategy

The primary input is AWS's published patched source tarball:

```text
https://amazon-source-code-downloads.s3.amazonaws.com/aws/clientvpn/openvpn-2.6.12-aws-1.tar.gz
```

That tarball contains two source trees:

- `openvpn/`
- `openssl/`

The current script builds bundled OpenSSL first, then builds OpenVPN against
that OpenSSL and stages this runtime layout:

```text
target/openvpn-runtime/<target>/openvpn/
  acvc-openvpn
  openssl.cnf
  client.up       # macOS only
  client.down     # macOS only
  README.runtime.txt
```

The macOS `client.up` and `client.down` scripts are original minimal helpers
for applying OpenVPN-pushed DNS to the active primary network service and
restoring it on disconnect. They are intentionally not copied from the AWS
Client VPN/Tunnelblick GPL scripts.

## Build

Native build:

```bash
packaging/openvpn/build-openvpn.sh
```

Nix-backed native build:

```bash
nix develop -c packaging/openvpn/build-openvpn.sh
```

Build and stage the runtime as an embedded Rust asset:

```bash
nix develop -c env EMBED_RUNTIME=1 packaging/openvpn/build-openvpn.sh
```

That copies the staged runtime into:

```text
assets/openvpn-runtime/<target>/openvpn/
```

`build.rs` embeds files from that directory into the `awsvpn` executable for
the matching Cargo target.

Target override:

```bash
TARGET=x86_64-unknown-linux-gnu packaging/openvpn/build-openvpn.sh
```

Useful overrides:

```text
SOURCE_URL              AWS source tarball URL
SOURCE_SHA256           expected tarball checksum, empty disables verification
TARGET                  runtime target triple
WORK_DIR                build work directory
DIST_DIR                staged runtime output directory
OPENSSL_TARGET          OpenSSL Configure target override
OPENVPN_CONFIGURE_ARGS  extra OpenVPN ./configure arguments
EMBED_RUNTIME           when set to 1, copy staged runtime into assets/openvpn-runtime
JOBS                    make parallelism
```

## Patch-Based Workflow

The `aws-vpn-client/aws-vpn-client` repository contains extracted patch files
for OpenVPN 2.6.12 and OpenSSL 3.0.14. Its `extract.sh` script shows how those
patches are derived from AWS's tarball by diffing against upstream OpenVPN.

We should treat that as an audit/rebase workflow:

1. Download AWS's source tarball.
2. Diff AWS OpenVPN against upstream OpenVPN tag `v2.6.12`.
3. Extract any OpenSSL patches from `openvpn/openssl-patches/`.
4. Review and vendor a small patch queue only if we need to build from pristine
   upstream OpenVPN/OpenSSL sources.

For now, building directly from the AWS tarball is simpler and more faithful to
what AWS publishes.

## Current Limitations

- Cross compilation is not fully automated yet.
- Linux DNS helper scripts are not implemented yet. Linux currently requires a
  native DNS integration path or `--dns disabled`.
