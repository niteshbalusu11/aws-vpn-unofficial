# Third-Party Notices

`awsvpn` can embed and redistribute an AWS-patched OpenVPN runtime so release
artifacts and `cargo install` builds can produce a single executable.

## AWS Client VPN OpenVPN Runtime

The embedded OpenVPN runtime is built from AWS's published source tarball:

```text
https://amazon-source-code-downloads.s3.amazonaws.com/aws/clientvpn/openvpn-2.6.12-aws-1.tar.gz
```

The runtime source tarball contains OpenVPN and OpenSSL sources. The build
script records the source URL, source checksum, and target triple in each
runtime's `README.runtime.txt`.

OpenVPN is GPL-licensed. Because this project can redistribute OpenVPN in the
same single-binary artifact, this repository is licensed as GPL-2.0-only.

## macOS DNS Helper Scripts

The macOS `client.up` and `client.down` helper scripts in this repository are
original minimal shell scripts. They are not copied from the AWS VPN Client or
Tunnelblick helper scripts.
