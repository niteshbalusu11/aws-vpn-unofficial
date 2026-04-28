{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };

          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "rust-src"
              "rustfmt"
            ];
          };

          commonPackages = with pkgs; [
            autoconf
            automake
            bash
            coreutils
            curl
            file
            git
            gnumake
            libtool
            openssl
            patch
            perl
            pkg-config
            rustToolchain
            tokio-console
          ];

          linuxPackages = pkgs.lib.optionals pkgs.stdenv.isLinux (with pkgs; [
            gcc
            iproute2
            libcap_ng
            libnl
            nettools
            resolvconf
            systemd
          ]);

          darwinPackages = pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs; [
            darwin.cctools
          ]);
        in
        {
          default = pkgs.mkShell {
            name = "aws-vpn-unofficial-dev";

            packages = commonPackages ++ linuxPackages ++ darwinPackages;

            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

            shellHook = ''
              export AWSVPN_OPENVPN_SOURCE_URL="https://amazon-source-code-downloads.s3.amazonaws.com/aws/clientvpn/openvpn-2.6.12-aws-1.tar.gz"

              if [ "$(uname -s)" = "Darwin" ] && command -v xcrun >/dev/null 2>&1; then
                sdkroot="$(xcrun --sdk macosx --show-sdk-path)"
                deployment_target="''${MACOSX_DEPLOYMENT_TARGET:-14.0}"
                export SDKROOT="$sdkroot"
                export MACOSX_DEPLOYMENT_TARGET="$deployment_target"
                export CMAKE_OSX_SYSROOT="$sdkroot"
                export CMAKE_OSX_DEPLOYMENT_TARGET="$deployment_target"
                export CFLAGS="-isysroot $sdkroot -mmacosx-version-min=$deployment_target''${CFLAGS:+ $CFLAGS}"
                export CXXFLAGS="-isysroot $sdkroot -mmacosx-version-min=$deployment_target''${CXXFLAGS:+ $CXXFLAGS}"
                export LDFLAGS="-L$sdkroot/usr/lib -Wl,-macosx_version_min,$deployment_target''${LDFLAGS:+ $LDFLAGS}"
                export RUSTFLAGS="-L native=$sdkroot/usr/lib -C link-arg=-mmacosx-version-min=$deployment_target''${RUSTFLAGS:+ $RUSTFLAGS}"
              fi
            '';
          };
        }
      );
    };
}
