{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils, naersk }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
      in rec {
        packages = {
          ethereum-p2p-handshake = naersk-lib.buildPackage {
            src = ./.;
            doDoc = true;
            doDocFail = true;
            copyLibs = true;
          };

          handshake = naersk-lib.buildPackage {
            pname = "handshake";
            src = ./.;

            overrideMain = old: {
              preConfigure = ''
                cargo_build_options="$cargo_build_options --bin handshake"
              '';
            };
          };

          ping-pong = naersk-lib.buildPackage {
            pname = "ping-pong";
            src = ./.;

            overrideMain = old: {
              preConfigure = ''
                cargo_build_options="$cargo_build_options --bin ping-pong"
              '';
            };
          };

          default = naersk-lib.buildPackage {
            src = ./.;

            overrideMain = old: {
              preConfigure = ''
                cargo_build_options="$cargo_build_options --bins"
              '';
            };
          };

        };

        checks = {
          check = naersk-lib.buildPackage {
            src = ./.;
            mode = "check";
          };

          test = naersk-lib.buildPackage {
            src = ./.;
            mode = "test";
          };

          clippy = naersk-lib.buildPackage {
            src = ./.;
            mode = "clippy";
            preConfigure = ''
              cargo_build_options="$cargo_build_options --all"
            '';
          };
        };

        devShells = {
          default = with pkgs; mkShell {
            buildInputs = [ cargo rustc rustfmt rustPackages.clippy ];
            RUST_SRC_PATH = rustPlatform.rustLibSrc;
          };
        };
      }
    );
}
