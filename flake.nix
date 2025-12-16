{
  description = "headscale - Open Source Tailscale Control server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , ...
    }:
    let
      headscaleVersion = self.shortRev or self.dirtyShortRev;
      commitHash = self.rev or self.dirtyRev;
    in
    {
      # NixOS module
      nixosModules = rec {
        headscale = import ./nix/module.nix;
        default = headscale;
      };

      overlay = _: prev:
        let
          pkgs = nixpkgs.legacyPackages.${prev.system};
          buildGo = pkgs.buildGo125Module;
          vendorHash = "sha256-qQwCMa3TIvWBX358/PxzLJOEV6O0hgfh1PpZ96rs9eU=";
        in
        {
          headscale = buildGo {
            pname = "headscale";
            version = headscaleVersion;
            src = pkgs.lib.cleanSource self;

            # Only run unit tests when testing a build
            checkFlags = [ "-short" ];

            # When updating go.mod or go.sum, a new sha will need to be calculated,
            # update this if you have a mismatch after doing a change to those files.
            inherit vendorHash;

            subPackages = [ "cmd/headscale" ];

            meta = {
              mainProgram = "headscale";
            };
          };

          hi = buildGo {
            pname = "hi";
            version = headscaleVersion;
            src = pkgs.lib.cleanSource self;

            checkFlags = [ "-short" ];
            inherit vendorHash;

            subPackages = [ "cmd/hi" ];
          };

          protobuf-language-server = buildGo rec {
            pname = "protobuf-language-server";
            version = "2546944";

            src = pkgs.fetchFromGitHub {
              owner = "lasorda";
              repo = "protobuf-language-server";
              rev = "${version}";
              sha256 = "sha256-Cbr3ktT86RnwUntOiDKRpNTClhdyrKLTQG2ZEd6fKDc=";
            };

            vendorHash = "sha256-PfT90dhfzJZabzLTb1D69JCO+kOh2khrlpF5mCDeypk=";

            subPackages = [ "." ];
          };
        };
    }
    // flake-utils.lib.eachDefaultSystem
      (system:
      let
        pkgs = import nixpkgs {
          overlays = [ self.overlay ];
          inherit system;
        };
        buildDeps = with pkgs; [ git go_1_25 gnumake ];
        devDeps = with pkgs;
          buildDeps
          ++ [
            nodePackages.prettier
            nixpkgs-fmt
            goreleaser
            nfpm
            gopls
            ksh
            ko
            ripgrep
            postgresql
            prek

            # 'dot' is needed for pprof graphs
            # go tool pprof -http=: <source>
            graphviz

            # Protobuf dependencies
            protobuf
            buf
            clang-tools # clang-format
            protobuf-language-server
          ]
          ++ lib.optional pkgs.stdenv.isLinux [ traceroute ];

        # Add entry to build a docker image with headscale
        # caveat: only works on Linux
        #
        # Usage:
        # nix build .#headscale-docker
        # docker load < result
        headscale-docker = pkgs.dockerTools.buildLayeredImage {
          name = "headscale";
          tag = headscaleVersion;
          contents = [ pkgs.headscale ];
          config.Entrypoint = [ (pkgs.headscale + "/bin/headscale") ];
        };
      in
      rec {
        # `nix develop`
        devShell = pkgs.mkShell {
          buildInputs =
            devDeps
            ++ [
              (pkgs.writeShellScriptBin
                "nix-vendor-sri"
                ''
                  set -eu

                  OUT=$(mktemp -d -t nar-hash-XXXXXX)
                  rm -rf "$OUT"

                  go mod vendor -o "$OUT"
                  go run tailscale.com/cmd/nardump --sri "$OUT"
                  rm -rf "$OUT"
                '')

              (pkgs.writeShellScriptBin
                "go-mod-update-all"
                ''
                  cat go.mod | ${pkgs.silver-searcher}/bin/ag "\t" | ${pkgs.silver-searcher}/bin/ag -v indirect | ${pkgs.gawk}/bin/awk '{print $1}' | ${pkgs.findutils}/bin/xargs go get -u
                  go mod tidy
                '')
            ];

          shellHook = ''
            export PATH="$PWD/result/bin:$PATH"
            export CGO_ENABLED=0
          '';
        };

        # `nix build`
        packages = with pkgs; {
          inherit headscale;
          inherit headscale-docker;
        };
        defaultPackage = pkgs.headscale;

        # `nix run`
        apps.headscale = flake-utils.lib.mkApp {
          drv = packages.headscale;
        };
        apps.default = apps.headscale;

        checks = {
          headscale = pkgs.nixosTest (import ./nix/tests/headscale.nix);
        };
      });
}
