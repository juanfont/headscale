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

      overlays.default = _: prev:
        let
          pkgs = nixpkgs.legacyPackages.${prev.stdenv.hostPlatform.system};
          buildGo = pkgs.buildGo125Module;
          vendorHash = "sha256-dWsDgI5K+8mFw4PA5gfFBPCSqBJp5RcZzm0ML1+HsWw=";
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

          protoc-gen-grpc-gateway = buildGo rec {
            pname = "grpc-gateway";
            version = "2.27.4";

            src = pkgs.fetchFromGitHub {
              owner = "grpc-ecosystem";
              repo = "grpc-gateway";
              rev = "v${version}";
              sha256 = "sha256-4bhEQTVV04EyX/qJGNMIAQDcMWcDVr1tFkEjBHpc2CA=";
            };

            vendorHash = "sha256-ohZW/uPdt08Y2EpIQ2yeyGSjV9O58+QbQQqYrs6O8/g=";

            nativeBuildInputs = [ pkgs.installShellFiles ];

            subPackages = [ "protoc-gen-grpc-gateway" "protoc-gen-openapiv2" ];
          };

          protobuf-language-server = buildGo rec {
            pname = "protobuf-language-server";
            version = "1cf777d";

            src = pkgs.fetchFromGitHub {
              owner = "lasorda";
              repo = "protobuf-language-server";
              rev = "1cf777de4d35a6e493a689e3ca1a6183ce3206b6";
              sha256 = "sha256-9MkBQPxr/TDr/sNz/Sk7eoZwZwzdVbE5u6RugXXk5iY=";
            };

            vendorHash = "sha256-4nTpKBe7ekJsfQf+P6edT/9Vp2SBYbKz1ITawD3bhkI=";

            subPackages = [ "." ];
          };

          # Upstream does not override buildGoModule properly,
          # importing a specific module, so comment out for now.
          # golangci-lint = prev.golangci-lint.override {
          #   buildGoModule = buildGo;
          # };
          # golangci-lint-langserver = prev.golangci-lint.override {
          #   buildGoModule = buildGo;
          # };

          # The package uses buildGo125Module, not the convention.
          # goreleaser = prev.goreleaser.override {
          #   buildGoModule = buildGo;
          # };

          gotestsum = prev.gotestsum.override {
            buildGoModule = buildGo;
          };

          gotests = prev.gotests.override {
            buildGoModule = buildGo;
          };

          gofumpt = prev.gofumpt.override {
            buildGoModule = buildGo;
          };

          # gopls = prev.gopls.override {
          #   buildGoModule = buildGo;
          # };
        };
    }
    // flake-utils.lib.eachDefaultSystem
      (system:
      let
        pkgs = import nixpkgs {
          overlays = [ self.overlays.default ];
          inherit system;
        };
        buildDeps = with pkgs; [ git go_1_25 gnumake ];
        devDeps = with pkgs;
          buildDeps
          ++ [
            golangci-lint
            golangci-lint-langserver
            golines
            nodePackages.prettier
            nixpkgs-fmt
            goreleaser
            nfpm
            gotestsum
            gotests
            gofumpt
            gopls
            ksh
            ko
            yq-go
            ripgrep
            postgresql
            prek

            # 'dot' is needed for pprof graphs
            # go tool pprof -http=: <source>
            graphviz

            # Protobuf dependencies
            protobuf
            protoc-gen-go
            protoc-gen-go-grpc
            protoc-gen-grpc-gateway
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
      {
        # `nix develop`
        devShells.default = pkgs.mkShell {
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
          default = headscale;
        };

        # `nix run`
        apps.headscale = flake-utils.lib.mkApp {
          drv = pkgs.headscale;
        };
        apps.default = flake-utils.lib.mkApp {
          drv = pkgs.headscale;
        };

        checks = {
          headscale = pkgs.testers.nixosTest (import ./nix/tests/headscale.nix);
        };
      });
}
