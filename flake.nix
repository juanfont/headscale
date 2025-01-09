{
  description = "headscale - Open Source Tailscale Control server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    ...
  }: let
    headscaleVersion =
      if (self ? shortRev)
      then self.shortRev
      else "dev";
  in
    {
      overlay = _: prev: let
        pkgs = nixpkgs.legacyPackages.${prev.system};
        buildGo = pkgs.buildGo123Module;
      in {
        headscale = buildGo rec {
          pname = "headscale";
          version = headscaleVersion;
          src = pkgs.lib.cleanSource self;

          # Only run unit tests when testing a build
          checkFlags = ["-short"];

          # When updating go.mod or go.sum, a new sha will need to be calculated,
          # update this if you have a mismatch after doing a change to those files.
          vendorHash = "sha256-SBfeixT8DQOrK2SWmHHSOBtzRdSZs+pwomHpw6Jd+qc=";

          subPackages = ["cmd/headscale"];

          ldflags = ["-s" "-w" "-X github.com/juanfont/headscale/cmd/headscale/cli.Version=v${version}"];
        };

        protoc-gen-grpc-gateway = buildGo rec {
          pname = "grpc-gateway";
          version = "2.24.0";

          src = pkgs.fetchFromGitHub {
            owner = "grpc-ecosystem";
            repo = "grpc-gateway";
            rev = "v${version}";
            sha256 = "sha256-lUEoqXJF1k4/il9bdDTinkUV5L869njZNYqObG/mHyA=";
          };

          vendorHash = "sha256-Ttt7bPKU+TMKRg5550BS6fsPwYp0QJqcZ7NLrhttSdw=";

          nativeBuildInputs = [pkgs.installShellFiles];

          subPackages = ["protoc-gen-grpc-gateway" "protoc-gen-openapiv2"];
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

          subPackages = ["."];
        };

        # Upstream does not override buildGoModule properly,
        # importing a specific module, so comment out for now.
        # golangci-lint = prev.golangci-lint.override {
        #   buildGoModule = buildGo;
        # };

        goreleaser = prev.goreleaser.override {
          buildGoModule = buildGo;
        };

        gotestsum = prev.gotestsum.override {
          buildGoModule = buildGo;
        };

        gotests = prev.gotests.override {
          buildGoModule = buildGo;
        };

        gofumpt = prev.gofumpt.override {
          buildGoModule = buildGo;
        };
      };
    }
    // flake-utils.lib.eachDefaultSystem
    (system: let
      pkgs = import nixpkgs {
        overlays = [self.overlay];
        inherit system;
      };
      buildDeps = with pkgs; [git go_1_23 gnumake];
      devDeps = with pkgs;
        buildDeps
        ++ [
          golangci-lint
          golines
          nodePackages.prettier
          goreleaser
          nfpm
          gotestsum
          gotests
          gofumpt
          ksh
          ko
          yq-go
          ripgrep
          postgresql

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
        ];

      # Add entry to build a docker image with headscale
      # caveat: only works on Linux
      #
      # Usage:
      # nix build .#headscale-docker
      # docker load < result
      headscale-docker = pkgs.dockerTools.buildLayeredImage {
        name = "headscale";
        tag = headscaleVersion;
        contents = [pkgs.headscale];
        config.Entrypoint = [(pkgs.headscale + "/bin/headscale")];
      };
    in rec {
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
        format =
          pkgs.runCommand "check-format"
          {
            buildInputs = with pkgs; [
              gnumake
              nixpkgs-fmt
              golangci-lint
              nodePackages.prettier
              golines
              clang-tools
            ];
          } ''
            ${pkgs.nixpkgs-fmt}/bin/nixpkgs-fmt ${./.}
            ${pkgs.golangci-lint}/bin/golangci-lint run --fix --timeout 10m
            ${pkgs.nodePackages.prettier}/bin/prettier --write '**/**.{ts,js,md,yaml,yml,sass,css,scss,html}'
            ${pkgs.golines}/bin/golines --max-len=88 --base-formatter=gofumpt -w ${./.}
            ${pkgs.clang-tools}/bin/clang-format -i ${./.}
          '';
      };
    });
}
