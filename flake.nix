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
      in rec {
        headscale = pkgs.buildGo121Module rec {
          pname = "headscale";
          version = headscaleVersion;
          src = pkgs.lib.cleanSource self;

          tags = ["ts2019"];

          # Only run unit tests when testing a build
          checkFlags = ["-short"];

          # When updating go.mod or go.sum, a new sha will need to be calculated,
          # update this if you have a mismatch after doing a change to thos files.
          vendorSha256 = "sha256-Q6eySc8lXYhkWka7Y+qOM6viv7QhdjFZDX8PttaLfr4=";

          ldflags = ["-s" "-w" "-X github.com/juanfont/headscale/cmd/headscale/cli.Version=v${version}"];
        };

        golines = pkgs.buildGoModule rec {
          pname = "golines";
          version = "0.11.0";

          src = pkgs.fetchFromGitHub {
            owner = "segmentio";
            repo = "golines";
            rev = "v${version}";
            sha256 = "sha256-2K9KAg8iSubiTbujyFGN3yggrL+EDyeUCs9OOta/19A=";
          };

          vendorSha256 = "sha256-rxYuzn4ezAxaeDhxd8qdOzt+CKYIh03A9zKNdzILq18=";

          nativeBuildInputs = [pkgs.installShellFiles];
        };

        golangci-lint = prev.golangci-lint.override {
          # Override https://github.com/NixOS/nixpkgs/pull/166801 which changed this
          # to buildGo118Module because it does not build on Darwin.
          inherit (prev) buildGoModule;
        };

        protoc-gen-grpc-gateway = pkgs.buildGoModule rec {
          pname = "grpc-gateway";
          version = "2.14.0";

          src = pkgs.fetchFromGitHub {
            owner = "grpc-ecosystem";
            repo = "grpc-gateway";
            rev = "v${version}";
            sha256 = "sha256-lnNdsDCpeSHtl2lC1IhUw11t3cnGF+37qSM7HDvKLls=";
          };

          vendorSha256 = "sha256-dGdnDuRbwg8fU7uB5GaHEWa/zI3w06onqjturvooJQA=";

          nativeBuildInputs = [pkgs.installShellFiles];

          subPackages = ["protoc-gen-grpc-gateway" "protoc-gen-openapiv2"];
        };
      };
    }
    // flake-utils.lib.eachDefaultSystem
    (system: let
      pkgs = import nixpkgs {
        overlays = [self.overlay];
        inherit system;
      };
      buildDeps = with pkgs; [git go_1_21 gnumake];
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
          ksh

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
        buildInputs = devDeps;

        shellHook = ''
          export GOFLAGS=-tags="ts2019"
          export PATH="$PWD/result/bin:$PATH"

          mkdir -p ./ignored
          export HEADSCALE_PRIVATE_KEY_PATH="./ignored/private.key"
          export HEADSCALE_NOISE_PRIVATE_KEY_PATH="./ignored/noise_private.key"
          export HEADSCALE_DB_PATH="./ignored/db.sqlite"
          export HEADSCALE_TLS_LETSENCRYPT_CACHE_DIR="./ignored/cache"
          export HEADSCALE_UNIX_SOCKET="./ignored/headscale.sock"
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
            ${pkgs.clang-tools}/bin/clang-format -style="{BasedOnStyle: Google, IndentWidth: 4, AlignConsecutiveDeclarations: true, AlignConsecutiveAssignments: true, ColumnLimit: 0}" -i ${./.}
          '';
      };
    });
}
