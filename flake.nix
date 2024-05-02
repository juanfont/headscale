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
        headscale = pkgs.buildGo122Module rec {
          pname = "headscale";
          version = headscaleVersion;
          src = pkgs.lib.cleanSource self;

          # Only run unit tests when testing a build
          checkFlags = ["-short"];

          # When updating go.mod or go.sum, a new sha will need to be calculated,
          # update this if you have a mismatch after doing a change to thos files.
          vendorHash = "sha256-HGu/OCtjzPeBki5FSL6v1XivCJ30eqj9rL0x7ZVv1TM=";

          subPackages = ["cmd/headscale"];

          ldflags = ["-s" "-w" "-X github.com/juanfont/headscale/cmd/headscale/cli.Version=v${version}"];
        };

        protoc-gen-grpc-gateway = pkgs.buildGoModule rec {
          pname = "grpc-gateway";
          version = "2.19.1";

          src = pkgs.fetchFromGitHub {
            owner = "grpc-ecosystem";
            repo = "grpc-gateway";
            rev = "v${version}";
            sha256 = "sha256-CdGQpQfOSimeio8v1lZ7xzE/oAS2qFyu+uN+H9i7vpo=";
          };

          vendorHash = "sha256-no7kZGpf/VOuceC3J+izGFQp5aMS3b+Rn+x4BFZ2zgs=";

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
      buildDeps = with pkgs; [git go_1_22 gnumake];
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
          ko
          yq-go
          ripgrep

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
            ${pkgs.clang-tools}/bin/clang-format -style="{BasedOnStyle: Google, IndentWidth: 4, AlignConsecutiveDeclarations: true, AlignConsecutiveAssignments: true, ColumnLimit: 0}" -i ${./.}
          '';
      };
    });
}
