{
  description = "headscale - Open Source Tailscale Control server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    let
      headscaleVersion = if (self ? shortRev) then self.shortRev else "dev";
    in
    {
      overlay = final: prev:
        let
          pkgs = nixpkgs.legacyPackages.${prev.system};
        in
        rec {
          headscale =
            pkgs.buildGo118Module rec {
              pname = "headscale";
              version = headscaleVersion;
              src = pkgs.lib.cleanSource self;

              # When updating go.mod or go.sum, a new sha will need to be calculated,
              # update this if you have a mismatch after doing a change to thos files.
              vendorSha256 = "sha256-T6rH+aqofFmCPxDfoA5xd3kNUJeZkT4GRyuFEnenps8=";

              ldflags = [ "-s" "-w" "-X github.com/juanfont/headscale/cmd/headscale/cli.Version=v${version}" ];
            };

          golines =
            pkgs.buildGoModule rec {
              pname = "golines";
              version = "0.9.0";

              src = pkgs.fetchFromGitHub {
                owner = "segmentio";
                repo = "golines";
                rev = "v${version}";
                sha256 = "sha256-BUXEg+4r9L/gqe4DhTlhN55P3jWt7ZyWFQycO6QePrw=";
              };

              vendorSha256 = "sha256-sEzWUeVk5GB0H41wrp12P8sBWRjg0FHUX6ABDEEBqK8=";

              nativeBuildInputs = [ pkgs.installShellFiles ];
            };

          golangci-lint = prev.golangci-lint.override {
            # Override https://github.com/NixOS/nixpkgs/pull/166801 which changed this
            # to buildGo118Module because it does not build on Darwin.
            inherit (prev) buildGoModule;
          };

          # golangci-lint =
          #   pkgs.buildGo117Module rec {
          #     pname = "golangci-lint";
          #     version = "1.46.2";
          #
          #     src = pkgs.fetchFromGitHub {
          #       owner = "golangci";
          #       repo = "golangci-lint";
          #       rev = "v${version}";
          #       sha256 = "sha256-7sDAwWz+qoB/ngeH35tsJ5FZUfAQvQsU6kU9rUHIHMk=";
          #     };
          #
          #     vendorSha256 = "sha256-w38OKN6HPoz37utG/2QSPMai55IRDXCIIymeMe6ogIU=";
          #
          #     nativeBuildInputs = [ pkgs.installShellFiles ];
          #   };

          protoc-gen-grpc-gateway =
            pkgs.buildGoModule rec {
              pname = "grpc-gateway";
              version = "2.8.0";

              src = pkgs.fetchFromGitHub {
                owner = "grpc-ecosystem";
                repo = "grpc-gateway";
                rev = "v${version}";
                sha256 = "sha256-8eBBBYJ+tBjB2fgPMX/ZlbN3eeS75e8TAZYOKXs6hcg=";
              };

              vendorSha256 = "sha256-AW2Gn/mlZyLMwF+NpK59eiOmQrYWW/9HPjbunYc9Ij4=";

              nativeBuildInputs = [ pkgs.installShellFiles ];

              subPackages = [ "protoc-gen-grpc-gateway" "protoc-gen-openapiv2" ];
            };
        };
    } // flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            overlays = [ self.overlay ];
            inherit system;
          };
          buildDeps = with pkgs; [ git go_1_18 gnumake ];
          devDeps = with pkgs;
            buildDeps ++ [
              golangci-lint
              golines
              nodePackages.prettier

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
            contents = [ pkgs.headscale ];
            config.Entrypoint = [ (pkgs.headscale + "/bin/headscale") ];
          };
        in
        rec {
          # `nix develop`
          devShell = pkgs.mkShell { buildInputs = devDeps; };

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
          defaultApp = apps.headscale;

          checks = {
            format = pkgs.runCommand "check-format"
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
