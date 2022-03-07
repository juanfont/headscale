{
  description = "headscale - Open Source Tailscale Control server";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    {
      overlay = final: prev:
        let
          pkgs = nixpkgs.legacyPackages.${prev.system};
        in
        rec {
          golines =
            pkgs.buildGoModule rec {
              pname = "golines";
              version = "0.8.0";

              src = pkgs.fetchFromGitHub {
                owner = "segmentio";
                repo = "golines";
                rev = "v${version}";
                sha256 = "sha256-W4vN3rGKyX43HZyjjVUKnR4Fy0LfYqVf6h7wIYO0U50=";
              };

              vendorSha256 = "sha256-ZHL2hQnJXpZu42hQZzIIaEzINSS+5BOL9dxAVCp0nMs=";

              nativeBuildInputs = [ pkgs.installShellFiles ];
            };

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

          headscale =
            pkgs.buildGo117Module rec {
              pname = "headscale";
              version = "dev";
              src = pkgs.lib.cleanSource self;

              # When updating go.mod or go.sum, a new sha will need to be calculated,
              # update this if you have a mismatch after doing a change to thos files.
              vendorSha256 = "sha256-XzcTErmY/jM73nGzH3R0+5lIqJ8tT1lFyQilwJpqBlo=";

              ldflags = [ "-s" "-w" "-X github.com/juanfont/headscale/cmd/headscale/cli.Version=v${version}" ];
            };
        };
    } // flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            overlays = [ self.overlay ];
            inherit system;
          };
          buildDeps = with pkgs; [ git go_1_17 gnumake ];
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
          headscale-docker = pkgs.dockerTools.buildLayeredImage {
            name = "headscale";
            tag = "latest";
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


        });
}
