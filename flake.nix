{
  description = "headscale - Open Source Tailscale Control server";

  inputs = {
    # Pinned to staging-next-26.05 for Go 1.26.4 (security fix GO-2026-5037/5039):
    # nixpkgs-unstable still ships 1.26.3 — the bump is merged to nixpkgs staging
    # but the large-rebuild staging->unstable pipeline lags. The 26.05 line is
    # otherwise current (dev tools match unstable). Switch back to nixpkgs-unstable
    # once it ships go_1_26 >= 1.26.4.
    nixpkgs.url = "github:NixOS/nixpkgs/staging-next-26.05";
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
          # Go 1.26 builder; resolves to Go 1.26.4 from the pinned nixpkgs.
          buildGo = pkgs.buildGo126Module;
          vendorHash = (builtins.fromJSON (builtins.readFile ./flakehashes.json)).vendor.sri;
        in
        {
          headscale = buildGo {
            pname = "headscale";
            version = headscaleVersion;
            src = pkgs.lib.cleanSource self;

            # Only run unit tests when testing a build
            checkFlags = [ "-short" ];

            # vendorHash is read from flakehashes.json; refresh via:
            #   go run ./cmd/vendorhash update
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
            version = "2.29.0";

            src = pkgs.fetchFromGitHub {
              owner = "grpc-ecosystem";
              repo = "grpc-gateway";
              rev = "v${version}";
              sha256 = "sha256-d9OIIGttyMBSNgpS6mbR5JEIm13qGu2gFHJazJAexdw=";
            };

            vendorHash = "sha256-p51yD+v8+rPs+ztlX7r0VQ4XlwUkxu+PxgknKEvH00k=";

            nativeBuildInputs = [ pkgs.installShellFiles ];

            subPackages = [ "protoc-gen-grpc-gateway" "protoc-gen-openapiv2" ];
          };

          protobuf-language-server = buildGo rec {
            pname = "protobuf-language-server";
            version = "ab4c128";

            src = pkgs.fetchFromGitHub {
              owner = "lasorda";
              repo = "protobuf-language-server";
              rev = "ab4c128f00774d51bd6d1f4cfa735f4b7c8619e3";
              sha256 = "sha256-yF6kG+qTRxVO/qp2V9HgTyFBeOm5RQzeqdZFrdidwxM=";
            };

            vendorHash = "sha256-4nTpKBe7ekJsfQf+P6edT/9Vp2SBYbKz1ITawD3bhkI=";

            subPackages = [ "." ];
          };

          # Build golangci-lint with stock Go 1.26 (upstream uses hardcoded Go
          # version); it does not build against the pinned 1.26.4.
          golangci-lint = buildGo rec {
            pname = "golangci-lint";
            version = "2.12.2";

            src = pkgs.fetchFromGitHub {
              owner = "golangci";
              repo = "golangci-lint";
              rev = "v${version}";
              hash = "sha256-qR7fp1x2S+EwEAcplRHTvA3jWwLr/XSiYKSZtAwkrNU=";
            };

            vendorHash = "sha256-AG5wtLwWLz55bdp1oi3cW+9O3yj1W1P7MV9zxym7Pb4=";

            subPackages = [ "cmd/golangci-lint" ];

            nativeBuildInputs = [ pkgs.installShellFiles ];

            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
              "-X main.commit=v${version}"
              "-X main.date=1970-01-01T00:00:00Z"
            ];

            postInstall = ''
              for shell in bash zsh fish; do
                HOME=$TMPDIR $out/bin/golangci-lint completion $shell > golangci-lint.$shell
                installShellCompletion golangci-lint.$shell
              done
            '';

            meta = {
              description = "Fast linters runner for Go";
              homepage = "https://golangci-lint.run/";
              changelog = "https://github.com/golangci/golangci-lint/blob/v${version}/CHANGELOG.md";
              mainProgram = "golangci-lint";
            };
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

          gopls = prev.gopls.override {
            buildGoLatestModule = buildGo;
          };
        };
    }
    // flake-utils.lib.eachDefaultSystem
      (system:
      let
        pkgs = import nixpkgs {
          overlays = [ self.overlays.default ];
          inherit system;
        };
        buildDeps = with pkgs; [ git go_1_26 gnumake ];
        devDeps = with pkgs;
          buildDeps
          ++ [
            golangci-lint
            golangci-lint-langserver
            golines
            prettier
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
            python314Packages.mdformat
            python314Packages.mdformat-footnote
            python314Packages.mdformat-frontmatter
            python314Packages.mdformat-mkdocs
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
          ++ lib.optionals pkgs.stdenv.isLinux [ traceroute ];

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
                  exec go run ./cmd/vendorhash update "$@"
                '')

              (pkgs.writeShellScriptBin
                "go-mod-update-all"
                ''
                  cat go.mod | ${pkgs.ripgrep}/bin/rg "\t" | ${pkgs.ripgrep}/bin/rg -v indirect | ${pkgs.gawk}/bin/awk '{print $1}' | ${pkgs.findutils}/bin/xargs go get -u
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
