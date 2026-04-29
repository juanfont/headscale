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
            version = "2.28.0";

            src = pkgs.fetchFromGitHub {
              owner = "grpc-ecosystem";
              repo = "grpc-gateway";
              rev = "v${version}";
              sha256 = "sha256-93omvHb+b+S0w4D+FGEEwYYDjgumJFDAruc1P4elfvA=";
            };

            vendorHash = "sha256-jVP5zfFPfHeAEApKNJzZwuZLA+DjKgkL7m2DFG72UNs=";

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

          # Build golangci-lint with Go 1.26 (upstream uses hardcoded Go version)
          golangci-lint = buildGo rec {
            pname = "golangci-lint";
            version = "2.11.4";

            src = pkgs.fetchFromGitHub {
              owner = "golangci";
              repo = "golangci-lint";
              rev = "v${version}";
              hash = "sha256-B19aLvfNRY9TOYw/71f2vpNUuSIz8OI4dL0ijGezsas=";
            };

            vendorHash = "sha256-xuoj4+U4tB5gpABKq4Dbp2cxnljxdYoBbO8A7DqPM5E=";

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
                  exec go run ./cmd/vendorhash update "$@"
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
