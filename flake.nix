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
    # Reusable Go flake checks (build/test/lint/format); CI runs them via
    # `nix build .#checks.<system>.<name>` instead of bespoke per-tool steps.
    flake-checks.url = "github:kradalby/flake-checks";
    flake-checks.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , flake-checks
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

            # External clients exercised by the Tailscale-compatible v2 API
            # roundtrip tests (TestAPIv2). Binaries: tofu, tscli.
            opentofu
            tscli
            python314Packages.mdformat
            python314Packages.mdformat-footnote
            python314Packages.mdformat-frontmatter
            python314Packages.mdformat-mkdocs
            prek

            # 'dot' is needed for pprof graphs
            # go tool pprof -http=: <source>
            graphviz
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

        # Go flake checks from the flake-checks library. CI gates on
        # `nix build .#checks.<system>.<name>`; the logic lives here, not in
        # bespoke workflow steps. Linux-only: parts of the tree are
        # Linux-specific and the pure unit subset is validated by CI.
        fc = flake-checks.lib;
        common = {
          inherit pkgs;
          root = ./.;
          pname = "headscale";
          version = headscaleVersion;
          vendorHash = (builtins.fromJSON (builtins.readFile ./flakehashes.json)).vendor.sri;
          goPkg = pkgs.go_1_26;
          # //go:embed targets and test-read files outside the default whitelist.
          embedDirs = [ ./hscontrol/assets ./hscontrol/db/schema.sql ./config-example.yaml ];
          extraSrc = [
            ./hscontrol/testdata
            ./hscontrol/types/testdata
            ./hscontrol/db/testdata
            ./hscontrol/policy/v2/testdata
          ];
        };
        goChecks = {
          build = fc.goBuild (common // { subPackages = [ "cmd/headscale" ]; });

          # The pure unit subset. ./integration (Docker) and
          # ./hscontrol/servertest (slow: 10s+ convergence plus race/stress/HA
          # property tests — run by the servertest workflow instead) are dropped
          # from the test set but kept in source so cmd/hi and friends still
          # compile; TestPostgres* needs a server (the SQLite equivalents still
          # run). CGO off matches the build.
          gotest = fc.goTest (common // {
            testExclude = [ "/integration" "/hscontrol/servertest" ];
            goSkip = [ "TestPostgres" ];
            testEnv = "export CGO_ENABLED=0";
          });

          # Full-tree golangci-lint (golines, gofumpt, etc.); uses the overlay's
          # golangci-lint built against the pinned Go.
          golangci-lint = fc.goLint common;

          # nixpkgs-fmt + prettier, excluding generated output. goFmt = "off":
          # Go formatting (golines, gofumpt) is enforced by the golangci-lint
          # check, not treefmt. prettierExts matches the old prettier-lint glob
          # (no json: testdata fixtures are hand-formatted).
          formatting = fc.goFormat (common // {
            goFmt = "off";
            prettier = true;
            prettierExts = [ "ts" "js" "md" "yaml" "yml" "sass" "css" "scss" "html" ];
            # Mirror .prettierignore (docs/ are mkdocs-flavoured; gen/ generated).
            fmtExclude = [ ./gen ./docs ];
          });
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
        }
        # The Go build/test checks are gated to Linux: parts of the tree are
        # Linux-specific and the pure unit subset is validated by CI.
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux goChecks;
      });
}
