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

    # Tailscale HEAD, built from source for the integration test client image.
    # Bump with `nix flake update tailscale-head` to track the latest main.
    # It is a flake; we still build our own derivation (we need derper +
    # containerboot, which its default package omits) but read its committed
    # vendorHash from flakehashes.json so the bump carries the hash.
    tailscale-head.url = "github:tailscale/tailscale";
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , flake-checks
    , tailscale-head
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

          # Go source with the non-Go scaffolding filtered out, so editing the
          # nix integration harness, CI workflows, docs or packaging does not
          # rebuild the (slow) integration test binary or container images.
          # Only changes to actual Go source invalidate them.
          goSrc = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.difference ./. (pkgs.lib.fileset.unions [
              ./nix
              ./.github
              ./docs
              ./packaging
              ./flake.nix
              ./flake.lock
              ./flakehashes.json
            ]);
          };
        in
        {
          headscale-go-src = goSrc;

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

          # The integration suite compiled into a single test binary, run later
          # inside a per-test NixOS VM check (see nix/tests/integration.nix).
          # Compiled once and shared by every integration check.
          integration-test-bin = buildGo {
            pname = "headscale-integration-test";
            # Fixed (not the commit rev) so the binary is content-addressed:
            # identical Go source → identical store path → shared-cache hit
            # across commits. The version string is irrelevant for a test binary.
            version = "integration";
            src = goSrc;

            inherit vendorHash;

            doCheck = false;

            buildPhase = ''
              runHook preBuild
              go test -c -o integration.test ./integration
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              install -Dm755 integration.test $out/bin/integration.test
              runHook postInstall
            '';
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
          embedDirs = [
            ./hscontrol/assets
            ./hscontrol/db/schema.sql
            ./config-example.yaml
            ./integration/tailscale-versions.json
          ];
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

        # Nix-built container images for the integration tests, plus the
        # per-test VM check factory. Linux-only (dockerTools + nixosTest).
        integrationImages = import ./nix/images.nix {
          inherit pkgs;
          buildGoModule = pkgs.buildGo126Module;
          tailscaleSrc = tailscale-head;
        };

        mkIntegrationCheck = { name, testFilter ? name, postgres ? false }:
          pkgs.testers.nixosTest (import ./nix/tests/integration.nix {
            inherit name testFilter pkgs postgres;
            inherit (integrationImages)
              headscaleImage tailscaleImage postgresImage tailscaleVersionImages;
            testBin = pkgs.integration-test-bin;
            # goSrc (not the full tree) so a check's result stays cached when
            # only nix/CI/docs change — only real Go/integration changes (which
            # also rebuild testBin) invalidate it. Maximises shared-cache reuse.
            src = pkgs.headscale-go-src;
          });

        # One sqlite check per test (full matrix), plus a postgres variant for
        # the postgres subset — exactly the sqlite+postgres jobs the generator
        # produces for the GitHub workflow.
        integrationChecks =
          let
            # A single shared builder can't fit the full per-test VM fan-out in
            # RAM, so batch the matrix into a few groups and run each group's
            # tests sequentially (-test.parallel=1) inside one VM. Only ~7 VMs
            # ever exist, so the builder can't be overcommitted no matter its
            # build concurrency. Split-test entries
            # (TestAutoApproveMultiNetwork/authkey-tag.*) collapse to their parent
            # function; round-robin assignment spreads heavy tests across groups.
            topLevel = f: builtins.head (pkgs.lib.splitString "/" f);
            sqliteTests = pkgs.lib.unique (map topLevel (import ./integration/tests.nix));
            pgTests = pkgs.lib.unique (map topLevel (import ./integration/postgres-tests.nix));
            numGroups = 6;
            groupOf = tests: g: builtins.filter (t: t != null)
              (pkgs.lib.imap0 (i: t: if pkgs.lib.mod i numGroups == g then t else null) tests);
            mkBatch = postgres: idx: tests:
              pkgs.lib.nameValuePair
                "integration-batch${toString idx}${pkgs.lib.optionalString postgres "-pg"}"
                (mkIntegrationCheck {
                  name = "batch${toString idx}";
                  testFilter = "(" + pkgs.lib.concatStringsSep "|" tests + ")";
                  inherit postgres;
                });
          in
          pkgs.lib.listToAttrs (
            (map (g: mkBatch false g (groupOf sqliteTests g)) (pkgs.lib.range 0 (numGroups - 1)))
            ++ [ (mkBatch true 0 pgTests) ]
          );
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

              # Regenerate integration/tailscale-versions.json after a capver bump
              # so the offline checks pin the tailscale images the suite requests.
              # It is a //go:generate step in the integration package (runs with
              # capver under `make generate`); this just scopes it to the pins.
              (pkgs.writeShellScriptBin "update-integration-images" ''
                exec go generate ./integration/...
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
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          headscale-integration-image = integrationImages.headscaleImage;
          tailscale-integration-image = integrationImages.tailscaleImage;
          postgres-integration-image = integrationImages.postgresImage;
          inherit (pkgs) integration-test-bin;

          # All shared inputs every integration check pulls in: the test binary
          # and every image. CI builds this once (a "prime" job) so it lands in
          # the shared nix cache before the per-test matrix fans out — the
          # matrix jobs then substitute it instead of each rebuilding.
          integration-deps = pkgs.linkFarm "integration-deps" (
            [
              { name = "test-bin"; path = pkgs.integration-test-bin; }
              { name = "headscale"; path = integrationImages.headscaleImage; }
              { name = "tailscale-head"; path = integrationImages.tailscaleImage; }
              { name = "postgres"; path = integrationImages.postgresImage; }
            ]
            ++ pkgs.lib.imap0
              (i: img: { name = "ts-version-${toString i}"; path = img; })
              integrationImages.tailscaleVersionImages
          );
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
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux goChecks
        # Integration checks only on x86_64-linux: nixosTest needs KVM and the
        # pinned version images are amd64 (nix/tailscale-versions.nix). aarch64
        # would need arch-specific pins.
        // pkgs.lib.optionalAttrs (system == "x86_64-linux") integrationChecks;
      });
}
