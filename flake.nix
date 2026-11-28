{
  description = "headscale - Open Source Tailscale Control server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    # Go releases reach nixpkgs late, so headscale pins go.dev's source and
    # builds it with nixpkgs' recipe. Keep in step with go.mod's go directive.
    go = {
      url = "https://go.dev/dl/go1.27.4.src.tar.gz";
      flake = false;
    };
    flake-utils.url = "github:numtide/flake-utils";
    # Reusable Go flake checks (build/test/lint/format); CI runs them via
    # `nix build .#checks.<system>.<name>` instead of bespoke per-tool steps.
    flake-checks.url = "github:kradalby/flake-checks";
    flake-checks.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      flake-checks,
      ...
    }@inputs:
    let
      headscaleVersion = self.shortRev or self.dirtyShortRev;
      commitHash = self.rev or self.dirtyRev;

      # Go from the pinned source, built with the given nixpkgs' recipe for
      # that major (falling back to go_latest), so consumers' channels work.
      toolchain =
        pkgs:
        let
          inherit (pkgs) lib;
          version = lib.removePrefix "go" (
            lib.head (lib.splitString "\n" (builtins.readFile "${inputs.go}/VERSION"))
          );
          major = lib.replaceStrings [ "." ] [ "_" ] (lib.versions.majorMinor version);
        in
        rec {
          go = (pkgs."go_${major}" or pkgs.go_latest).overrideAttrs {
            inherit version;
            src = inputs.go;
          };
          # Not buildGoModule.override: nixpkgs aliases it and it recurses.
          buildGoModule = pkgs.callPackage "${pkgs.path}/pkgs/build-support/go/module.nix" { inherit go; };
          # Dev tools parse and lint Go with the Go they were built with, so an
          # older one rejects new syntax. Builders pinned to another major stay.
          withGo =
            pkg:
            pkg.override (
              lib.intersectAttrs (lib.functionArgs pkg.override) {
                inherit go buildGoModule;
                buildGoLatestModule = buildGoModule;
                "buildGo${lib.replaceStrings [ "_" ] [ "" ] major}Module" = buildGoModule;
              }
            );
        };
    in
    {
      # NixOS module
      nixosModules = rec {
        # Defaults the package to this flake's: the pre-switch checks need
        # `headscale check`. Priority 1001 sits just below mkDefault, so a
        # user's mkDefault wins instead of conflicting. The overlay, not
        # self.packages, so every system nixpkgs supports evaluates.
        headscale =
          { lib, pkgs, ... }:
          {
            # Dedupes importing it twice, directly and via testkit.
            key = "${toString ./flake.nix}#nixosModules.headscale";
            _file = "${toString ./flake.nix}#nixosModules.headscale";
            imports = [ ./nix/module.nix ];
            services.headscale.package = lib.mkOverride 1001 (self.overlays.default pkgs pkgs).headscale;
          };
        default = headscale;
        # Control node for NixOS VM tests of Tailscale clients, and a peer
        # that joins it; nix/README.md.
        testkit = import ./nix/testkit.nix self;
        testkit-peer = ./nix/testkit-peer.nix;
      };

      # Builds with the consumer's nixpkgs; only Go comes from this flake.
      overlays.default =
        final: _:
        let
          inherit (toolchain final) buildGoModule;
          vendorHash = (builtins.fromJSON (builtins.readFile ./flakehashes.json)).vendor.sri;
        in
        {
          headscale = buildGoModule {
            pname = "headscale";
            version = headscaleVersion;
            src = final.lib.cleanSource self;

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

          hi = buildGoModule {
            pname = "hi";
            version = headscaleVersion;
            src = final.lib.cleanSource self;

            checkFlags = [ "-short" ];
            inherit vendorHash;

            subPackages = [ "cmd/hi" ];
          };
        };
    }
    # Explicit: nixpkgs no longer evaluates x86_64-darwin, which
    # eachDefaultSystem still lists.
    // flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        pkgs = import nixpkgs {
          overlays = [ self.overlays.default ];
          inherit system;
        };
        inherit (toolchain pkgs) go withGo;
        buildDeps = with pkgs; [
          git
          go
          gnumake
        ];
        devDeps =
          with pkgs;
          buildDeps
          ++ map withGo [
            golangci-lint
            golangci-lint-langserver
            gotestsum
            gotests
            gofumpt
            gopls
            gotools
          ]
          ++ [
            prettier
            nixfmt
            goreleaser
            nfpm

            gh
            gh-actions-lock
            zizmor
            ksh
            ko
            yq-go
            ripgrep
            postgresql

            # External clients exercised by the Tailscale-compatible v2 API
            # roundtrip tests (TestAPIv2). Binaries: tofu, tscli.
            opentofu
            tscli
            python3Packages.mdformat
            python3Packages.mdformat-footnote
            python3Packages.mdformat-frontmatter
            python3Packages.mdformat-mkdocs
            prek

            # 'dot' is needed for pprof graphs
            # go tool pprof -http=: <source>
            graphviz
          ]
          ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ traceroute ];

        # Add entry to build a docker image with headscale
        # caveat: only works on Linux
        #
        # Usage:
        # nix build .#headscale-docker
        # docker load < result
        headscale-docker = pkgs.dockerTools.buildLayeredImage {
          name = "headscale";
          tag = headscaleVersion;
          # CA certificates for outbound HTTPS, such as the DERP map.
          contents = [
            pkgs.headscale
            pkgs.cacert
          ];
          config.Entrypoint = [ (pkgs.headscale + "/bin/headscale") ];
          config.Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
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
          goPkg = go;
          # //go:embed targets and test-read files outside the default whitelist.
          embedDirs = [
            ./hscontrol/assets
            ./hscontrol/db/schema.sql
          ];
          extraSrc = [
            ./hscontrol/testdata
            ./hscontrol/config/testdata
            ./hscontrol/db/testdata
            ./hscontrol/policy/v2/testdata
          ];
        };
        goChecks = {
          build = fc.goBuild (common // { subPackages = [ "cmd/headscale" ]; });

          # The pure unit subset. The root ./integration package (Docker) and
          # ./hscontrol/servertest (slow: 10s+ convergence plus race/stress/HA
          # property tests — run by the servertest workflow instead) are dropped
          # from the test set but kept in source so cmd/hi and friends still
          # compile. Pure integration helper tests remain included.
          # TestPostgres* needs a server (the SQLite equivalents still
          # run). This check keeps CGO off; gorace below enables it for tests.
          gotest = fc.goTest (
            common
            // {
              testExclude = [
                "/integration$"
                "/hscontrol/servertest"
              ];
              goSkip = [ "TestPostgres" ];
              testEnv = "export CGO_ENABLED=0";
            }
          );

          # -race needs cgo; release build and dev shell stay CGO-free.
          # Test hscontrol recursively; servertest runs in its own workflow, without -race.
          gorace = fc.goTest (
            common
            // {
              name = "headscale-gorace";
              goRace = true;
              testEnv = "export CGO_ENABLED=1";
              testFlags = [ "-p=2" ];
              goSkip = [ "TestPostgres" ];
              testPackages = "./hscontrol/...";
              testExclude = [ "/hscontrol/servertest" ];
            }
          );

          # Full-tree golangci-lint (gofumpt, gci, etc.), built with the
          # pinned Go.
          golangci-lint = fc.goLint (common // { golangciLint = withGo pkgs.golangci-lint; });

          # nixfmt + prettier, excluding generated output. goFmt = "off":
          # Go formatting (gofumpt, gci) is enforced by the golangci-lint
          # check, not treefmt. prettierExts matches the old prettier-lint glob
          # (no json: testdata fixtures are hand-formatted).
          formatting = fc.goFormat (
            common
            // {
              goFmt = "off";
              prettier = true;
              prettierExts = [
                "ts"
                "js"
                "md"
                "yaml"
                "yml"
                "sass"
                "css"
                "scss"
                "html"
              ];
              # Mirror .prettierignore (docs/ are mkdocs-flavoured; gen/ generated).
              fmtExclude = [
                ./gen
                ./docs
              ];
            }
          );
        };

        # nix/options.generated.nix: what the binary prints, every default
        # and example of its option's type, the examples loaded unchanged by
        # headscale, and descriptions that render.
        nixos-options =
          let
            inherit (pkgs) lib;
            options = import ./nix/options.generated.nix { inherit lib; };
            each = f: lib.mapAttrsRecursiveCond (o: !lib.isOption o) (_: f) options;
            eval = config: lib.evalModules { modules = [ { inherit options config; } ]; };
            defaults = eval (each (o: lib.mkIf (!(o ? default)) o.example));
            examples = eval (each (o: o.example));
            doc = pkgs.nixosOptionsDoc { inherit (examples) options; };
            # Development tool, not shipped: loads a file as headscale does.
            files = pkgs.headscale.overrideAttrs { subPackages = [ "tools/configgen/files" ]; };
            # Values of the wrong shape: each must fail the option it is set on.
            rejected = {
              listen_addr = [
                "8080"
                "::1:8080"
                "0.0.0.0:abc"
              ];
              "node.expiry" = [
                "30"
                ""
                "3 hours"
              ];
              unix_socket_permission = [
                "0778"
                "07777"
                504
              ];
              "prefixes.v4" = [
                "100.64.0.1"
                "100.64.0.0/33"
              ];
              "prefixes.v6" = [ "fd7a::/129" ];
              "oidc.issuer" = [
                "headscale.example.com"
                "ftp://x"
                "https://"
              ];
              "oidc.client_secret" = [ "hunter2" ];
              "database.postgres.pass" = [ "hunter2" ];
              # Relative to the config, which is in the store.
              "policy.path" = [
                "policy.hujson"
                42
              ];
              "tls.cert_path" = [ "cert.pem" ];
              "derp.paths" = [ [ "derp.yaml" ] ];
              # A key in the store is world-readable.
              "noise.private_key_path" = [
                ./flake.nix
                "${./flake.nix}"
                "noise_private.key"
              ];
              "tls.key_path" = [ "${./flake.nix}" ];
              "database.sqlite.path" = [ "db.sqlite" ];
              "dns.extra_records" = map (r: [ ({ name = "grafana.example.com"; } // r) ]) [
                { value = "grafana"; }
                { value = "256.1.1.1"; }
                {
                  type = "CNAME";
                  value = "100.64.0.3";
                }
                { }
              ];
            };
            # Only the option itself is forced, so nothing else can fail it.
            fails =
              name: value:
              let
                path = lib.splitString "." name;
                config = (eval (lib.setAttrByPath path value)).config;
              in
              lib.hasAttrByPath path options
              && !(builtins.tryEval (builtins.deepSeq (lib.getAttrFromPath path config) null)).success;
            accepted = lib.concatLists (
              lib.mapAttrsToList (
                name: values: map (v: "${name} = ${builtins.toJSON v}") (lib.filter (v: !fails name v) values)
              ) rejected
            );
          in
          assert lib.assertMsg (
            accepted == [ ]
          ) "nixos-options: types accept ${lib.concatStringsSep "; " accepted}";
          pkgs.runCommand "headscale-nixos-options"
            {
              nativeBuildInputs = [
                pkgs.headscale
                pkgs.yq-go
                pkgs.jq
              ];
              # Unused; evaluating it checks every default against its type.
              defaults = builtins.toJSON defaults.config;
              examples = builtins.toJSON examples.config;
              passAsFile = [ "examples" ];
            }
            ''
              headscale generate nixos-options | diff -u ${./nix/options.generated.nix} -
              cp "$examplesPath" examples.json
              ${files}/bin/files -load examples.json > loaded.yaml
              jq -S . examples.json > want.json
              yq -o json . loaded.yaml | jq -S . > got.json
              diff -u want.json got.json
              # A secret's NixOS form renders as Nix source takes it.
              grep -F '"file:\''${CREDENTIALS_DIRECTORY}/oidc_client_secret"' ${doc.optionsCommonMark}
              touch $out
            '';

        # Offline, so a new advisory for some action cannot fail unrelated
        # pull requests. Not named zizmor: that would shadow pkgs.zizmor in
        # devDeps' `with pkgs`.
        zizmor-check =
          pkgs.runCommand "headscale-zizmor"
            {
              nativeBuildInputs = [ pkgs.zizmor ];
              src = pkgs.lib.fileset.toSource {
                root = ./.;
                fileset = pkgs.lib.fileset.unions [
                  ./.github
                  ./.pre-commit-config.yaml
                ];
              };
            }
            ''
              # zizmor reads actions.lock only from a directory with a .git.
              cp -r "$src" tree
              chmod -R u+w tree
              mkdir tree/.git
              zizmor --offline --no-progress --cache-dir "$TMPDIR" tree
              touch $out
            '';
      in
      {
        # `nix develop`
        devShells.default = pkgs.mkShell {
          buildInputs = devDeps ++ [
            (pkgs.writeShellScriptBin "nix-vendor-sri" ''
              set -eu
              exec go run ./cmd/vendorhash update "$@"
            '')

            (pkgs.writeShellScriptBin "go-mod-update-all" ''
              cat go.mod | ${pkgs.ripgrep}/bin/rg "\t" | ${pkgs.ripgrep}/bin/rg -v '^\s*//' | ${pkgs.ripgrep}/bin/rg -v indirect | ${pkgs.gawk}/bin/awk '{print $1}' | ${pkgs.findutils}/bin/xargs go get -u
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

        # `nix fmt` is built from the same treefmt module as the formatting
        # check, so the two cannot disagree. Every formatter the tree is judged
        # by lives here, not in a hand-kept list of pre-commit hooks.
        formatter = fc.formatter (
          common
          // {
            goFmt = "off";
            prettier = true;
          }
        );

        # Gated to Linux: parts of the tree are Linux-specific, and the VM
        # tests need KVM.
        checks = pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
          goChecks
          // {
            headscale = pkgs.testers.runNixOSTest (import ./nix/tests/headscale.nix self);
            headscale-checks = pkgs.testers.runNixOSTest (import ./nix/tests/checks.nix self);
            nixos-module = import ./nix/tests/module.nix self pkgs;
            inherit nixos-options;
            zizmor = zizmor-check;
          }
        );
      }
    );
}
