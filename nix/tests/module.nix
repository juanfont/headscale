# What the module writes, grants and exports, without a VM. headscale's own
# check decides what the written config means.
self: pkgs:
let
  inherit (pkgs) lib;

  required = {
    server_url = "https://headscale.example.com";
    dns.base_domain = "tailnet.example.com";
    dns.nameservers.global = [ "192.0.2.53" ];
  };
  system =
    m:
    pkgs.nixos {
      imports = [
        self.nixosModules.default
        m
      ];
      services.headscale = {
        enable = true;
        settings = required;
      };
    };
  settings = s: system { services.headscale.settings = s; };

  policy = pkgs.writeText "policy.json" "{}";
  derpMap = pkgs.writeText "derp.yaml" "regions: {}";

  ok = settings {
    policy = {
      mode = "file";
      path = policy;
    };
    derp.paths = [ derpMap ];
    unix_socket = "/run/headscale/moved.sock";
    dns = {
      certificates.enabled = true;
      challenge.provider = {
        name = "rfc2136";
        server = "127.0.0.1:53";
        key_name = "headscale.";
        key_alg = "hmac-sha256.";
        key = "file:\${CREDENTIALS_DIRECTORY}/tsig";
      };
    };
  };
  http = settings { listen_addr = ":http"; };
  # A user's mkDefault and a plain assignment both replace the module's values.
  overrides = settings {
    prefixes.v4 = lib.mkDefault "100.96.0.0/11";
    derp.urls = lib.mkDefault [ "https://derp.example.com/map.json" ];
    derp.update_frequency = "1h";
  };
  # Both spellings Go reads as cli.*.
  clis = settings {
    cli.api_key = "not-for-the-store";
    "cli.api_key" = "not-for-the-store";
  };
  # Key errors only: headscale stops at them before it reads any value.
  bad = settings {
    listen_addr = "[::]:443";
    dns.magic_dsn = true;
    oidc.client_secret_path = "/run/x";
    db_password_file = "/run/x";
    tls_cert_path = "/x";
  };
  badUrl = settings { server_url = lib.mkForce "ftp://headscale"; };
  # A record's unknown field is a decoding error, reported without the others.
  badRecord = settings {
    dns.extra_records = [
      {
        name = "grafana.tailnet.example.com";
        value = "100.64.0.3";
        typo = "A";
      }
    ];
  };
  # A system evaluated inside the build, where the test can read its error.
  evalSystem = pkgs.writeText "eval-system.nix" ''
    { case }:
    let
      inherit
        (import ${pkgs.path}/nixos/lib/eval-config.nix {
          system = "${pkgs.stdenv.hostPlatform.system}";
          modules = [
            ${self}/nix/module.nix
            (builtins.fromJSON (builtins.readFile case))
          ];
        })
        config
        ;
      unit = config.systemd.services.headscale.serviceConfig;
    in
    # What building the system reads: the settings and the unit's account.
    builtins.deepSeq [
      config.services.headscale.settings
      unit.User
      unit.Group
    ] true
  '';
  evalCase =
    name: c:
    pkgs.writeText "${name}.json" (
      builtins.toJSON (
        lib.recursiveUpdate {
          services.headscale = {
            enable = true;
            settings = required;
          };
        } c
      )
    );

  configFile = s: s.config.services.headscale.configFile;
  binds =
    s:
    lib.elem "CAP_NET_BIND_SERVICE" s.config.systemd.services.headscale.serviceConfig.CapabilityBoundingSet;
  inherit (ok.config.environment) sessionVariables;
  overridden = overrides.config.services.headscale.settings;
in
assert lib.assertMsg (
  sessionVariables.HEADSCALE_UNIX_SOCKET or null == "/run/headscale/moved.sock"
) "ok: HEADSCALE_UNIX_SOCKET is not settings.unix_socket";
assert lib.assertMsg (
  sessionVariables.HEADSCALE_DISABLE_CHECK_UPDATES or null == "true"
) "ok: HEADSCALE_DISABLE_CHECK_UPDATES is not true";
assert lib.assertMsg (
  overridden.prefixes.v4 == "100.96.0.0/11"
) "overrides: a user's mkDefault does not replace prefixes.v4";
assert lib.assertMsg (
  overridden.derp.urls == [
    "https://derp.example.com/map.json"
  ]
) "overrides: a user's mkDefault does not replace derp.urls";
assert lib.assertMsg (
  overridden.derp.update_frequency == "1h"
) "overrides: a plain assignment does not replace derp.update_frequency";
assert lib.assertMsg (lib.any (
  a: !a.assertion && lib.hasPrefix "services.headscale.settings: remove cli, cli.api_key:" a.message
) clis.config.assertions) "clis: no failed assertion names every spelling of settings.cli";
assert lib.assertMsg (
  !(ok.config.environment.etc ? "headscale/config.yaml")
) "ok: /etc/headscale/config.yaml is written";
assert lib.assertMsg (!binds ok) "ok: 127.0.0.1:8080 grants CAP_NET_BIND_SERVICE";
assert lib.assertMsg (binds http) "http: :http does not grant CAP_NET_BIND_SERVICE";
assert lib.assertMsg (binds bad) "bad: [::]:443 does not grant CAP_NET_BIND_SERVICE";
assert lib.assertMsg (
  ok.config.systemd.services.headscale.serviceConfig.CapabilityBoundingSet == [ "" ]
) "ok: the unit keeps a capability";
pkgs.runCommand "headscale-nixos-module"
  {
    nativeBuildInputs = [
      ok.config.services.headscale.package
      pkgs.yq-go
      pkgs.jq
      pkgs.nix
    ];
  }
  ''
    want() {
      yq -o json "$1" | jq -e "$2" >/dev/null || { echo "$1: want $2"; cat "$1"; exit 1; }
    }
    rejects() {
      local file=$1 out
      shift
      if out=$(headscale check config -f "$file" 2>&1); then
        echo "$file: check config passed"
        exit 1
      fi
      for msg in "$@"; do
        grep -qF -- "$msg" <<<"$out" || { echo "$file: no '$msg' in:"; echo "$out"; exit 1; }
      done
    }

    ok=${configFile ok}
    want $ok '.policy.path == "${policy}" and .derp.paths == ["${derpMap}"]'
    want $ok 'has("cli") | not'
    want $ok '.listen_addr == "127.0.0.1:8080" and .disable_check_updates == true'
    want $ok '.database.type == "sqlite"'
    want $ok '.derp.urls[0] == "https://controlplane.tailscale.com/derpmap/default"'
    headscale check config -f $ok

    bad=${configFile bad}
    want $bad '(.dns | has("magic_dsn")) and (.oidc | has("client_secret_path"))'
    want $bad 'has("db_password_file") and has("tls_cert_path")'
    rejects $bad 'unknown configuration key dns.magic_dsn' \
      'oidc.client_secret_path was removed' \
      'db_password_file was removed' \
      'tls_cert_path was removed'

    rejects ${configFile badUrl} 'missing a scheme'

    badRecord=${configFile badRecord}
    want $badRecord '.dns.extra_records[0].typo == "A"'
    rejects $badRecord 'dns.extra_records has invalid keys: typo'

    export HOME=$TMPDIR NIX_STATE_DIR=$TMPDIR/state NIX_CONF_DIR=$TMPDIR/etc NIX_LOG_DIR=$TMPDIR/log
    evaluate() {
      nix-instantiate --store dummy:// --readonly-mode --eval --strict ${evalSystem} --argstr case "$1" 2>&1
    }
    evalFails() {
      local case=$1 out
      shift
      if out=$(evaluate "$case"); then
        echo "$case: evaluates"
        exit 1
      fi
      for msg in "$@"; do
        grep -qF -- "$msg" <<<"$out" || { echo "$case: no '$msg' in:"; echo "$out"; exit 1; }
      done
    }
    # The distro defaults pass their types.
    evaluate ${evalCase "defaults" { }} || exit 1
    evalFails ${
      evalCase "store-key" { services.headscale.settings.noise.private_key_path = "${./module.nix}"; }
    } "services.headscale.settings.noise.private_key_path' is not of type"
    evalFails ${
      evalCase "literal-secret" { services.headscale.settings.oidc.client_secret = "hunter2"; }
    } "services.headscale.settings.oidc.client_secret' is not of type"
    evalFails ${
      evalCase "no-port" { services.headscale.settings.listen_addr = "0.0.0.0"; }
    } "services.headscale.settings.listen_addr' is not of type"
    evalFails ${
      evalCase "user" { services.headscale.user = "hs2"; }
    } "services.headscale.user' is read-only"
    evalFails ${
      evalCase "group" { services.headscale.group = "hs2"; }
    } "services.headscale.group' is read-only"
    touch $out
  ''
