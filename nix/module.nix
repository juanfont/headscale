{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.headscale;

  dataDir = "/var/lib/headscale";
  runDir = "/run/headscale";

  settingsFormat = pkgs.formats.yaml { };

  # headscale reads a non-empty variable of the unit over the setting.
  effective =
    name: setting:
    let
      v = config.systemd.services.headscale.environment.${name} or null;
    in
    if v == null || v == "" then setting else v;
  policyMode = effective "HEADSCALE_POLICY_MODE" cfg.settings.policy.mode;
  policyPath = effective "HEADSCALE_POLICY_PATH" cfg.settings.policy.path;
  # Interpolated as the config and the unit are, so a Nix path is the same store path.
  policyFile = if policyMode == "file" && policyPath != "" then "${policyPath}" else null;
  policyFileCheck = cfg.check.policy && policyFile != null;
  # The build can read a store path, and must be able to run the binary.
  buildTimePolicy =
    policyFileCheck
    && lib.hasPrefix "${builtins.storeDir}/" policyFile
    && pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform;
  preSwitchPolicy = policyFileCheck && !buildTimePolicy;

  policyCheck = pkgs.runCommand "headscale-policy-check" { } ''
    ${lib.getExe cfg.package} check policy -f ${lib.escapeShellArg policyFile}
    touch $out
  '';

  # Its own script, for shellcheck and runtimeInputs.
  preSwitchCheck =
    let
      # systemd gives the unit Group= and the account's /etc/group memberships.
      # Activation rewrites the account's memberships in the groups NixOS
      # declares (members holds extraGroups), so those come from the new
      # configuration. With mutableUsers it keeps a hand-made group.
      groups = [
        "headscale"
      ]
      ++ map (g: g.name) (
        lib.filter (g: lib.elem "headscale" g.members) (lib.attrValues config.users.groups)
      )
      ++ lib.filter (g: g != "") (
        lib.concatMap (g: lib.splitString " " (toString g)) (
          lib.toList (config.systemd.services.headscale.serviceConfig.SupplementaryGroups or [ ])
        )
      );
      declared = map (g: g.name) (lib.attrValues config.users.groups);
      unitEnv = lib.mapAttrsToList (n: v: "${n}=${toString v}") (
        lib.filterAttrs (_: v: v != null) config.systemd.services.headscale.environment
      );
    in
    pkgs.writeShellApplication {
      name = "headscale-pre-switch-check";
      runtimeInputs = [
        pkgs.coreutils
        pkgs.getent
        pkgs.util-linux
      ];
      text = ''
        # An unchanged unit is not restarted, so there is nothing to protect.
        unit=etc/systemd/system/headscale.service
        if [ "$(readlink -f "/run/current-system/$unit")" = "$(readlink -f "$1/$unit")" ]; then
          echo "headscale: unit unchanged, skipping checks"
          exit 0
        fi
        # Activation creates users and groups after this check runs.
        if ! id -u headscale >/dev/null 2>&1; then
          echo "headscale: user headscale does not exist yet, skipping checks"
          exit 0
        fi
        if ! getent group headscale >/dev/null; then
          echo "headscale: group headscale does not exist yet, skipping checks"
          exit 0
        fi
        trap '[ "$?" = 0 ] || echo "headscale: to skip, set services.headscale.check.config and check.policy to false, or run once with NIXOS_NO_CHECK=1"' EXIT

        # A group this switch creates does not exist yet; setpriv would fail on it.
        want=(${lib.escapeShellArgs groups})
        ${lib.optionalString config.users.mutableUsers ''
          # Not the account's primary group, which the unit does not get, nor a
          # group NixOS declares now, or declared before and activation removes.
          skip=" $(id -gn headscale 2>/dev/null || true) "${lib.escapeShellArg (toString declared)}" $(cat /var/lib/nixos/declarative-groups 2>/dev/null || true) "
          for g in $(id -Gn headscale); do
            [[ $skip == *" $g "* ]] || want+=("$g")
          done
        ''}
        groups=()
        for g in "''${want[@]}"; do
          if getent group "$g" >/dev/null; then groups+=("$g"); fi
        done
        grouplist=$(IFS=,; echo "''${groups[*]}")

        # As the unit's user and groups, with the unit's environment rather than the caller's.
        hs() {
          setpriv --reuid=headscale --regid=headscale --groups="$grouplist" -- \
            env -i ${lib.escapeShellArgs unitEnv} ${lib.getExe cfg.package} "$@"
        }

        ${lib.optionalString cfg.check.config ''
          echo "headscale: checking the new configuration"
          hs check all -f ${cfg.configFile}
        ''}
        ${lib.optionalString preSwitchPolicy ''
          echo "headscale: checking the new policy"
          hs check policy -f ${lib.escapeShellArg policyFile}
        ''}
      '';
    };

  # The option's type admits a number or http/https as the port, or an empty
  # listen_addr, which grants nothing. Past four digits a port is never
  # privileged, and the cap keeps toIntBase10 from throwing on a number too
  # long for an integer.
  listenPort = lib.last (lib.splitString ":" cfg.settings.listen_addr);
  listenDigits = builtins.match "0*([0-9]{1,4})" listenPort;
  privilegedPort =
    lib.elem listenPort [
      "http"
      "https"
    ]
    || (listenDigits != null && lib.toIntBase10 (lib.head listenDigits) < 1024);

  # Below lib.mkDefault, so a user's own mkDefault replaces these values
  # instead of conflicting with a scalar or merging into a list.
  distroDefault = lib.mkOverride 1200;

  # Go reads cli, nested or dotted, as the client-only cli.*; written to the
  # config, cli.api_key would land in the world-readable store.
  cliKeys = lib.filter (n: n == "cli" || lib.hasPrefix "cli." n) (lib.attrNames cfg.settings);
in
{
  # Disable the upstream NixOS module to prevent conflicts
  disabledModules = [ "services/networking/headscale.nix" ];

  options = {
    services.headscale = {
      enable = lib.mkEnableOption "headscale, Open Source coordination server for Tailscale";

      package = lib.mkPackageOption pkgs "headscale" { };

      configFile = lib.mkOption {
        type = lib.types.path;
        readOnly = true;
        default = settingsFormat.generate "headscale.yaml" cfg.settings;
        defaultText = lib.literalMD "{option}`services.headscale.settings` as YAML";
        description = ''
          Path to the configuration file of headscale:
          {option}`services.headscale.settings` as YAML.
        '';
      };

      check.config = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Before a switch restarts headscale, run the new package's
          `headscale check all` on the new configuration and abort the switch
          if it fails. It checks the configuration and every file it names
          (policy, DERP maps, extra records, TLS pair, existing noise and DERP
          keys) as the `headscale` user. Keys are read, never created.

          It runs outside the unit, and only when headscale's unit changes.
          It never reads a `file:` secret, so credentials referenced with
          `file:` pass. Turning off only {option}`services.headscale.check.policy`
          does not skip the policy here. Skip all checks once with
          `NIXOS_NO_CHECK=1`.
        '';
      };

      check.policy = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          In file policy mode, run `headscale check policy -f` on the new
          policy: it checks the policy and runs its `tests` and `sshTests`
          against one node for each user and tag the policy names. A policy in
          the Nix store is checked while building the system (native builds
          only), so a bad policy fails `nixos-rebuild build`. Any other policy
          is checked before a switch restarts headscale.
          {option}`services.headscale.check.config` checks the policy before a
          switch too; turn off both to skip every policy check.
        '';
      };

      # Read-only, kept only because nixpkgs' headplane module reads them.
      user = lib.mkOption {
        type = lib.types.str;
        default = "headscale";
        readOnly = true;
        description = "User account under which headscale runs, created by this module.";
      };

      group = lib.mkOption {
        type = lib.types.str;
        default = "headscale";
        readOnly = true;
        description = "Group under which headscale runs, created by this module.";
      };

      settings = lib.mkOption {
        description = ''
          headscale's configuration, written to
          {option}`services.headscale.configFile`. Each option is one key of
          [Configuration options](https://headscale.net/stable/ref/configuration-options/).
          A key without an option passes through to headscale, which rejects
          unknown keys.
        '';
        type = lib.types.submodule {
          freeformType = settingsFormat.type;
          options = import ./options.generated.nix { inherit lib; };
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    system.checks = lib.optional buildTimePolicy policyCheck;

    system.preSwitchChecks.headscale = lib.mkIf (
      cfg.check.config || preSwitchPolicy
    ) ''${lib.getExe preSwitchCheck} "$@"'';

    assertions = [
      {
        assertion = cliKeys == [ ];
        message = "services.headscale.settings: remove ${lib.concatStringsSep ", " cliKeys}: the server never reads cli.*; headscale's CLI reads ~/.config/headscale/config.yaml or HEADSCALE_CLI_*, and here it would be written to the world-readable Nix store.";
      }
    ];

    services.headscale.settings = lib.mapAttrsRecursive (_: distroDefault) {
      # Where this module keeps state and the socket. Nix pins the package, so
      # an update notice cannot be acted on.
      noise.private_key_path = "${dataDir}/noise_private.key";
      derp.server.private_key_path = "${dataDir}/derp_server_private.key";
      database.type = "sqlite";
      database.sqlite.path = "${dataDir}/db.sqlite";
      unix_socket = "${runDir}/headscale.sock";
      disable_check_updates = true;

      # Earlier defaults of this module that headscale's own do not match,
      # kept so an upgrade does not change a running configuration.
      listen_addr = "127.0.0.1:8080";
      prefixes.v4 = "100.64.0.0/10";
      prefixes.v6 = "fd7a:115c:a1e0::/48";
      derp.urls = [ "https://controlplane.tailscale.com/derpmap/default" ];
      derp.auto_update_enabled = true;
      derp.update_frequency = "24h";
      node.ephemeral.inactivity_timeout = "30m";
    };

    environment = {
      systemPackages = [ cfg.package ];

      # The local CLI reads no file: these point it at the server's socket and
      # update-check setting. Through PAM, so sudo keeps them too.
      sessionVariables = {
        HEADSCALE_UNIX_SOCKET = cfg.settings.unix_socket;
        HEADSCALE_DISABLE_CHECK_UPDATES = lib.boolToString cfg.settings.disable_check_updates;
      };
    };

    users.groups.headscale = { };

    users.users.headscale = {
      description = "headscale user";
      home = dataDir;
      group = "headscale";
      isSystemUser = true;
    };

    systemd.services.headscale = {
      description = "headscale coordination server for Tailscale";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      script = ''
        exec ${lib.getExe cfg.package} serve --config ${cfg.configFile}
      '';

      serviceConfig =
        let
          # "" empties the set, and comes first, so the unit gets only the
          # capabilities listed after it, here or by another module.
          capabilities = lib.mkBefore ([ "" ] ++ lib.optional privilegedPort "CAP_NET_BIND_SERVICE");
        in
        {
          ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
          Restart = "always";
          RestartSec = "5s";
          Type = "simple";
          # Read here, so setting either read-only option fails evaluation.
          User = cfg.user;
          Group = cfg.group;

          # Hardening options
          RuntimeDirectory = "headscale";
          # Allow headscale group access so users can be added and use the CLI.
          RuntimeDirectoryMode = "0750";

          StateDirectory = "headscale";
          StateDirectoryMode = "0750";

          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectControlGroups = true;
          RestrictSUIDSGID = true;
          PrivateMounts = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectHostname = true;
          ProtectClock = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          RestrictNamespaces = true;
          RemoveIPC = true;
          UMask = "0077";

          CapabilityBoundingSet = capabilities;
          AmbientCapabilities = capabilities;
          NoNewPrivileges = true;
          LockPersonality = true;
          RestrictRealtime = true;
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
          ];
          SystemCallArchitectures = "native";
          RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";
        };
    };
  };

  meta.maintainers = with lib.maintainers; [
    kradalby
    misterio77
  ];
}
