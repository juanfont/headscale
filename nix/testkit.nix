# Makes a NixOS test node a headscale control server that any Tailscale client
# joins without trust setup: plain-HTTP control, plus the same router on a
# self-signed TLS :443 whose DERP region is InsecureForTests. That is the one
# shape tailscaled, tsnet, webpki-only tailscale-rs and the Android app all
# accept. Contract: nix/README.md.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  hs-authkey = pkgs.writeShellApplication {
    name = "hs-authkey";
    runtimeInputs = [
      config.services.headscale.package
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.gnused
    ];
    text = ''
      : "''${1:?usage: hs-authkey OWNER [headscale auth keys create flags]}"
      line=("$@")
      # A flag may be given once, and only the CLI's parser knows which word
      # is a flag. Tab asks it without running anything or dialling a server:
      # the flags it offers after the line are the ones not given yet. It
      # offers none where a flag still waits for its value, or after --; the
      # kit then adds nothing. __complete is the protocol the shipped
      # completion scripts call.
      offered=$(headscale __complete auth keys create "''${line[@]}" -- 2>/dev/null | cut -f1)
      defaults=()
      grep -qx -- --reusable <<<"$offered" && defaults+=(--reusable)
      grep -qx -- --expiry <<<"$offered" && defaults+=(--expiry 24h)
      # --config is the one root flag that chooses the server (and with it
      # the credential). While Tab still offers it, the environment chooses
      # for every command the kit runs. When it does not (the caller gave
      # --config, or the line ends after -- or at a pending value, where Tab
      # offers nothing), the kit runs only the caller's line, with the
      # defaults Tab offered: none after --.
      environment=
      grep -qx -- --config <<<"$offered" && environment=1
      if [ -n "$environment" ]; then
        # Safe straight after start_all(): the CLI retries the socket until this.
        HEADSCALE_CLI_TIMEOUT=''${HEADSCALE_CLI_TIMEOUT:-60s} headscale debug health >/dev/null
      fi
      errors=$(mktemp)
      trap 'rm -f "$errors"' EXIT
      if headscale auth keys create "''${line[@]}" "''${defaults[@]}" 2>"$errors"; then
        cat "$errors" >&2
        exit 0
      fi
      # The user the CLI names as missing, as its parser read the owner. The
      # kit makes it with no word of the caller's line, so only on the
      # server the environment chooses, and asks again.
      user=$(sed -n 's/^Error: no user matches "\(.*\)"\.$/\1/p' "$errors")
      if [ -z "$user" ]; then
        cat "$errors" >&2
        exit 1
      fi
      if [ -z "$environment" ]; then
        cat "$errors" >&2
        echo "hs-authkey: create the user $user on the same server first, then run this line again" >&2
        exit 1
      fi
      headscale users create "$user" >/dev/null
      headscale auth keys create "''${line[@]}" "''${defaults[@]}"
    '';
  };
in
{
  key = "headscale-testkit";
  _file = ./testkit.nix;
  imports = [ self.nixosModules.headscale ];

  services.headscale = {
    enable = true;
    settings = {
      server_url = "http://${config.networking.hostName}";
      listen_addr = "[::]:80";
      dns.base_domain = lib.mkDefault "tailnet";
      dns.override_local_dns = lib.mkDefault false;
      # Nothing stored allows all, and `headscale policy set` works live.
      policy.mode = lib.mkDefault "database";
      derp = {
        urls = [ ];
        server = {
          enabled = true;
          region_id = 999;
          region_code = "headscale";
          region_name = "headscale test kit";
          stun_listen_addr = "[::]:3478";
        };
      };
    };
  };

  # DERP rides this listener, and so does noise: Go clients redial only :443
  # for a hostname URL after a recent dial.
  systemd.services.headscale = {
    environment.HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR = "[::]:443";
    # The module grants this from listen_addr, which does not name this :443.
    serviceConfig.AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
    serviceConfig.CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
  };

  networking.firewall = {
    allowedTCPPorts = [
      80
      443
    ];
    allowedUDPPorts = [ 3478 ];
  };

  environment.systemPackages = [ hs-authkey ];
}
