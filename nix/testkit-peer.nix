# A tailscaled peer for nix/testkit.nix: `hs-join KEY` joins the kit's control
# node, which is named headscale. Contract: nix/README.md.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  hs-join = pkgs.writeShellApplication {
    name = "hs-join";
    runtimeInputs = [ config.services.tailscale.package ];
    text = ''
      key=''${1:?usage: hs-join KEY [tailscale up flags]}
      shift
      # Returns once tailscaled is up, so joining straight after boot can't race it.
      systemctl start tailscaled.service
      # Broken control fails here instead of hanging the test to its global timeout.
      exec tailscale up --timeout=60s --login-server http://headscale --auth-key "$key" "$@"
    '';
  };
in
{
  key = "headscale-testkit-peer";
  services.tailscale.enable = true;
  # Interactive driver runs have a route out; keep their logs off Tailscale's servers.
  services.tailscale.disableUpstreamLogging = lib.mkDefault true;
  environment.systemPackages = [ hs-join ];
}
