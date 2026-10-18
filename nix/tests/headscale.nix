# The test kit's contract test, and CI's coverage of nix/module.nix.
self:
{ lib, pkgs, ... }:
let
  policy = pkgs.writeText "policy.json" (
    builtins.toJSON {
      acls = [
        {
          action = "accept";
          src = [ "*" ];
          dst = [ "*:*" ];
        }
      ];
    }
  );
in
{
  name = "headscale";
  meta.maintainers = with lib.maintainers; [
    kradalby
    misterio77
  ];

  nodes = {
    headscale = {
      imports = [ self.nixosModules.testkit ];
      services.headscale.settings.dns.extra_records = [
        {
          name = "foo.bar";
          type = "A";
          value = "100.64.0.2";
        }
      ];
    };
    # All of peer1's noise goes over the kit's TLS listener, not plain :80.
    peer1 = {
      imports = [ self.nixosModules.testkit-peer ];
      systemd.services.tailscaled.environment.TS_FORCE_NOISE_443 = "1";
    };
    # No direct UDP for peer2: its traffic has to cross the kit's DERP.
    peer2 = {
      imports = [ self.nixosModules.testkit-peer ];
      systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
    };
  };

  testScript = ''
    from datetime import timedelta

    start_all()
    key = headscale.succeed("hs-authkey test").strip()
    for peer in [peer1, peer2]:
        peer.succeed(f"hs-join {key}")

    peer1.wait_until_succeeds("tailscale ping --until-direct=false -c 1 peer2 | grep -F 'via DERP(headscale)'")
    peer2.wait_until_succeeds("tailscale ping --until-direct=false -c 1 peer1.tailnet")
    res = peer1.wait_until_succeeds("${lib.getExe pkgs.dig} +short foo.bar").strip()
    assert res == "100.64.0.2", res

    headscale.succeed("headscale policy set -f ${policy}")

    # Clients reconnect after a control restart, peer1 over the TLS listener.
    headscale.systemctl("restart headscale.service")
    headscale.wait_until_succeeds(
        "headscale nodes list -o json | ${lib.getExe pkgs.jq} -e 'length == 2 and all(.[]; .online)'",
        timeout=timedelta(minutes=2),
    )
    peer1.wait_until_succeeds("tailscale ping --until-direct=false -c 1 peer2")
  '';
}
