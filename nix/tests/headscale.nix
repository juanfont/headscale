# The test kit's contract test, and CI's coverage of nix/module.nix.
self:
{ lib, pkgs, ... }:
let
  # A config that names the server for the CLI alone: hs-authkey -c.
  cliConfig = pkgs.writeText "cli.yaml" "unix_socket: /run/headscale/headscale.sock\n";
  policy = pkgs.writeText "policy.json" (
    builtins.toJSON {
      tagOwners."tag:ci" = [ ];
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
      services.headscale.settings.dns = {
        extra_records = [
          {
            name = "foo.bar";
            type = "A";
            value = "100.64.0.2";
          }
        ];
        # Startup builds the provider but does not call it.
        certificates.enabled = true;
        challenge.provider = {
          name = "rfc2136";
          server = "127.0.0.1:53";
          key_name = "headscale.";
          key_alg = "hmac-sha256.";
          key = "file:\${CREDENTIALS_DIRECTORY}/tsig";
        };
      };
      # Read by serve, never by the checks.
      systemd.services.headscale.serviceConfig.LoadCredential = [
        "tsig:${pkgs.writeText "tsig" "c2VjcmV0"}"
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
    peer1.wait_until_succeeds(
        "tailscale status --json | ${lib.getExe pkgs.jq} -e '.CertDomains == [\"peer1.tailnet\"]'"
    )

    headscale.succeed("headscale policy set ${policy}")
    # A tag owner makes no user, and the caller's flags replace the kit's own.
    headscale.succeed("hs-authkey tag:ci --expiry 1h --reusable=false")
    headscale.succeed(
        "headscale auth keys list --filter owner=tag:ci -o json | ${lib.getExe pkgs.jq} -e 'length == 1 and (.[0].reusable | not)'"
    )
    # A caller's value that looks like a flag is a value: the kit keeps its own.
    headscale.succeed("hs-authkey test --description --reusable")
    headscale.succeed("hs-authkey test --description --expiry")
    headscale.succeed(
        "headscale auth keys list -o json | ${lib.getExe pkgs.jq} -e '[.[] | select(.description | startswith(\"--\"))] | length == 2 and all(.reusable and (.expiry | sub(\"[.][0-9]+\"; \"\") | fromdateiso8601) > now + 43200)'"
    )
    # The kit asks Tab, which runs nothing: a line that ends in a flag
    # waiting for its value makes no key, and --help shows the help.
    keys = "headscale auth keys list --all -o json | ${lib.getExe pkgs.jq} length"
    before = headscale.succeed(keys).strip()
    headscale.fail("hs-authkey tag:ci --description")
    out = headscale.succeed("hs-authkey tag:ci --expiry 1h --help")
    assert "Usage:" in out, out
    assert headscale.succeed(keys).strip() == before, "a probe made a key"
    # A tag with space around it is a tag, as auth keys create reads it.
    headscale.succeed("hs-authkey ' tag:ci '")
    headscale.succeed("hs-authkey $'\\xc2\\xa0tag:ci'")
    headscale.succeed(
        "headscale auth keys list --filter owner=tag:ci -o json | ${lib.getExe pkgs.jq} -e 'length == 3'"
    )
    # After --, Tab offers no flag, so the caller's flags stand alone.
    headscale.succeed("hs-authkey tag:ci --reusable=false -e 2h --")
    headscale.succeed("headscale users list -o json | ${lib.getExe pkgs.jq} -e 'map(.name) == [\"test\"]'")
    # A -c on the line chooses the server for that line alone, so the kit
    # makes no user there: the default server is unreachable here, and the
    # line still goes where -c points once the user exists.
    other = "env -u HEADSCALE_UNIX_SOCKET HEADSCALE_CONFIG=/nonexistent.yaml hs-authkey other -c ${cliConfig}"
    out = headscale.fail(other + " 2>&1")
    assert "create the user other on the same server first" in out, out
    headscale.succeed("headscale users list -o json | ${lib.getExe pkgs.jq} -e 'map(.name) == [\"test\"]'")
    headscale.succeed("headscale users create other")
    headscale.succeed(other)
    # After --, Tab offers nothing: the kit makes no user, and says how.
    out = headscale.fail("hs-authkey nobody -- 2>&1")
    assert "create the user nobody on the same server first" in out, out
    headscale.succeed("headscale users list -o json | ${lib.getExe pkgs.jq} -e 'map(.name) == [\"test\", \"other\"]'")
    # With the environment choosing, the kit makes the user the CLI names,
    # with no word of the line: key-only flags and padding do not matter.
    headscale.succeed("hs-authkey $'\\xc2\\xa0fresh ' --ephemeral")
    headscale.succeed("headscale users list -o json | ${lib.getExe pkgs.jq} -e 'map(.name) == [\"test\", \"other\", \"fresh\"]'")
    # The default socket needs neither a config file nor a variable.
    headscale.succeed("env -u HEADSCALE_UNIX_SOCKET headscale nodes list")
    # sudo resets the environment; PAM sets the module's variables again.
    out = headscale.succeed("env -u HEADSCALE_DISABLE_CHECK_UPDATES sudo printenv HEADSCALE_DISABLE_CHECK_UPDATES")
    assert out.strip() == "true", out

    # The docs tell operators to run this; it needs ExecReload in the unit.
    headscale.succeed("systemctl reload headscale.service")
    headscale.wait_until_succeeds("journalctl -u headscale.service --grep 'Received SIGHUP'")

    # Clients reconnect after a control restart, peer1 over the TLS listener.
    headscale.systemctl("restart headscale.service")
    headscale.wait_until_succeeds(
        "headscale nodes list -o json | ${lib.getExe pkgs.jq} -e 'length == 2 and all(.[]; .connectedToControl)'",
        timeout=timedelta(minutes=2),
    )
    peer1.wait_until_succeeds("tailscale ping --until-direct=false -c 1 peer2")
  '';
}
