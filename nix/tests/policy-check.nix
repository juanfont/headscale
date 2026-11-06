# A switch to a config or policy headscale rejects must fail before headscale
# restarts, checked against a throwaway copy of the live database.
self:
{ lib, pkgs, ... }:
let
  writePolicy = name: policy: pkgs.writeText name (builtins.toJSON policy);
  acceptAll = [
    {
      action = "accept";
      src = [ "*" ];
      dst = [ "*:*" ];
    }
  ];
  valid = writePolicy "valid.json" { acls = acceptAll; };
  # group:missing is never defined, so headscale refuses to load this.
  invalid = writePolicy "invalid.json" {
    acls = [
      {
        action = "accept";
        src = [ "group:missing" ];
        dst = [ "*:*" ];
      }
    ];
  };
  # Only real data decides these: test@ has a node in the live database.
  testsPass = writePolicy "tests-pass.json" {
    acls = acceptAll;
    tests = [
      {
        src = "test@";
        accept = [ "test@:22" ];
      }
    ];
  };
  testsFail = writePolicy "tests-fail.json" {
    acls = acceptAll;
    tests = [
      {
        src = "test@";
        deny = [ "test@:22" ];
      }
    ];
  };
  withPolicy = path: extra: {
    imports = [
      { services.headscale.settings.policy.path = lib.mkForce path; }
      { services.headscale = extra; }
    ];
  };
in
{
  name = "headscale-policy-check";
  meta.maintainers = with lib.maintainers; [ kradalby ];

  nodes = {
    headscale = {
      imports = [ self.nixosModules.testkit ];
      services.headscale.settings.policy = {
        mode = "file";
        path = valid;
      };
      specialisation = lib.mapAttrs (_: c: { configuration = c; }) {
        invalid = withPolicy invalid { };
        invalidConfig = withPolicy valid { settings.server_url = lib.mkForce "ftp://headscale"; };
        testsPass = withPolicy testsPass { };
        testsFail = withPolicy testsFail { };
        testsFailUnchecked = withPolicy testsFail { check.policy = false; };
        unchecked = withPolicy invalid {
          check = {
            config = false;
            policy = false;
          };
        };
      };
    };
    peer.imports = [ self.nixosModules.testkit-peer ];
  };

  testScript =
    { nodes, ... }:
    ''
      def stc(spec, action):
          return f"${nodes.headscale.system.build.toplevel}/specialisation/{spec}/bin/switch-to-configuration {action} 2>&1"

      def main_pid():
          return headscale.succeed("systemctl show -P MainPID headscale.service").strip()

      def policy_has_tests():
          return headscale.succeed("headscale policy get | ${lib.getExe pkgs.jq} 'has(\"tests\")'").strip()

      def assert_rejected(spec, why):
          out = headscale.fail(stc(spec, "test"))
          assert "Pre-switch check 'headscale' failed" in out, out
          assert why in out, out

      def assert_no_tmp():
          headscale.succeed("test -z \"$(find /tmp -maxdepth 1 -name 'headscale-check.*')\"")

      start_all()
      key = headscale.succeed("hs-authkey test").strip()
      peer.succeed(f"hs-join {key}")
      headscale.wait_until_succeeds("headscale nodes list -o json | ${lib.getExe pkgs.jq} -e 'length == 1'")

      with subtest("rejected switches leave the running headscale alone"):
          pid = main_pid()
          assert_rejected("invalid", 'group not found: "group:missing"')
          assert_rejected("invalidConfig", "server_url is missing a scheme")
          assert_rejected("testsFail", "test@")
          assert main_pid() == pid, "headscale was restarted"
          assert policy_has_tests() == "false", "old policy no longer served"
          headscale.succeed("headscale health")
          assert_no_tmp()

      with subtest("escape hatches"):
          headscale.succeed(stc("testsFailUnchecked", "check"))
          headscale.succeed(stc("unchecked", "check"))
          headscale.succeed("NIXOS_NO_CHECK=1 " + stc("invalid", "check"))

      with subtest("a stopped headscale is checked without changing its files"):
          headscale.systemctl("stop headscale.service")
          # SQLite may add -wal/-shm sidecars; nothing else may change.
          snapshot = "cd /var/lib/headscale && ls -A | grep -vE '^db.sqlite-(wal|shm)$' && sha256sum $(ls -A | grep -vE '^db.sqlite-(wal|shm)$')"
          before = headscale.succeed(snapshot)
          headscale.fail(stc("invalid", "check"))
          # Passes only if the copy holds test@ and its node.
          headscale.succeed(stc("testsPass", "check"))
          after = headscale.succeed(snapshot)
          assert before == after, f"live state changed:\n{before}\n{after}"
          assert_no_tmp()

      with subtest("no database yet: nothing to check against"):
          headscale.succeed("mv /var/lib/headscale/db.sqlite /var/lib/headscale/db.sqlite.bak")
          out = headscale.succeed(stc("testsFail", "check"))
          assert "skipping checks" in out, out
          headscale.succeed("mv /var/lib/headscale/db.sqlite.bak /var/lib/headscale/db.sqlite")
          headscale.systemctl("start headscale.service")
          headscale.wait_for_unit("headscale.service")

      with subtest("a valid switch goes through and applies the policy"):
          headscale.succeed(stc("testsPass", "test"))
          headscale.wait_until_succeeds("headscale health")
          assert policy_has_tests() == "true", "new policy not served"
    '';
}
