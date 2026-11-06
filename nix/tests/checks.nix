# A policy headscale rejects must fail the build, and a config or policy it
# rejects must fail a switch before headscale restarts.
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
  # group:missing is never defined.
  undefinedGroup = writePolicy "undefined-group.json" {
    acls = [
      {
        action = "accept";
        src = [ "group:missing" ];
        dst = [ "*:*" ];
      }
    ];
  };
  # Stand-in users and nodes decide these tests.
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

  # The build-time check a system with this store-path policy must pass.
  policyBuild =
    policy:
    lib.findFirst (d: d.name == "headscale-policy-check") (throw "no headscale-policy-check")
      (pkgs.nixos {
        imports = [ self.nixosModules.headscale ];
        services.headscale = {
          enable = true;
          settings.policy = {
            mode = "file";
            path = policy;
          };
        };
      }).config.system.checks;
  buildFailures = {
    undefinedGroup = pkgs.testers.testBuildFailure (policyBuild undefinedGroup);
    testsFail = pkgs.testers.testBuildFailure (policyBuild testsFail);
  };

  # Outside the store, so only the switch can check it.
  mutablePolicy = "/var/lib/headscale/policy.json";
  # Readable only through the group headscale.
  oldGroupPolicy = "/var/lib/hsold/policy.json";
  # Readable only through hshand, a group made by hand.
  handGroupPolicy = "/var/lib/hshand/policy.json";
  # Readable only through the group hsread.
  groupPolicy = "/var/lib/hsread/policy.json";
  badServerUrl = lib.mkForce "ftp://headscale";
in
{
  name = "headscale-checks";
  meta.maintainers = with lib.maintainers; [ kradalby ];

  nodes.headscale = {
    imports = [
      self.nixosModules.testkit
      # Specialisations that set more than services.headscale.
      {
        specialisation = lib.mapAttrs (_: c: { configuration = c; }) {
          unitEnv.systemd.services.headscale.environment.HEADSCALE_SERVER_URL = "ftp://headscale";
          newGroup = {
            services.headscale.group = "hs3";
            users.groups.hs3 = { };
          };
          # hsnew is created by this switch, so the check leaves it out.
          supplementaryGroup = {
            services.headscale.settings.policy.path = lib.mkForce groupPolicy;
            users.groups.hsnew = { };
            systemd.services.headscale.serviceConfig.SupplementaryGroups = [
              "hsread"
              "hsnew"
            ];
          };
          extraGroup = {
            services.headscale.settings.policy.path = lib.mkForce groupPolicy;
            users.users.headscale.extraGroups = [ "hsread" ];
          };
          memberGroup = {
            services.headscale.settings.policy.path = lib.mkForce groupPolicy;
            users.groups.hsread.members = [ "headscale" ];
          };
        };
      }
    ];
    services.headscale.settings.policy = {
      mode = "file";
      path = valid;
    };
    users.groups.hsread = { };
    specialisation = lib.mapAttrs (_: c: { configuration.services.headscale = c; }) {
      badConfig.settings.server_url = badServerUrl;
      mutable.settings.policy.path = lib.mkForce mutablePolicy;
      policyOnly = {
        settings.policy.path = lib.mkForce mutablePolicy;
        check.config = false;
      };
      unchecked = {
        settings.server_url = badServerUrl;
        check = {
          config = false;
          policy = false;
        };
      };
      newUser = {
        user = "hs2";
        group = "hs2";
      };
      testsPass.settings.policy.path = lib.mkForce testsPass;
      # After activation the user is no longer in its old primary group headscale.
      newPrimaryGroup = {
        group = "hsread";
        settings.policy.path = lib.mkForce oldGroupPolicy;
      };
      # Activation keeps a membership of a group NixOS does not declare.
      handGroup.settings.policy.path = lib.mkForce handGroupPolicy;
      credential.settings.dns = {
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
  };

  testScript =
    { nodes, ... }:
    let
      toplevel = nodes.headscale.system.build.toplevel;
      jq = lib.getExe pkgs.jq;
    in
    ''
      from datetime import timedelta

      def stc(spec, action):
          return f"${toplevel}/specialisation/{spec}/bin/switch-to-configuration {action} 2>&1"

      def main_pid():
          return headscale.succeed("systemctl show -P MainPID headscale.service").strip()

      def served_policy():
          return headscale.succeed("headscale policy get | ${jq} -S .")

      def put_policy(src, mode="644"):
          headscale.succeed(f"install -m {mode} {src} ${mutablePolicy}")

      def assert_rejected(spec, why):
          out = headscale.fail(stc(spec, "test"))
          assert "Pre-switch check 'headscale' failed" in out, out
          assert why in out, out
          assert "NIXOS_NO_CHECK=1" in out, "no skip hint:\n" + out
          return out

      with subtest("a bad store-path policy fails the build"):
          for path, why in [
              ("${buildFailures.undefinedGroup}", 'group not found: "group:missing"'),
              ("${buildFailures.testsFail}", "test(s) failed"),
          ]:
              build_log = open(f"{path}/testBuildFailure.log").read()
              assert why in build_log, build_log

      headscale.wait_for_unit("headscale.service")
      headscale.wait_until_succeeds("headscale health", timeout=timedelta(seconds=60))

      with subtest("rejected switches leave the running headscale alone"):
          pid = main_pid()
          before = served_policy()
          assert_rejected("badConfig", "server_url is missing a scheme")
          assert_rejected("unitEnv", "server_url is missing a scheme")
          put_policy("${undefinedGroup}")
          assert_rejected("mutable", 'group not found: "group:missing"')
          put_policy("${testsFail}")
          assert_rejected("mutable", "test(s) failed")
          out = assert_rejected("policyOnly", "test(s) failed")
          assert "checking the new configuration" not in out, out
          # Checked as the headscale user, who cannot read this file.
          put_policy("${valid}", "600")
          assert_rejected("mutable", "permission denied")
          assert main_pid() == pid, "headscale was restarted"
          assert served_policy() == before, "old policy no longer served"
          headscale.succeed("headscale health")

      with subtest("a passing switch check"):
          put_policy("${valid}")
          # The caller's environment does not reach the check.
          headscale.succeed("HEADSCALE_SERVER_URL=ftp://headscale " + stc("mutable", "check"))

      with subtest("the check has the unit's groups"):
          headscale.succeed("install -d -m 750 -g hsread ${builtins.dirOf groupPolicy}")
          headscale.succeed("install -m 640 -g hsread ${valid} ${groupPolicy}")
          headscale.succeed(stc("supplementaryGroup", "check"))
          headscale.succeed(stc("extraGroup", "check"))
          headscale.succeed(stc("memberGroup", "check"))
          headscale.succeed("groupadd hshand && usermod -aG hshand headscale")
          headscale.succeed("install -d -m 750 -g hshand ${builtins.dirOf handGroupPolicy}")
          headscale.succeed("install -m 640 -g hshand ${valid} ${handGroupPolicy}")
          headscale.succeed(stc("handGroup", "check"))
          headscale.succeed("install -d -m 750 -g headscale ${builtins.dirOf oldGroupPolicy}")
          headscale.succeed("install -m 640 -g headscale ${valid} ${oldGroupPolicy}")
          assert_rejected("newPrimaryGroup", "permission denied")

      with subtest("a file: secret is skipped, not read"):
          out = headscale.succeed(stc("credential", "check"))
          assert "secret, not read" in out, out

      with subtest("skips"):
          out = headscale.succeed("${toplevel}/bin/switch-to-configuration check 2>&1")
          assert "unit unchanged" in out, out
          out = headscale.succeed(stc("newUser", "check"))
          assert "does not exist yet" in out, out
          out = headscale.succeed(stc("newGroup", "check"))
          assert 'group hs3 does not exist yet' in out, out

      with subtest("escape hatches"):
          headscale.succeed(stc("unchecked", "check"))
          headscale.succeed("NIXOS_NO_CHECK=1 " + stc("badConfig", "check"))

      with subtest("a valid switch goes through and applies the policy"):
          pid = main_pid()
          headscale.succeed(stc("testsPass", "test"))
          headscale.wait_until_succeeds("headscale health", timeout=timedelta(seconds=60))
          assert main_pid() != pid, "headscale was not restarted"
          want = headscale.succeed("${jq} -S . ${testsPass}")
          assert served_policy() == want, "new policy not served"
    '';
}
