# Per-test integration check: a NixOS VM that boots docker, loads the nix-built
# + pinned images (full tailscale version matrix), and runs the prebuilt
# integration test binary filtered to a single test. Hermetic equivalent of one
# `go run ./cmd/hi run <TestName>` job. `postgres = true` produces the postgres
# variant (HEADSCALE_INTEGRATION_POSTGRES=1) for the postgres subset.
#
# The suite runs *inside* a container named headscale-test-suite-<runID> with
# the docker socket mounted (docker-out-of-docker): scenario.go attaches that
# container to each test network, and IntegrationSkip gates on /.dockerenv. We
# reuse the headscale image as the runner base and bind-mount the host nix store
# so the test binary's closure resolves.
{ name
, testFilter ? name
, pkgs
, headscaleImage
, tailscaleImage
, postgresImage
, tailscaleVersionImages
, testBin
, src
, postgres ? false
}:
let
  lib = pkgs.lib;

  # The test function name, dropping any "/subtest" filter on a split check, so
  # the skip-guard below matches a whole-function skip without tripping on a
  # legitimately-skipped subtest.
  testFunc = builtins.head (lib.splitString "/" testFilter);

  # >=6 chars and DNS-safe: tsic/hsic derive container hostnames from the last
  # 6 chars of the run ID (runID[len-6:]), which panics on shorter ids.
  runID = "nixcheck";
  runnerName = "headscale-test-suite-${runID}";

  # Images this check must have locally before the suite runs. Every test may
  # fan out over the full tailscale version matrix (MustTestVersions); the head
  # image doubles as the DERP server; the postgres variant adds postgres.
  images =
    [ headscaleImage tailscaleImage ]
    ++ tailscaleVersionImages
    ++ lib.optional postgres postgresImage;

  # Loading ~8 images dominates wall time; do it in parallel (they share layers,
  # so docker dedups) and fail if any load fails.
  loadImages = pkgs.writeShellScript "load-integration-images" ''
    set -u
    pids=""
    ${lib.concatMapStringsSep "\n" (img: ''docker load -i ${img} & pids="$pids $!"'') images}
    rc=0
    for p in $pids; do wait "$p" || rc=1; done
    exit "$rc"
  '';

  pgEnv = lib.optionalString postgres
    "-e HEADSCALE_INTEGRATION_POSTGRES=1 -e HEADSCALE_INTEGRATION_POSTGRES_IMAGE=postgres:16 ";
in
{
  name = "integration-${name}${lib.optionalString postgres "-pg"}";

  nodes.machine = { ... }: {
    virtualisation.docker.enable = true;

    # Match the integration CI: Docker 29's default containerd snapshotter +
    # overlayfs regresses image load/exec for these images; the classic
    # overlay2 graph driver is the known-good path.
    virtualisation.docker.daemon.settings = {
      storage-driver = "overlay2";
      features.containerd-snapshotter = false;
    };

    # tailscaled needs /dev/net/tun for its --tun=tsdev device.
    boot.kernelModules = [ "tun" ];

    # The VM's dhcpcd otherwise manages docker's bridges/veths: as containers
    # and the cable-pull tests churn interfaces it deletes their routes and
    # races libnetwork's gateway setup, surfacing as
    # "API error (500): updating gateway endpoint: failed to set gateway:
    # network is unreachable" on reconnect (TestHASubnetRouterFailover*Disconnect
    # /CablePull) and intermittent container-startup flakes. Keep it off them.
    networking.dhcpcd.denyInterfaces = [ "veth*" "br-*" "docker*" ];

    # Trim the guest toward a tiny profile: this VM only needs to boot, run
    # docker, and exec one test binary. Measured boot is 18.7s (1.7s kernel +
    # 3.9s initrd + 13.1s userspace); the userspace critical chain is
    # dhcpcd (6.1s) -> network-online.target -> docker.service (+3.5s), i.e. the
    # remaining cost is functional (docker waits for the network), not fat to
    # trim. documentation + timesyncd off shave the cheap, avoidable part.
    #
    # microvm.nix was evaluated against this and rejected: it still needs a full
    # docker daemon + nested KVM, and boot is only ~10-15% of the 2-3 min
    # image-load + test runtime, so a new flake input can't pay itself back. The
    # one real lever left, dropping docker's network-online wait (~6s), sits
    # right next to the dhcpcd interface races handled below and isn't worth
    # destabilising the matrix for.
    documentation.enable = false;
    services.timesyncd.enable = false;

    # Each check batches many tests, run one at a time (-test.parallel=1) inside
    # this VM, so only a handful of VMs exist at once and a shared builder can't
    # be overcommitted regardless of its build concurrency. 6 GB covers the
    # heaviest single test (the version matrix's ~12 containers, or k3s); running
    # sequentially means we don't need per-test-fanout headroom.
    virtualisation.memorySize = 6144;
    virtualisation.cores = 2;
    virtualisation.diskSize = 12288;
  };

  testScript = ''
    start_all()
    machine.wait_for_unit("docker.service")

    # Load all matrix images in parallel (store paths visible inside the VM).
    machine.succeed("${loadImages}", timeout=600)

    # Writable copy of just the integration package (the suite writes
    # control_logs/ under CWD and reads testdata relative to it). Only this
    # subtree is needed at runtime — the repo-root build context is only used
    # for image builds, which we bypass with prebuilt images.
    machine.succeed("mkdir -p /tmp/hs && cp -r ${src}/integration /tmp/hs/integration && chmod -R u+w /tmp/hs")

    # hsic/tsic save artifacts (and tsic.Status writes <host>_status.json) under
    # /tmp/control; cmd/hi mounts this dir. Without it every Status() errors on
    # the write and the suite never observes NeedsLogin.
    machine.succeed("mkdir -p /tmp/control")

    # Run the suite inside a container (docker-out-of-docker), mirroring cmd/hi:
    #  - name matches scenario.go's testSuiteName so it can join test networks
    #  - docker socket mounted so sibling containers spawn on this daemon
    #  - host nix store mounted so the test binary's closure resolves
    out = machine.succeed(
        "docker run --rm --name ${runnerName} "
        "-v /var/run/docker.sock:/var/run/docker.sock "
        "-v /nix/store:/nix/store:ro "
        "-v /tmp/hs:/tmp/hs -w /tmp/hs/integration "
        "-v /tmp/control:/tmp/control "
        "-e HEADSCALE_INTEGRATION_HEADSCALE_IMAGE=headscale:nix "
        "-e HEADSCALE_INTEGRATION_TAILSCALE_IMAGE=tailscale-head:nix "
        "-e HEADSCALE_INTEGRATION_TAILSCALE_WEBSOCKET_IMAGE=tailscale-head:nix "
        "-e HEADSCALE_INTEGRATION_DERPER_IMAGE=tailscale-head:nix "
        "${pgEnv}"
        "-e HEADSCALE_INTEGRATION_RUN_ID=${runID} "
        "-e CI=1 "
        # The nested-docker VM converges slower than a host docker daemon; widen
        # the ScaledTimeout budgets (subnet-route convergence, HA cycles) past 2x.
        "-e HEADSCALE_INTEGRATION_TIMEOUT_SCALE=4 "
        "-e SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt "
        "headscale:nix "
        "${testBin}/bin/integration.test -test.run '^${testFilter}$' -test.v -test.parallel=1 -test.timeout=4h",
        timeout=15000,
    )
    print(out)

    # A skipped or unmatched test still exits 0; guard against a false green.
    assert "no tests to run" not in out, "filter ${testFilter} matched nothing"
    assert "--- SKIP: ${testFunc} " not in out, "test ${testFunc} was skipped (not in container?)"
  '';
}
