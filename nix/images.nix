# Nix-built + pinned container images for the integration tests.
#
# Built images (headscale, tailscale-HEAD, derper) replace
# Dockerfile.integration-ci / Dockerfile.tailscale-HEAD / Dockerfile.derper for
# the nix/flake-check path. Released tailscale versions + postgres are pinned
# pulls (nix/tailscale-versions.nix). Everything is loaded into the VM docker so
# the checks run the full version matrix offline; the Go test code is unchanged
# and consumes them via the same HEADSCALE_INTEGRATION_*_IMAGE env vars / repo
# tags the `hi` CI path already uses.
{ pkgs, buildGoModule, tailscaleSrc }:
let
  lib = pkgs.lib;

  # Single source of truth for the tailscale version matrix + pinned registry
  # images, shared with the Go suite (MustTestVersions reads the same file).
  # Regenerate with `update-integration-images`.
  versions = builtins.fromJSON (builtins.readFile ../integration/tailscale-versions.json);

  # amd64/arm64 follows the build system; the tailscale + postgres registry
  # images are multi-arch so the imageDigest (the index) is shared and we select
  # the per-arch nix hash. Run on whatever arch the runner is, no forced cross-build.
  dockerArch = if pkgs.stdenv.hostPlatform.isAarch64 then "arm64" else "amd64";

  # Same headscale build, but from the Go-only filtered source and a fixed
  # version (not the commit rev) so the image is content-addressed: identical
  # source → identical store path → shared-cache hit across commits.
  headscale = pkgs.headscale.overrideAttrs (_: {
    src = pkgs.headscale-go-src;
    version = "integration";
  });

  # alpine's `update-ca-certificates` has no drop-in nixpkgs equivalent. The
  # integration containers write the per-test headscale CA to
  # /usr/local/share/ca-certificates/user-N.crt and then call
  # update-ca-certificates so TLS to headscale is trusted (integration/tsic,
  # integration/hsic). This shim reproduces exactly that: append those certs
  # onto a writable bundle that Go reads via SSL_CERT_FILE.
  #
  # ponytail: minimal CA shim; swap for a real ca-certificates package only if a
  # test needs the full openssl rehash dance.
  caShim = pkgs.writeShellScriptBin "update-ca-certificates" ''
    set -eu
    bundle=/etc/ssl/certs/ca-certificates.crt
    mkdir -p /etc/ssl/certs
    if [ ! -s "$bundle" ]; then
      cp ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt "$bundle"
    fi
    for f in /usr/local/share/ca-certificates/*.crt; do
      [ -e "$f" ] || continue
      cat "$f" >> "$bundle"
    done
  '';

  # taildrive (TestGrantCapDrive) spawns its per-user fileserver by re-execing
  # tailscaled under `su` (tailscale drive/driveimpl/remote_impl.go): tailscaled
  # runs as root and sus to the share's user. With no `su` on PATH canSU() fails,
  # the fallback hits assertNotRoot() while root, the fileserver never starts,
  # and every share fails with "unable to determine address for share". The
  # released alpine images ship busybox su; expose just that applet here so it
  # does not shadow coreutils on the image PATH.
  busyboxSu = pkgs.runCommand "busybox-su" { } ''
    mkdir -p $out/bin
    ln -s ${pkgs.busybox}/bin/busybox $out/bin/su
  '';

  # Tailscale HEAD client + daemon + derper, built once from the pinned source.
  # Mirrors Dockerfile.tailscale-HEAD / Dockerfile.derper's `go install`.
  tailscaleHead = buildGoModule {
    pname = "tailscale-head";
    version = "head";
    src = tailscaleSrc;

    # Tailscale commits its own Go module vendorHash to flakehashes.json; reuse
    # it so `nix flake update tailscale-head` carries the matching hash and we
    # never hand-maintain it. (The hash tracks go.mod, not our subPackages.)
    vendorHash = (builtins.fromJSON (builtins.readFile "${tailscaleSrc}/flakehashes.json")).vendor.sri;

    subPackages = [ "cmd/tailscale" "cmd/tailscaled" "cmd/containerboot" "cmd/derper" ];

    # ts_debug_websockets so this one image also serves the websocket-DERP test
    # (no separate build); the code path is inert without TS_DEBUG_DERP_WS_CLIENT.
    tags = [ "ts_debug_websockets" ];

    env.CGO_ENABLED = "0";
    doCheck = false;
  };

  # Userland the integration suite shells out to inside the containers:
  # sh/sleep/cat (coreutils), find (findutils), ps/pidof (procps),
  # grep/sed/awk, bash. Missing any of these makes test Execute() calls fail.
  baseUserland = with pkgs; [
    bashInteractive
    coreutils
    findutils
    procps
    gnugrep
    gnused
    gawk
  ];

  # Shared image scaffolding. Go reads /etc/ssl/certs/ca-certificates.crt via
  # SSL_CERT_FILE (maintained by caShim at container start).
  commonEnv = [
    "PATH=/bin:/usr/bin:/usr/local/bin:/sbin"
    "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
  ];
  # /var/lib/tailscale must exist and be writable, else tailscaled's default
  # state path resolves empty and it exits with "--state is required"
  # (tailscale paths/paths_unix.go stateFileUnix). derper-certs holds the
  # manual cert dsic writes before starting derper.
  mkWritableDirs = ''
    mkdir -p etc/ssl/certs usr/local/share/ca-certificates usr/local/share/derper-certs etc/headscale tmp var/run var/lib/tailscale
  '';

  # Local login accounts the SSH integration tests map tailscale SSH sessions to.
  # Pre-created in both images at build time (head: seeded passwd below; released:
  # busybox adduser in withTestTools) so no container is mutated at startup.
  sshTestUsers = [ "ssh-it-user" "user1" "user2" ];
  passwdFile = pkgs.writeText "passwd" (''
    root:x:0:0:root:/root:/bin/sh
    nobody:x:65534:65534:nobody:/:/bin/sh
  '' + lib.concatStrings (lib.imap0
    (i: u: "${u}:x:${toString (1000 + i)}:${toString (1000 + i)}::/home/${u}:/bin/sh\n")
    sshTestUsers));
  groupFile = pkgs.writeText "group" (''
    root:x:0:
    nobody:x:65534:
  '' + lib.concatStrings (lib.imap0 (i: u: "${u}:x:${toString (1000 + i)}:\n") sshTestUsers));

  tailscaleImage = pkgs.dockerTools.buildLayeredImage {
    name = "tailscale-head";
    tag = "nix";
    contents = [
      tailscaleHead
      caShim
      pkgs.dockerTools.binSh # /bin/sh -> bash (tsic entrypoint is /bin/sh -c)
      pkgs.iproute2 # ip
      pkgs.iptables # iptables, ip6tables
      pkgs.curl
      pkgs.python3 # webserver tests
      pkgs.dnsutils # dig/nslookup (dns tests apk-add bind-tools)
      pkgs.openssh # ssh, for the SSH tests
      pkgs.getent # tailscale SSH server execs `getent passwd <user>`
      pkgs.hostname # SSH tests run `hostname` on the peer over the session
      pkgs.traceroute # HA/route tests assert path via traceroute (head-only)
      busyboxSu # taildrive sus to spawn its per-user fileserver (TestGrantCapDrive)
    ] ++ baseUserland;
    # buildLayeredImage puts every package's bin on /bin, which is on PATH, so
    # the suite resolves tailscale/tailscaled/derper/curl/ssh/... directly — no
    # symlinks needed. Just the writable state dirs and a passwd with the login
    # the SSH tests use (ssh-it-user, pre-created so no runtime adduser).
    extraCommands = ''
      ${mkWritableDirs}
      ${lib.concatMapStringsSep "\n" (u: "mkdir -p home/${u}") sshTestUsers}
      cp ${passwdFile} etc/passwd
      cp ${groupFile} etc/group
    '';
    config.Env = commonEnv;
  };

  headscaleImage = pkgs.dockerTools.buildLayeredImage {
    name = "headscale";
    tag = "nix";
    contents = [
      headscale
      caShim
      pkgs.dockerTools.binSh # hsic entrypoint is /bin/bash -c
      pkgs.iproute2 # ip
      pkgs.jq
      pkgs.sqlite
      pkgs.python3
      pkgs.curl
      pkgs.dnsutils # dig
    ] ++ baseUserland;
    extraCommands = ''
      ${mkWritableDirs}
      mkdir -p usr/local/bin
      ln -sf ${headscale}/bin/headscale usr/local/bin/headscale
    '';
    config.Env = commonEnv;
  };

  # The tools the suite used to `apk add` into the released alpine images at
  # runtime (curl/ssh/dig/python3/getent). A nixosTest has no network, so we bake
  # them in at build time instead — one buildEnv copied onto the image so they
  # land on /bin (already on the alpine PATH), no per-tool symlinks. Only /bin is
  # linked: overlaying /lib would shadow musl's loader and break alpine's
  # tailscaled. The binaries carry their own glibc closure via RPATH, so they run
  # on musl without it. Tests assert these are present rather than installing them.
  testTools = pkgs.buildEnv {
    name = "ts-test-tools";
    paths = with pkgs; [ curl openssh dnsutils python3 getent ];
    pathsToLink = [ "/bin" ];
  };

  # Pinned registry images, as docker-loadable tarballs that keep their
  # repo:tag so the suite finds them locally (its own pull fails offline, then
  # RunWithOptions uses the loaded image). The spec's sha256 is per-arch.
  pullImage = spec: pkgs.dockerTools.pullImage {
    imageName = spec.imageName;
    finalImageName = spec.imageName;
    finalImageTag = spec.finalImageTag;
    imageDigest = spec.imageDigest;
    os = "linux";
    arch = dockerArch;
    sha256 = spec.sha256.${dockerArch};
  };

  # Released tailscale images with the test tools layered on, keeping the exact
  # registry repo:tag the suite requests, and the SSH login pre-created at build
  # time (alpine's busybox adduser) so no container is mutated at startup —
  # matching the head image's baked ssh-it-user.
  withTestTools = spec: pkgs.dockerTools.buildImage {
    name = spec.imageName;
    tag = spec.finalImageTag;
    fromImage = pullImage spec;
    copyToRoot = testTools;
    runAsRoot = ''
      #!${pkgs.runtimeShell}
      export PATH=/usr/sbin:/usr/bin:/sbin:/bin
      ${lib.concatMapStringsSep "\n" (u: "grep -q '^${u}:' /etc/passwd || adduser -D -s /bin/sh ${u}") sshTestUsers}
    '';
  };

  tailscaleVersionImages = map withTestTools (builtins.attrValues versions.images);
  postgresImage = pullImage versions.postgres;
in
{
  inherit
    tailscaleImage
    headscaleImage
    postgresImage
    tailscaleVersionImages
    tailscaleHead
    caShim;
}
