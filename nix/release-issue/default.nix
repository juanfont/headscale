{ pkgs, ... }:
pkgs.writeShellApplication {
  name = "headscale-release-issue";

  runtimeInputs = with pkgs; [
    gh
    coreutils
    gnused
  ];

  text = ''
    export HEADSCALE_RELEASE_CHECKLIST=${./release-checklist.md}
  '' + builtins.readFile ./release-issue.sh;
}
