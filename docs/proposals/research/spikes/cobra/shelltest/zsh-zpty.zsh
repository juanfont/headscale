zmodload zsh/zpty
zpty -b z /nix/store/n6rxzys5jnb65vgvrbkiag195g2yz12v-zsh-5.9.1/bin/zsh -f -i
zpty -w z 'PS1="> "; cd /tmp/claude-21000/-home-kradalby-worktrees-headscale-cli-restructure-proposal/b7270764-e671-4458-ad8d-b750f4986e0e/scratchpad/cobrab/pdir; export PATH=/tmp/claude-21000/-home-kradalby-worktrees-headscale-cli-restructure-proposal/b7270764-e671-4458-ad8d-b750f4986e0e/scratchpad/cobrab:$PATH; autoload -Uz compinit; compinit -u; source /tmp/claude-21000/-home-kradalby-worktrees-headscale-cli-restructure-proposal/b7270764-e671-4458-ad8d-b750f4986e0e/scratchpad/cobrab/comp.zsh; compdef _headscale headscale; bindkey -e; zstyle ":completion:*" list-prompt ""'
sleep 1; zpty -r -t z junk
t() {
  zpty -w -n z "$1"$'\t'
  sleep 1.2
  local out=""; zpty -r -t z out
  zpty -w -n z $'\x03'; sleep 0.3; zpty -r -t z junk
  print -r -- "== [$1<Tab>]"; print -r -- "${out}" | tr -d '\r' | cat -v | sed 's/\^\[\[[0-9;?]*[a-zA-Z]//g; s/\^\[\[J//g' | grep -v '^\s*$' | tail -4
}
t 'headscale nodes list --columns id,na'
t 'headscale policy set po'
t 'headscale nodes list --columns +ho'
zpty -d z
