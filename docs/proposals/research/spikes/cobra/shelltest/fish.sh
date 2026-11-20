# usage: fish.sh <bindir without spaces> (holds headscale, comp.fish, pdir/)
for l in "headscale no" "headscale nodes list --columns " "headscale nodes list --columns id,na" "headscale nodes list -o " "headscale policy set " "headscale nodes " "headscale nodes routes ap" "headscale nodes list --sort -la"; do
  printf '%-40s -> ' "$l<Tab>"; (cd "$1/pdir" && fish -N -c "set -x PATH $1 \$PATH; source $1/comp.fish; complete -C '$l'" 2>&1 | tr '\n' ' '); echo
done
