# Phase B: the adapter spike

The test kit is ready: `spikes/kit` in this folder (module `spike/kit`). Read `spikes/kit/README.md`
first, then `spike-kit.md` for the choices behind it. `DECISIONS.md` now holds D1–D14; read it again.

Do this for your candidate:

1. Write one adapter in `spikes/<candidate>/` (its own module, `replace spike/kit => ../kit`).
   The adapter is the only code that imports the framework. Do not change the kit. If a case
   looks wrong or unfair to your candidate, keep it failing and say why in your notes: the same
   kit runs for all five, so a quiet fix would make the results useless.
1. Run the conformance suite the way the README says, with zsh and PowerShell on PATH
   (`nix shell nixpkgs#zsh nixpkgs#powershell -c nix develop -c …` from the Headscale worktree),
   and also with `-race -count=3`. Keep the Markdown result table at
   `spikes/<candidate>/RESULT.md`.
1. One check the kit does not do: drive completion through a real shell. Build a tiny binary
   from your adapter and the kit's tree, source the generated bash script in a non-interactive
   bash, set `COMP_WORDS`/`COMP_CWORD`/`COMP_LINE`/`COMP_POINT`, call the completion function and
   print `COMPREPLY` for a few lines (`headscale no<Tab>`, `headscale nodes list --columns <Tab>`,
   `headscale nodes list -o <Tab>`, `headscale policy set <Tab>`). Do the same in zsh and fish if you
   can do it without a terminal (fish: `complete -C 'headscale nodes '`); say so if you cannot.
1. Completion scripts: say where yours come from (the framework, a library, a copy of cobra's
   scripts, `tailscale.com/tempfork/spf13/cobra` from the module Headscale already requires, or
   written by you), under which licence, and what we would have to keep current.
1. Report these numbers: lines of adapter code (non-test), lines of it that work around the
   framework rather than use it (name each workaround), argv handled before the framework sees
   it (the README calls this out; declare all of it), modules added to go.sum, MUST passed out
   of the total, STRETCH passed, and what each OBSERVE case did. For `-ojson` (D11): does the
   framework accept it, and what does it cost to refuse it?
1. Add a "Phase B" part to your `deep-<candidate>.md`: the table, the numbers, what surprised
   you, what was ugly, and whether Phase B changed your Phase A verdict. Then say in one
   paragraph: if you had to maintain this adapter for five years, what would worry you.

Final message back: 12 lines at most.
