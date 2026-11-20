# A value that holds `=`, completed in the `--x=` form

`eqp list --filter=<Tab>` with the candidates `name=web` and `name=db` (`main.go`, on the final
prototype; scripts from cobra v1.10.2). Run like `spikes/final/headscale/shell/run.sh`, with
`lines.txt` here. Shells: bash 5.3p9 + bash-completion 2.17, zsh 5.9.1, fish 4.9.3, pwsh 7.6.5.

| Line + Tab                 | bash (pty)                  | zsh (pty)                | fish (`complete -C`)                    | pwsh (`TabExpansion2`) |
| -------------------------- | --------------------------- | ------------------------ | --------------------------------------- | ---------------------- |
| `eqp list --filter=name=w` | `--filter=name=web␣`        | nothing (bell)           | `--filter=name=name=web`                | `--filter=name=web␣`   |
| `eqp list --filter=na`     | lists both, inserts `name=` | inserts `--filter=name=` | `--filter=name=db`, `--filter=name=web` | both                   |

`__complete list --filter=name=w` answers `name=web` and `:4`. zsh and fish put back the text that
matches `-.*=` (greedy, to the last `=`) in front of each candidate; bash and PowerShell cut at the
first `=`.
