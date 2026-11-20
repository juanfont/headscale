| `headscale auth keys create alice --tags tag:p` | bash | `tag:prod` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` |
| | zsh | `tag:prod` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` |
| | fish | `tag:prod` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` |
| | pwsh | `tag:prod` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` | `tag:prod␣` |
| `headscale auth keys create alice --tags tag:ci,tag:p` | bash | `~tag:ci,tag:tag:ci\,tag:prod` | `tag:ci,tag:prod␣` | `tag:ci,tag:prod␣` | `tag:ci,tag:prod␣` | `~tag:ci,tag:tag:ci\,tag:prod` | `~tag:ci,tag:tag:ci\,tag:prod` |
| | zsh | `tag:ci,tag:prod` | `tag:ci,tag:prod␣` | `tag:ci,tag:prod␣` | `tag:ci,tag:prod␣` | `tag:ci,tag:prod` | `tag:ci,tag:prod` |
| | fish | `tag:ci,tag:prod` | `tag:ci,tag:prod␣` | `tag:ci,tag:prod␣` | `tag:ci,tag:prod␣` | `tag:ci,tag:prod` | `tag:ci,tag:prod` |
| | pwsh | `tag:ci`,tag:prod`|`tag:ci`,tag:prod␣` | `tag:ci`,tag:prod␣`|`tag:ci`,tag:prod␣` | `tag:ci`,tag:prod`|`tag:ci`,tag:prod` |
