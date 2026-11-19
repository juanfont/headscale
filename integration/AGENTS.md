# integration

Read `README.md` here before writing a test and `../cmd/hi/README.md` before
running one. Never guess `hi` flags.

- Every test function starts with `IntegrationSkip(t)`.
- External calls (`client.Status`, `headscale.ListNodes`, …) go inside
  `EventuallyWithT`; state-mutating commands (`tailscale set`) never do.
- Prefer `hscontrol/servertest/` when a test does not need Docker.
- A run writes ~100 MB of logs under `control_logs/{runID}/`; prune old runs.
