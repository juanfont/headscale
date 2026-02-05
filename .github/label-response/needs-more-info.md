Thank you for taking the time to report this issue.

To help us investigate and resolve this, we need more information. Please provide the following:

> [!TIP]
> Most issues turn out to be configuration errors rather than bugs. We encourage you to discuss your problem in our [Discord community](https://discord.gg/c84AZQhmpx) **before** opening an issue. The community can often help identify misconfigurations quickly, saving everyone time.

## Required Information

### Environment Details

- **Headscale version**: (run `headscale version`)
- **Tailscale client version**: (run `tailscale version`)
- **Operating System**: (e.g., Ubuntu 24.04, macOS 14, Windows 11)
- **Deployment method**: (binary, Docker, Kubernetes, etc.)
- **Reverse proxy**: (if applicable: nginx, Traefik, Caddy, etc. - include configuration)

### Debug Information

Please follow our [Debugging and Troubleshooting Guide](https://headscale.net/stable/ref/debug/) and provide:

1. **Client netmap dump** (from affected Tailscale client):

   ```bash
   tailscale debug netmap > netmap.json
   ```

2. **Client status dump** (from affected Tailscale client):

   ```bash
   tailscale status --json > status.json
   ```

3. **Tailscale client logs** (if experiencing client issues):

   ```bash
   tailscale debug daemon-logs
   ```

   > [!IMPORTANT]
   > We need logs from **multiple nodes** to understand the full picture:
   >
   > - The node(s) initiating connections
   > - The node(s) being connected to
   >
   > Without logs from both sides, we cannot diagnose connectivity issues.

4. **Headscale server logs** with `log.level: trace` enabled

5. **Headscale configuration** (with sensitive values redacted - see rules below)

6. **ACL/Policy configuration** (if using ACLs)

7. **Proxy/Docker configuration** (if applicable - nginx.conf, docker-compose.yml, Traefik config, etc.)

## Formatting Requirements

- **Attach long files** - Do not paste large logs or configurations inline. Use GitHub file attachments or GitHub Gists.
- **Use proper Markdown** - Format code blocks, logs, and configurations with appropriate syntax highlighting.
- **Structure your response** - Use the headings above to organize your information clearly.

## Redaction Rules

> [!CAUTION]
> **Replace, do not remove.** Removing information makes debugging impossible.

When redacting sensitive information:

- ✅ **Replace consistently** - If you change `alice@company.com` to `user1@example.com`, use `user1@example.com` everywhere (logs, config, policy, etc.)
- ✅ **Use meaningful placeholders** - `user1@example.com`, `bob@example.com`, `my-secret-key` are acceptable
- ❌ **Never remove information** - Gaps in data prevent us from correlating events across logs
- ❌ **Never redact IP addresses** - We need the actual IPs to trace network paths and identify issues

**If redaction rules are not followed, we will be unable to debug the issue and will have to close it.**

---

**Note:** This issue will be automatically closed in 3 days if no additional information is provided. Once you reply with the requested information, the `needs-more-info` label will be removed automatically.

If you need help gathering this information, please visit our [Discord community](https://discord.gg/c84AZQhmpx).
