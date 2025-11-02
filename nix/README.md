# Headscale NixOS Module

This directory contains the NixOS module for Headscale, providing a declarative way to configure and run Headscale on NixOS systems.

## Features

- **Freeform Settings**: Use any Headscale configuration option through the `settings` attribute
- **Type-safe Configuration**: Common options have explicit types and validation
- **Automatic Conflict Resolution**: Disables the upstream NixOS module to prevent conflicts
- **Comprehensive Hardening**: Systemd service with security best practices
- **Backward Compatibility**: Migration paths from deprecated options

## Quick Start

### Using the Flake

Add Headscale to your flake inputs:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    headscale.url = "github:juanfont/headscale";
  };

  outputs = { self, nixpkgs, headscale, ... }: {
    nixosConfigurations.yourhost = nixpkgs.lib.nixosSystem {
      modules = [
        headscale.nixosModules.default
        {
          services.headscale = {
            enable = true;
            settings = {
              server_url = "https://headscale.example.com";
              dns.base_domain = "tailnet.example.com";
            };
          };
        }
      ];
    };
  };
}
```

### Basic Configuration

```nix
{
  services.headscale = {
    enable = true;
    address = "0.0.0.0";
    port = 8080;

    settings = {
      server_url = "https://headscale.example.com";

      dns = {
        magic_dns = true;
        base_domain = "tailnet.example.com";
      };
    };
  };
}
```

## Configuration Options

### Explicitly Typed Options

The module provides type-safe options for common configurations:

- **`services.headscale.enable`**: Enable the Headscale service
- **`services.headscale.package`**: The Headscale package to use
- **`services.headscale.user`** / **`group`**: User and group for the service
- **`services.headscale.address`**: Listening address (default: `127.0.0.1`)
- **`services.headscale.port`**: Listening port (default: `8080`)

### Freeform Settings

All Headscale configuration options can be set through `services.headscale.settings`:

```nix
services.headscale.settings = {
  # Server configuration
  server_url = "https://headscale.example.com";

  # IP allocation
  prefixes = {
    v4 = "100.64.0.0/10";
    v6 = "fd7a:115c:a1e0::/48";
    allocation = "sequential";  # or "random"
  };

  # DNS with MagicDNS
  dns = {
    magic_dns = true;
    base_domain = "tailnet.example.com";
    nameservers.global = [ "1.1.1.1" "8.8.8.8" ];
    search_domains = [ "internal.example.com" ];
  };

  # DERP relay configuration
  derp = {
    urls = [ "https://controlplane.tailscale.com/derpmap/default" ];
    auto_update_enabled = true;
    update_frequency = "24h";
  };

  # Database (SQLite recommended)
  database = {
    type = "sqlite";
    sqlite = {
      path = "/var/lib/headscale/db.sqlite";
      write_ahead_log = true;
    };
  };

  # Logging
  log = {
    level = "info";  # debug, info, warn, error
    format = "text"; # text or json
  };

  # ACL policy
  policy = {
    mode = "file";  # or "database"
    path = "/var/lib/headscale/policy.hujson";
  };
};
```

### OIDC Authentication

```nix
services.headscale.settings.oidc = {
  issuer = "https://accounts.google.com";
  client_id = "your-client-id.apps.googleusercontent.com";
  client_secret_path = "/run/secrets/oidc-client-secret";
  scope = [ "openid" "profile" "email" ];
  allowed_domains = [ "example.com" ];
  allowed_users = [ "admin@example.com" ];

  pkce = {
    enabled = true;
    method = "S256";
  };
};
```

### TLS Configuration

#### Let's Encrypt

```nix
services.headscale.settings = {
  tls_letsencrypt_hostname = "headscale.example.com";
  tls_letsencrypt_challenge_type = "HTTP-01";  # or "TLS-ALPN-01"
  tls_letsencrypt_listen = ":http";
};

# Open port 80 for HTTP-01 challenge
networking.firewall.allowedTCPPorts = [ 80 ];
```

#### Custom Certificates

```nix
services.headscale.settings = {
  tls_cert_path = "/path/to/cert.pem";
  tls_key_path = "/path/to/key.pem";
};
```

#### Nginx Reverse Proxy

```nix
services.nginx = {
  enable = true;
  virtualHosts."headscale.example.com" = {
    enableACME = true;
    forceSSL = true;
    locations."/" = {
      proxyPass = "http://127.0.0.1:8080";
      proxyWebsockets = true;
    };
  };
};

services.headscale = {
  enable = true;
  address = "127.0.0.1";  # Only listen locally
  settings.server_url = "https://headscale.example.com";
};
```

### Running Your Own DERP Server

```nix
services.headscale.settings.derp = {
  server = {
    enabled = true;
    region_id = 999;
    stun_listen_addr = "0.0.0.0:3478";
  };
  urls = [ ];  # Don't use external DERP servers
};

networking.firewall.allowedUDPPorts = [ 3478 ];
```

## File Locations

- **Configuration**: Generated at `/nix/store/.../headscale.yaml`
- **CLI Configuration**: `/etc/headscale/config.yaml` (for headscale CLI commands)
- **Data Directory**: `/var/lib/headscale/`
  - SQLite database: `db.sqlite`
  - Noise private key: `noise_private.key`
  - DERP server key: `derp_server_private.key`
- **Runtime Directory**: `/run/headscale/`
  - Unix socket: `headscale.sock`

## Usage

After enabling the service:

```bash
# Create a user
sudo headscale users create myuser

# Create a pre-authentication key
sudo headscale preauthkeys --user myuser create --reusable --expiration 24h

# List nodes
sudo headscale nodes list

# Check service status
systemctl status headscale
```

## Testing

The module includes a NixOS test that validates:
- Service startup and configuration
- User and pre-authentication key creation
- Tailscale client connectivity
- Peer-to-peer communication
- MagicDNS functionality

Run the test:

```bash
nix build .#checks.x86_64-linux.headscale
# or
nix flake check
```

## Differences from Upstream NixOS Module

This module:
- **Automatically disables the upstream module** via `disabledModules` to prevent conflicts
- Uses the latest Headscale package from this repository's flake
- Provides the same configuration interface for easy migration
- Can be updated independently of the NixOS release cycle

## Migration from Upstream Module

The configuration is compatible with the upstream NixOS module. Simply:

1. Add the Headscale flake to your inputs
2. Import `headscale.nixosModules.default`
3. Keep your existing `services.headscale` configuration

The module will automatically disable the upstream module and use this one instead.

## Upstreaming

When upstreaming changes to nixpkgs:

1. Copy `nix/module.nix` to `nixos/modules/services/networking/headscale.nix`
2. Copy `nix/tests/headscale.nix` to `nixos/tests/headscale.nix`
3. Remove the `disabledModules` line (not needed in nixpkgs)
4. Update the package reference if needed
5. Test with `nixos/release.nix`

## Example Configurations

See [`example-configuration.nix`](./example-configuration.nix) for a comprehensive example with all major features demonstrated.

## Security

The systemd service includes extensive hardening:
- Restricted filesystem access
- Capability bounding
- Syscall filtering
- Namespace isolation
- Private /tmp and /dev

Port binding (<1024) automatically adds `CAP_NET_BIND_SERVICE` capability.

## Troubleshooting

### Module Conflict

If you see an error about duplicate definitions of `services.headscale`, ensure you haven't manually imported the upstream module. This module automatically disables it.

### Permission Issues

Users need to be in the `headscale` group to use the CLI:

```nix
users.users.myuser.extraGroups = [ "headscale" ];
```

### Database Issues

For SQLite, ensure WAL mode is enabled for better concurrency:

```nix
services.headscale.settings.database.sqlite.write_ahead_log = true;
```

## Development

To modify the module:

1. Edit `nix/module.nix`
2. Test with `nix flake check`
3. Build the test: `nix build .#checks.<system>.headscale`
4. Use in a VM: `nixos-rebuild build-vm` with the module imported

## Support

For issues specific to this module, please open an issue in the Headscale repository.

For general Headscale questions, see the main [documentation](https://headscale.net/).
