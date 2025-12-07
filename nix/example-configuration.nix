# Example NixOS configuration using the headscale module
#
# This file demonstrates how to use the headscale NixOS module from this flake.
# To use in your own configuration, add this to your flake.nix inputs:
#
#   inputs.headscale.url = "github:juanfont/headscale";
#
# Then import the module:
#
#   imports = [ inputs.headscale.nixosModules.default ];
#

{ config, pkgs, ... }:

{
  # Import the headscale module
  # In a real configuration, this would come from the flake input
  # imports = [ inputs.headscale.nixosModules.default ];

  services.headscale = {
    enable = true;

    # Optional: Use a specific package (defaults to pkgs.headscale)
    # package = pkgs.headscale;

    # Listen on all interfaces (default is 127.0.0.1)
    address = "0.0.0.0";
    port = 8080;

    settings = {
      # The URL clients will connect to
      server_url = "https://headscale.example.com";

      # IP prefixes for the tailnet
      # These use the freeform settings - you can set any headscale config option
      prefixes = {
        v4 = "100.64.0.0/10";
        v6 = "fd7a:115c:a1e0::/48";
        allocation = "sequential";
      };

      # DNS configuration with MagicDNS
      dns = {
        magic_dns = true;
        base_domain = "tailnet.example.com";

        # Whether to override client's local DNS settings (default: true)
        # When true, nameservers.global must be set
        override_local_dns = true;

        nameservers = {
          global = [ "1.1.1.1" "8.8.8.8" ];
        };
      };

      # DERP (relay) configuration
      derp = {
        # Use default Tailscale DERP servers
        urls = [ "https://controlplane.tailscale.com/derpmap/default" ];
        auto_update_enabled = true;
        update_frequency = "24h";

        # Optional: Run your own DERP server
        # server = {
        #   enabled = true;
        #   region_id = 999;
        #   stun_listen_addr = "0.0.0.0:3478";
        # };
      };

      # Database configuration (SQLite is recommended)
      database = {
        type = "sqlite";
        sqlite = {
          path = "/var/lib/headscale/db.sqlite";
          write_ahead_log = true;
        };

        # PostgreSQL example (not recommended for new deployments)
        # type = "postgres";
        # postgres = {
        #   host = "localhost";
        #   port = 5432;
        #   name = "headscale";
        #   user = "headscale";
        #   password_file = "/run/secrets/headscale-db-password";
        # };
      };

      # Logging configuration
      log = {
        level = "info";
        format = "text";
      };

      # Optional: OIDC authentication
      # oidc = {
      #   issuer = "https://accounts.google.com";
      #   client_id = "your-client-id";
      #   client_secret_path = "/run/secrets/oidc-client-secret";
      #   scope = [ "openid" "profile" "email" ];
      #   allowed_domains = [ "example.com" ];
      # };

      # Optional: Let's Encrypt TLS certificates
      # tls_letsencrypt_hostname = "headscale.example.com";
      # tls_letsencrypt_challenge_type = "HTTP-01";

      # Optional: Provide your own TLS certificates
      # tls_cert_path = "/path/to/cert.pem";
      # tls_key_path = "/path/to/key.pem";

      # ACL policy configuration
      policy = {
        mode = "file";
        path = "/var/lib/headscale/policy.hujson";
      };

      # You can add ANY headscale configuration option here thanks to freeform settings
      # For example, experimental features or settings not explicitly defined above:
      # experimental_feature = true;
      # custom_setting = "value";
    };
  };

  # Optional: Open firewall ports
  networking.firewall = {
    allowedTCPPorts = [ 8080 ];
    # If running a DERP server:
    # allowedUDPPorts = [ 3478 ];
  };

  # Optional: Use with nginx reverse proxy for TLS termination
  # services.nginx = {
  #   enable = true;
  #   virtualHosts."headscale.example.com" = {
  #     enableACME = true;
  #     forceSSL = true;
  #     locations."/" = {
  #       proxyPass = "http://127.0.0.1:8080";
  #       proxyWebsockets = true;
  #     };
  #   };
  # };
}
