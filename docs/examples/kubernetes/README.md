# Deploying headscale on Kubernetes

This directory contains [Kustomize](https://kustomize.io) templates that deploy
headscale in various configurations.

These templates currently support Rancher k3s. Other clusters may require
adaptation, especially around volume claims and ingress.

Commands below assume this directory is your current working directory.

# Generate secrets and site configuration

Run `./init.bash` to generate keys, passwords, and site configuration files.

Edit `base/site/public.env`, changing `public-hostname` to the public DNS name
that will be used for your headscale deployment.

Set `public-proto` to "https" if you're planning to use TLS & Let's Encrypt.

Configure DERP servers by editing `base/site/derp.yaml` if needed.

# Add the image to the registry

You'll somehow need to get `headscale:latest` into your cluster image registry.

An easy way to do this with k3s:

- Reconfigure k3s to use docker instead of containerd (`k3s server --docker`)
- `docker build -t headscale:latest ..` from here

# Create the namespace

If it doesn't already exist, `kubectl create ns headscale`.

# Deploy headscale

## sqlite

`kubectl -n headscale apply -k ./sqlite`

## postgres

`kubectl -n headscale apply -k ./postgres`

# TLS & Let's Encrypt

Test a staging certificate with your configured DNS name and Let's Encrypt.

`kubectl -n headscale apply -k ./staging-tls`

Replace with a production certificate.

`kubectl -n headscale apply -k ./production-tls`

## Static / custom TLS certificates

Only Let's Encrypt is supported. If you need other TLS settings, modify or patch the ingress.

# Administration

Use the wrapper script to remotely operate headscale to perform administrative
tasks like creating namespaces, authkeys, etc.

```
[c@nix-slate:~/Projects/headscale/k8s]$ ./headscale.bash

headscale is an open source implementation of the Tailscale control server

https://gitlab.com/juanfont/headscale

Usage:
  headscale [command]

Available Commands:
  help        Help about any command
  namespace   Manage the namespaces of headscale
  node        Manage the nodes of headscale
  preauthkey  Handle the preauthkeys in headscale
  routes      Manage the routes of headscale
  serve       Launches the headscale server
  version     Print the version.

Flags:
  -h, --help            help for headscale
  -o, --output string   Output format. Empty for human-readable, 'json' or 'json-line'

Use "headscale [command] --help" for more information about a command.

```

# TODO / Ideas

- Interpolate `email:` option to the ClusterIssuer from site configuration.
  This probably needs to be done with a transformer, kustomize vars don't seem to work.
- Add kustomize examples for cloud-native ingress, load balancer
- CockroachDB for the backend
- DERP server deployment
- Tor hidden service
