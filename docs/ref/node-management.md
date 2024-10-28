# Node management

See https://tailscale.com/kb/1099/device-approval for more information.

## Setup

### 1. Change the configuration

1. Change the `config.yaml` to contain the desired records like so:

   ```yaml
   node_management:
     manual_approve_new_node: true
   ```

2. Restart your headscale instance.

### Warning
Enabling the `node_management.manual_approve_new_node: true` option will allow manual approval of nodes in both **cli mode** and **oidc mode**.

## Usage

### Pre-approve a node using preauthkeys

1. Create preauthkey with a pre-approve option

```bash
headscale preauthkeys create --user=<USER_NAME> --pre-approved
```

2. Register a node on the headscale using preauthkey (with the pre-approval option enabled)

```bash
headscale nodes register --user=<USER_NAME> --mkey=mkey:<MACHINE_KEY> --auth-key=<PREAUTHKEY_PRE_APPROVED>
```

### Node approval after registration without the option to pre-approve the authentication key

```bash
headscale nodes approve --identifier=<NODE_ID>
```