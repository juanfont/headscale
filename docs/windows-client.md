# Connecting a Windows client

## Goal

This documentation has the goal of showing how a user can use the official Windows [Tailscale](https://tailscale.com) client with `headscale`.

## Installation

Download the [Official Windows Client](https://tailscale.com/download/windows) and install it.

When the installation has finished, close the tailscale application in the windows tray. (Richt click > Exit)

## Login to Headscale server

Open Command Prompt or Powershell and type in the following:

```
tailscale up --accept-routes --login-server https://<your-headscale-server>
```

Follow the instructions shown in your opened browser.

## Troubleshooting

If you are seeing repeated messages like:

```
[GIN] 2022/02/10 - 16:39:34 | 200 |    1.105306ms |       127.0.0.1 | POST     "/machine/redacted"
```

in your `headscale` output, turn on `DEBUG` logging and look for:

```
2022-02-11T00:59:29Z DBG Machine registration has expired. Sending a authurl to register machine=redacted
```

This typically means that the registry keys above was not set appropriately.

To reset and try again, it is important to do the following:

1. Ensure the registry keys from the previous guide is correctly set.
2. Shut down the Tailscale service (or the client running in the tray)
3. Delete Tailscale Application data folder, located at `C:\Users\<USERNAME>\AppData\Local\Tailscale` and try to connect again.
4. Ensure the Windows node is deleted from headscale (to ensure fresh setup)
5. Start Tailscale on the windows machine and retry the login.
