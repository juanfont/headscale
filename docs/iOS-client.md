# Connecting an iOS client

## Goal

This documentation has the goal of showing how a user can use the official iOS [Tailscale](https://tailscale.com) client with `headscale`.

## Installation

Install the official Tailscale iOS client from the [App Store](https://apps.apple.com/app/tailscale/id1470499037).

Ensure that the installed version is at least 1.38.1, as that is the first release to support alternate control servers.

## Configuring the headscale URL

!!! info "Apple devices"

    An endpoint with information on how to connect your Apple devices
    (currently macOS only) is available at `/apple` on your running instance.

Ensure that the tailscale app is logged out before proceeding.

After the first launch, Tailscale established its VPN profile with the address https://tailscale.com .
At first - you need to go to Settings —> VPN —> Tailscale (click info icon) —> Delete VPN.
Then go to Settings —> Tailscale (App settings) —> enter the address in the "Alternate Coordination Server URL" field (https://example.com).
Next, launch Tailscale, It will prompt you to install the VPN profile. Allow the installation by entering the password.
Connect.

> **Note**
>
> If the app was previously logged into tailscale, toggle on the _Reset Keychain_ switch.

Restart the app by closing it from the iOS app switcher, open the app and select the regular _Sign in_ option (non-SSO), and it should open up to the headscale authentication page.

Enter your credentials and log in. Headscale should now be working on your iOS device.
