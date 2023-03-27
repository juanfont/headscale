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

Go to iOS settings, scroll down past game center and tv provider to the tailscale app and select it. The headscale URL can be entered into the _"ALTERNATE COORDINATION SERVER URL"_ box.

> **Note**
>
> If the app was previously logged into tailscale, toggle on the _Reset Keychain_ switch.

Restart the app by closing it from the iOS app switcher, open the app and select the regular _Sign in_ option (non-SSO), and it should open up to the headscale authentication page.

Enter your credentials and log in. Headscale should now be working on your iOS device.
