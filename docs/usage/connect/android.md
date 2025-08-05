# Connecting an Android client

This documentation has the goal of showing how a user can use the official Android [Tailscale](https://tailscale.com) client with headscale.

## Installation

Install the official Tailscale Android client from the [Google Play Store](https://play.google.com/store/apps/details?id=com.tailscale.ipn) or [F-Droid](https://f-droid.org/packages/com.tailscale.ipn/).

## Connect via normal, interactive login

- Open the app and select the settings menu in the upper-right corner
- Tap on `Accounts`
- In the kebab menu icon (three dots) in the upper-right corner select `Use an alternate server`
- Enter your server URL (e.g `https://headscale.example.com`) and follow the instructions
- The client connects automatically as soon as the node registration is complete on headscale. Until then, nothing is
  visible in the server logs.

## Connect using a preauthkey

- Open the app and select the settings menu in the upper-right corner
- Tap on `Accounts`
- In the kebab menu icon (three dots) in the upper-right corner select `Use an alternate server`
- Enter your server URL (e.g `https://headscale.example.com`). If login prompts open, close it and continue
- Open the settings menu in the upper-right corner
- Tap on `Accounts`
- In the kebab menu icon (three dots) in the upper-right corner select `Use an auth key`
- Enter your [preauthkey generated from headscale](../getting-started.md#using-a-preauthkey)
- If needed, tap `Log in` on the main screen. You should now be connected to your headscale.
