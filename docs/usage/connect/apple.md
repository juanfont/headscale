# Connecting an Apple client

This documentation has the goal of showing how a user can use the official iOS and macOS [Tailscale](https://tailscale.com) clients with headscale.

!!! info "Instructions on your headscale instance"

    An endpoint with information on how to connect your Apple device
    is also available at `/apple` on your running instance.

## iOS

### Installation

Install the official Tailscale iOS client from the [App Store](https://apps.apple.com/app/tailscale/id1470499037).

### Configuring the headscale URL

- Open Tailscale and make sure you are _not_ logged in to any account
- Tap the user profile icon in the top right corner of the Tailscale app to open the `Settings` menu
- If you are not signed into any other tailnets, tap the `Log in` menu item. Otherwise, tap the signed-in user
- Tap the `⋯` icon menu in the top right corner, then select `Use a custom coordination server`
- Enter the custom control server URL and tap `Log in`
- Enter your credentials and log in. Headscale should now be working on your iOS device.

## macOS

### Installation

Choose one of the available [Tailscale clients for macOS](https://tailscale.com/kb/1065/macos-variants) and install it.

### Configuring the headscale URL

#### Command line

Use Tailscale's login command to connect with your headscale instance (e.g `https://headscale.example.com`):

```
tailscale login --login-server <YOUR_HEADSCALE_URL>
```

#### GUI

- ALT + Click the Tailscale icon in the menu and hover over the Debug menu
- Under `Custom Login Server`, select `Add Account...`
- Enter the URL of your headscale instance (e.g `https://headscale.example.com`) and press `Add Account`
- Follow the login procedure in the browser

## tvOS

### Installation

Install the official Tailscale tvOS client from the [App Store](https://apps.apple.com/app/tailscale/id1470499037).

!!! danger

    **Don't** open the Tailscale App after installation!

### Configuring the headscale URL

- Open Settings (the Apple tvOS settings) > Apps > Tailscale
- Under `ALTERNATE COORDINATION SERVER URL`, select `URL`
- Enter the URL of your headscale instance (e.g `https://headscale.example.com`) and press `OK`
- Return to the tvOS Home screen
- Open Tailscale
- Click the button `Install VPN configuration` and confirm the appearing popup by clicking the `Allow` button
- Scan the QR code and follow the login procedure
