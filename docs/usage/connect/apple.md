# Connecting an Apple client

This documentation has the goal of showing how a user can use the official iOS and macOS [Tailscale](https://tailscale.com) clients with headscale.

!!! info "Instructions on your headscale instance"

    An endpoint with information on how to connect your Apple device
    is also available at `/apple` on your running instance.

## iOS

### Installation

Install the official Tailscale iOS client from the [App Store](https://apps.apple.com/app/tailscale/id1470499037).

### Configuring the headscale URL

- Open the Tailscale app
- Click the account icon in the top-right corner and select “Log in…”.
- Tap the top-right options menu button and select “Use custom coordination server”.
- Enter your instance url

<details>
  <summary>Older app versions</summary>

- Open Settings on the iOS device
- Scroll down to the `third party apps` section, under `Game Center` or `TV Provider`
- Find Tailscale and select it
  - If the iOS device was previously logged into Tailscale, switch the `Reset Keychain` toggle to `on`
- Enter the URL of your headscale instance (e.g `https://headscale.example.com`) under `Alternate Coordination Server URL`
- Restart the app by closing it from the iOS app switcher, open the app and select the regular sign in option
  _(non-SSO)_. It should open up to the headscale authentication page.
- Enter your credentials and log in. Headscale should now be working on your iOS device.

</details>

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

- Option + Click the Tailscale icon in the menu and hover over the Debug menu
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
