# Connecting an Android client

## Goal

This documentation has the goal of showing how a user can use the official Android [Tailscale](https://tailscale.com) client with `headscale`.

## Installation

### The recent Tailscale v1.34 release has broken the ability to change the control server URL in the Android Client.

The feature was introduced at v1.30.0, and broke with the release of v1.33.299. At the moment the both the Play Store and F-Droid carry a broken version. However with F-Droid, you can scroll to the bottom of the page, and choose to install [Version 1.33.97-t81fd25913](https://f-droid.org/repo/com.tailscale.ipn_135.apk)

## Configuring the headscale URL

After opening the app, the kebab menu icon (three dots) on the top bar on the right must be repeatedly opened and closed until the _Change server_ option appears in the menu. This is where you can enter your headscale URL.

A screen recording of this process can be seen in the `tailscale-android` PR which implemented this functionality: <https://github.com/tailscale/tailscale-android/pull/55>

After saving and restarting the app, selecting the regular _Sign in_ option (non-SSO) should open up the headscale authentication page.
