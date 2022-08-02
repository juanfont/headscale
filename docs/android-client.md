# Connecting an Android client

## Goal

This documentation has the goal of showing how a user can use the official Android [Tailscale](https://tailscale.com) client with `headscale`.

## Installation

Install the official Tailscale Android client from the [Google Play Store](https://play.google.com/store/apps/details?id=com.tailscale.ipn) or [F-Droid](https://f-droid.org/packages/com.tailscale.ipn/).

Ensure that the installed version is at least 1.30.0, as that is the first release to support custom URLs.

## Configuring the headscale URL

After opening the app, the kebab menu icon (three dots) on the top bar on the right must be repeatedly opened and closed until the _Change server_ option appears in the menu. This is where you can enter your headscale URL.

A screen recording of this process can be seen in the `tailscale-android` PR which implemented this functionality: <https://github.com/tailscale/tailscale-android/pull/55>

After saving and restarting the app, selecting the regular _Sign in_ option (non-SSO) should open up the headscale authentication page.
