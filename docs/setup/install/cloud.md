# Running headscale in a cloud

!!! warning "Community documentation"

    This page is not actively maintained by the headscale authors and is
    written by community members. It is _not_ verified by headscale developers.

    **It might be outdated and it might miss necessary steps**.

## Sealos

[Deploy headscale as service on Sealos.](https://icloudnative.io/en/posts/how-to-set-up-or-migrate-headscale/)

1. Click the following prebuilt template:

   [![](https://cdn.jsdelivr.net/gh/labring-actions/templates@main/Deploy-on-Sealos.svg)](https://cloud.sealos.io/?openapp=system-template%3FtemplateName%3Dheadscale)

2. Click "Deploy Application" on the template page to start deployment. Upon completion, two applications appear: headscale, and one of its [web interfaces](../../ref/integration/web-ui.md).
3. Once deployment concludes, click 'Details' on the headscale application page to navigate to the application's details.
4. Wait for the application's status to switch to running. For accessing the headscale server, the Public Address associated with port 8080 is the address of the headscale server. To access the headscale console, simply append `/admin/` to the headscale public URL.

!!! tip "Remote CLI"

    Headscale can be managed remotely via its remote CLI support. See our [Controlling headscale with remote
    CLI](../../ref/remote-cli.md) documentation for details.
