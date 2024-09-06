# Using a Custom template

## Goal

The purpose of this documentation is to show the user how-to use custom templates for some pages.

## Prepare

Create a separate directory for your templates on the Headscale server.
You can use any directory that Headscale has access to.

```shell
mkdir -p /var/lib/headscale/templates
```

Set the `user_template_dir_path` parameter in your Headscale config file

```yaml
user_template_dir_path: "/var/lib/headscale/templates"
```

Upload standard templates `hscontrol/html/*` from the Headscale repository to your templates directory.
You can upload all templates or just one, for all templates that, are not in your directory, the default templates will be used.

**Caution:** the file names must be identical to the files from standard templates.

