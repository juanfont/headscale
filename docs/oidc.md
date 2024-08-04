# Configuring Headscale to use OIDC authentication

In order to authenticate users through a centralized solution one must enable the OIDC integration.

Known limitations:

- No dynamic ACL support
- OIDC groups cannot be used in ACLs

## Basic configuration

In your `config.yaml`, customize this to your liking:

```yaml
oidc:
  only_start_if_oidc_is_available: true
  issuer: "https://your-oidc.issuer.com/path"
  client_id: "your-oidc-client-id"
  client_secret: "your-oidc-client-secret"
  # Alternatively, set `client_secret_path` to read the secret from the file.
  # It resolves environment variables, making integration to systemd's
  # `LoadCredential` straightforward:
  # client_secret_path: "${CREDENTIALS_DIRECTORY}/oidc_client_secret"
  # client_secret and client_secret_path are mutually exclusive.
  #
  # Customize the scopes used in the OIDC flow, defaults to "openid", "profile" and "email" and add custom query
  # parameters to the Authorize Endpoint request. Scopes default to "openid", "profile" and "email".
  scope: ["openid", "profile", "email", "custom"]
    extra_params:
      domain_hint: example.com

  expiry:
    #
    # Use the expiry from the token received from OpenID when the user logged
    # in, this will typically lead to frequent need to reauthenticate and should
    # only been enabled if you know what you are doing.
    # Note: enabling this will cause `oidc.expiry.fixed_time` to be ignored.
    from_token: false
    #
    # The amount of time from a node is authenticated with OpenID until it
    # expires and needs to reauthenticate.
    # Setting the value to "0" will mean no expiry.
    fixed_time: 180d

  # # List allowed principal domains and/or users. If an authenticated user's domain is not in this list, the
  # # authentication request will be rejected.
  allowed:
    domains:
      - example.com
    groups:
      - admins
    users:
      - admin@example.com

  #  Map claims from the OIDC token to the user object
  claims_map:
    name: name
    username: email
   # username: preferred_username
    email: email
    groups: groups
    

  #  some random configuration
  misc:
    # if the username is set to `email` then `strip_email_domain` is valid
    # If `strip_email_domain` is set to `true`, the domain part of the username email address will be removed.
    # This will transform `first-name.last-name@example.com` to the user `first-name.last-name`
    # If `strip_email_domain` is set to `false` the domain part will NOT be removed resulting to the following
    # user: `first-name.last-name.example.com`
    strip_email_domain: true
    # If `flatten_groups` is set to `true`, the groups claim will be flattened to a single level.
    # this is used for keycloak where the groups are nested. the groups format from keycloak is `group1/subgroup1/subgroup2`
    flatten_groups: true
    # If `flatten_splitter` is set to a string, the groups claim will be split by the string and flattened to a single level.
    flatten_splitter: "/"


```

## Azure AD example

In order to integrate Headscale with Azure Active Directory, we'll need to provision an App Registration with the correct scopes and redirect URI. Here with Terraform:

```hcl
resource "azuread_application" "headscale" {
  display_name = "Headscale"

  sign_in_audience = "AzureADMyOrg"
  fallback_public_client_enabled = false

  required_resource_access {
    // Microsoft Graph
    resource_app_id = "00000003-0000-0000-c000-000000000000"

    resource_access {
      // scope: profile
      id   = "14dad69e-099b-42c9-810b-d002981feec1"
      type = "Scope"
    }
    resource_access {
      // scope: openid
      id   = "37f7f235-527c-4136-accd-4a02d197296e"
      type = "Scope"
    }
    resource_access {
      // scope: email
      id   = "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0"
      type = "Scope"
    }
  }
  web {
    # Points at your running Headscale instance
    redirect_uris = ["https://headscale.example.com/oidc/callback"]

    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled = true
    }
  }

  group_membership_claims = ["SecurityGroup"]
  optional_claims {
    # Expose group memberships
    id_token {
      name = "groups"
    }
  }
}

resource "azuread_application_password" "headscale-application-secret" {
  display_name          = "Headscale Server"
  application_object_id = azuread_application.headscale.object_id
}

resource "azuread_service_principal" "headscale" {
  application_id = azuread_application.headscale.application_id
}

resource "azuread_service_principal_password" "headscale" {
  service_principal_id = azuread_service_principal.headscale.id
  end_date_relative    = "44640h"
}

output "headscale_client_id" {
  value = azuread_application.headscale.application_id
}

output "headscale_client_secret" {
  value = azuread_application_password.headscale-application-secret.value
}
```

And in your Headscale `config.yaml`:

```yaml
oidc:
  issuer: "https://login.microsoftonline.com/<tenant-UUID>/v2.0"
  client_id: "<client-id-from-terraform>"
  client_secret: "<client-secret-from-terraform>"

  # Optional: add "groups"
  scope: ["openid", "profile", "email"]
  extra_params:
    # Use your own domain, associated with Azure AD
    domain_hint: example.com
    # Optional: Force the Azure AD account picker
    prompt: select_account
```

## Google OAuth Example

In order to integrate Headscale with Google, you'll need to have a [Google Cloud Console](https://console.cloud.google.com) account.

Google OAuth has a [verification process](https://support.google.com/cloud/answer/9110914?hl=en) if you need to have users authenticate who are outside of your domain. If you only need to authenticate users from your domain name (ie `@example.com`), you don't need to go through the verification process.

However if you don't have a domain, or need to add users outside of your domain, you can manually add emails via Google Console.

### Steps

1. Go to [Google Console](https://console.cloud.google.com) and login or create an account if you don't have one.
2. Create a project (if you don't already have one).
3. On the left hand menu, go to `APIs and services` -> `Credentials`
4. Click `Create Credentials` -> `OAuth client ID`
5. Under `Application Type`, choose `Web Application`
6. For `Name`, enter whatever you like
7. Under `Authorised redirect URIs`, use `https://example.com/oidc/callback`, replacing example.com with your Headscale URL.
8. Click `Save` at the bottom of the form
9. Take note of the `Client ID` and `Client secret`, you can also download it for reference if you need it.
10. Edit your headscale config, under `oidc`, filling in your `client_id` and `client_secret`:

```yaml
oidc:
  issuer: "https://accounts.google.com"
  client_id: ""
  client_secret: ""
  scope: ["openid", "profile", "email"]
```

You can also use `allowed.domains` and `allowed.users` to restrict the users who can authenticate.
