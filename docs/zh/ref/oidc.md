# 配置 Headscale 使用 OIDC 认证

为了通过集中式解决方案认证用户，需要启用 OIDC 集成。

已知限制：

- 不支持动态 ACL
- OIDC 组不能用于 ACL

---

## 基本配置

在 `config.yaml` 中，根据你的需求进行配置：

```yaml title="config.yaml"
oidc:
  # 在 OIDC 提供者健康且可用之前阻止启动
  only_start_if_oidc_is_available: true
  # 由 OIDC 提供者指定
  issuer: "https://your-oidc.issuer.com/path"
  # 由 OIDC 提供者指定/生成
  client_id: "your-oidc-client-id"
  client_secret: "your-oidc-client-secret"
  # 或者，使用 `client_secret_path` 从文件中读取密钥。
  # 它支持环境变量解析，便于与 systemd 的 `LoadCredential` 集成：
  #client_secret_path: "${CREDENTIALS_DIRECTORY}/oidc_client_secret"
  # 第三种选择是从环境变量中加载 OIDC 密钥
  # 设置 HEADSCALE_OIDC_CLIENT_SECRET 为所需的值

  # 自定义 OIDC 流程中的范围，默认为 "openid"、"profile" 和 "email"，并添加自定义查询参数
  scope: ["openid", "profile", "email", "custom"]
  # 可选：传递给浏览器登录请求的参数，用于调整 OIDC 提供者的行为
  extra_params:
    domain_hint: example.com

  # 可选：允许的主体域和/或用户列表。如果认证用户的域不在此列表中，认证请求将被拒绝。
  allowed_domains:
    - example.com
  # 可选。注意 Keycloak 中的组名前有 '/'。
  allowed_groups:
    - /headscale
  # 可选。
  allowed_users:
    - alice@example.com

  # 可选：PKCE（Proof Key for Code Exchange）配置
  # PKCE 通过防止授权代码拦截攻击，为 OAuth 2.0 授权代码流程增加了额外的安全层
  # 参见 https://datatracker.ietf.org/doc/html/rfc7636
  pkce:
    # 启用或禁用 PKCE 支持（默认：false）
    enabled: false
    # 使用的 PKCE 方法：
    # - plain: 使用纯代码验证器
    # - S256: 使用 SHA256 哈希代码验证器（默认，推荐）
    method: S256
```

---

## Azure AD 示例

为了将 Headscale 与 Azure Active Directory 集成，我们需要配置一个具有正确范围和重定向 URI 的应用注册。以下是使用 Terraform 的示例：

```hcl title="terraform.hcl"
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
    # 指向你的 Headscale 实例
    redirect_uris = ["https://headscale.example.com/oidc/callback"]

    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled = true
    }
  }

  group_membership_claims = ["SecurityGroup"]
  optional_claims {
    # 暴露组成员关系
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

在 Headscale 的 `config.yaml` 中配置：

```yaml title="config.yaml"
oidc:
  issuer: "https://login.microsoftonline.com/<tenant-UUID>/v2.0"
  client_id: "<client-id-from-terraform>"
  client_secret: "<client-secret-from-terraform>"

  # 可选：添加 "groups"
  scope: ["openid", "profile", "email"]
  extra_params:
    # 使用与 Azure AD 关联的域名
    domain_hint: example.com
    # 可选：强制 Azure AD 账户选择器
    prompt: select_account
```

---

## Google OAuth 示例

为了将 Headscale 与 Google 集成，你需要一个 [Google Cloud Console](https://console.cloud.google.com) 账户。

如果你需要认证来自你域名外的用户，Google OAuth 有一个[验证流程](https://support.google.com/cloud/answer/9110914?hl=en)。如果只需要认证你域名内的用户（例如 `@example.com`），则不需要通过验证流程。

如果你没有域名，或者需要添加域名外的用户，可以通过 Google Console 手动添加电子邮件。

### 步骤

1. 登录 [Google Console](https://console.cloud.google.com)，如果没有账户则创建一个。
2. 创建一个项目（如果还没有）。
3. 在左侧菜单中，转到 `APIs and services` -> `Credentials`。
4. 点击 `Create Credentials` -> `OAuth client ID`。
5. 在 `Application Type` 下选择 `Web Application`。
6. 在 `Name` 中输入任意名称。
7. 在 `Authorised redirect URIs` 中使用 `https://example.com/oidc/callback`，将 `example.com` 替换为你的 Headscale URL。
8. 点击表单底部的 `Save`。
9. 记下 `Client ID` 和 `Client secret`，你也可以下载以备参考。
10. 编辑 Headscale 配置文件，在 `oidc` 部分填写 `client_id` 和 `client_secret`：
    ```yaml title="config.yaml"
    oidc:
      issuer: "https://accounts.google.com"
      client_id: ""
      client_secret: ""
      scope: ["openid", "profile", "email"]
    ```

你还可以使用 `allowed_domains` 和 `allowed_users` 来限制可以认证的用户。