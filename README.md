# 企业微信扫码登录 Amazon Quick · 临时用户方案

独立交付项目：企业微信负责员工认证，Keycloak 转换为 Quick Web 的 SAML 和 Quick Desktop 的 OIDC。管理员批准的映射补齐 Quick 身份，**不依赖企微 API 返回邮箱**；启用受控会话复用，避免同一有效浏览器会话内的两段登录重复扫码。

完成迁移和显式清理后，Keycloak **Users 为零**，之后扫码不再创建持久员工账号。映射、会话和日志仍有身份数据，并不是完全无状态的协议转发器。

```text
企业微信扫码验证 UserId
  → 管理员批准的 UserId → 用户名 / 邮箱 / Role pair / 稳定 sub
  → Keycloak 临时用户会话
  ├─ SAML → AWS 联合角色 → 原 Quick 用户
  └─ OIDC + PKCE → Quick Desktop
       同一有效会话可复用；强制认证、过期或不同浏览器仍需扫码
```

## 从哪里开始

| 当前情况 | 执行顺序 |
|---|---|
| 只有 Keycloak 26.6.4 + 社区 wecom 插件，其他未配置 | [首次部署图文](docs/扫码登录快速实施.md) → [临时用户迁移、会话复用和清理](docs/管理员映射临时用户实施.md) |
| 已有兼容的 Realm、每员工 IAM 角色、Quick 用户及已验证的企微绑定 | 直接执行 [临时用户迁移](docs/管理员映射临时用户实施.md)；不重复注册 Quick 用户 |
| 希望逐项理解控制台配置 | [完整手动配置图文](docs/完整手动配置图文说明.md)解释初始配置；最终临时用户切换仍按专用脚本完成 |

**首次部署是两阶段流程，不是从第一步就 Users 为零。** 初始化脚本先创建无本地密码的过渡员工账号与准确绑定、AWS 角色和经确认的 Quick 席位；再迁移为临时用户，完成验收后显式删除过渡账号。不要停在初始配置步骤，就宣称完成了本方案。

## 项目包含什么

- [方案与参数](docs/方案与参数.md)：系统职责、需要维护的值、用户和权限边界。
- [管理员映射实施](docs/管理员映射临时用户实施.md)：安装扩展、备份、迁移、一次扫码复用、Users 清理、校验和回滚。
- [权限与恢复](docs/首次部署权限与恢复.md)：AWS / Keycloak 权限及中断处理。
- [维护与验收](docs/项目维护.md)：构建、测试、打包和已知验证范围。
- `mapped-provider/`：自建扩展 1.1.0 源码。社区 wecom 插件保持不变。
- `scripts/migrate_mapped_*.py`、`scripts/retire_mapped_users.py`：迁移、受控会话和精确清理脚本。
- `new_customer.py`、`wecom_sso.py`、`store_secret.py`：初始配置和通用依赖；不是其他身份路线。

## 下载与使用

GitHub 中维护源码和 Markdown；[Releases](https://github.com/kasimxiao/quick-wecom-transient-sso/releases) 的 `quick-wecom-transient-sso-v1.0.0.zip` 包含离线 HTML、脚本、已脱敏截图和自建扩展 JAR。解压后先打开 `quick-wecom-transient-sso/README.html`。GitHub 自动生成的 `Source code.zip` 不是这个离线交付包。

只想安全查看初始资源和费用计划，在解压目录执行：

```bash
python3 new_customer.py plan --config new-customer.example.json
```

这是离线示例，不访问云服务。正式实施须替换全部示例参数，按手册确认目标和收费用户，不能把模板直接用于客户。

## 必须了解的边界

- 需要自建 mapper + 受控 Cookie 扩展；不是只安装社区插件就能完成。Keycloak `transient-users` 为实验功能，内部 SPI 升级必须重测。
- Quick 用户和 IAM 权限仍需创建/批准；本项目不会根据邮箱自动认领资产，不在扫码时自动增加收费席位。
- 当前迁移器只接受项目支持的每员工独立 IAM 角色及精确身份合同，不是任意现有 SSO 的自动迁移器。
- 固定初始清单最多 25 人；没有通讯录同步、随意增删员工或自动离职撤权功能。已有令牌、STS 和 Quick 会话需要各自撤销。
- 不新建 Keycloak 服务器、VPC、ECS、数据库、域名或 Quick 订阅；客户须自行批准费用及运维责任。
- 真实 Desktop 单次扫码由参考环境用户确认；清理后 Users=0 已线上回读，删除后的真实 Desktop 再验收尚未记录。不要将本地协议测试视为所有客户现场验收。

独立项目版本 **1.0.0**。继承自 [原实施项目](https://github.com/kasimxiao/quick-wecom-customer-migration)，不携带其客户配置、历史提交或过程文件。自有内容采用 [MIT](LICENSE)；参见 [安全要求](SECURITY.md)及[第三方声明](THIRD_PARTY_NOTICES.md)。
