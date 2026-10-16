# 企业微信扫码登录 Amazon Quick

客户实施包 **v1.0.1**：企业微信负责扫码认证，Keycloak 转换为 SAML / OIDC，Quick 继续使用获批用户。迁移并清理后，Keycloak 不保存持久员工账号，同一有效浏览器会话可复用扫码。

## 从这里开始

| 客户当前情况 | 操作说明 |
|---|---|
| 只有 Keycloak 26.6.4 和社区 wecom 插件 | [首次部署图文](docs/扫码登录快速实施.md) → [临时用户配置与清理](docs/管理员映射临时用户实施.md) |
| 已有兼容的 Quick、IAM、Keycloak 及验证过的企微绑定 | [临时用户配置与清理](docs/管理员映射临时用户实施.md)，不重复建 Quick 用户 |
| 需要逐项手动配置 | [手动配置图文](docs/完整手动配置图文说明.md)；最终临时用户切换按专用脚本完成 |

## 目录里是什么

```text
README.md    从这里开始
docs/        客户操作手册、截图、安全与权限说明
config/      客户参数模板（全部使用示例值）
scripts/     部署、迁移、核验、清理及其必需依赖
provider/    已编译的 Keycloak 扩展、校验值、镜像安装文件
LICENSE      使用许可
```

客户只按手册执行脚本，无需理解内部模块：

- `scripts/new_customer.py`：首次创建 Realm、AWS 配置和经批准的 Quick 用户。
- `scripts/store_secret.py`：隐藏输入企微 Secret，保存到客户 SSM。
- `scripts/wecom_sso.py`：已有兼容环境的企微接入，也供其他脚本调用。
- `scripts/migrate_mapped_transient.py`：迁移临时用户；`scripts/migrate_mapped_sso.py`：启用受控会话复用。
- `scripts/retire_mapped_users.py`：批准后精确清理旧 Keycloak 员工。
- 其他 `scripts/*.py` 是上述命令的必需依赖，**不用单独执行，也不要删除**。

根目录不放开发源码、测试工程、构建工具或实施过程记录；扩展已编译，无需安装 Maven / Node.js。

## 下载后先做什么

[离线交付包](https://github.com/kasimxiao/quick-wecom-transient-sso/releases) 文件名为 `quick-wecom-transient-sso-v1.0.1.zip`，解压后打开包内 `quick-wecom-transient-sso/README.html`。源码下载也含运行脚本和 JAR，Markdown 手册可直接在 GitHub 阅读；离线包额外包含 HTML。

在项目根目录执行以下命令，只查看示例计划，不访问云资源：

```bash
python3 scripts/new_customer.py plan --config config/new-customer.example.json
```

正式实施需要 Python 3.10+、[Python 依赖](scripts/requirements.txt)、客户凭据及批准的服务器变更窗口。脚本不会新建 Keycloak 服务器或 Quick 订阅。参数怎么填写见[方案与参数](docs/方案与参数.md)，权限及失败恢复见[权限与恢复](docs/首次部署权限与恢复.md)。

## 实施边界

首次部署是**两阶段**：先创建过渡账号、AWS 配置和收费确认后的 Quick 用户，再迁移、实测、明确批准清理，最终才达到 **Keycloak Users=0**。Quick 用户和批准映射仍需保留，不是完全无身份数据。

本方案需要附带的自建扩展 1.1.0，社区企微插件不改动；Keycloak `transient-users` 是实验功能，升级必须重新验证。当前支持固定初始名单最多 25 人，不提供通讯录同步或自动离职撤权。映射、在线/离线会话和日志仍按客户安全策略管理。

测试通过不代替客户真实 Web / Desktop 扫码验收。尤其清理后需再次验证进入原 Quick 身份且 Users 保持为零。参见[安全说明](docs/安全说明.md)、[第三方声明](docs/第三方声明.md)和 [MIT 许可](LICENSE)。
