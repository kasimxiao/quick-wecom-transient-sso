# 企业微信扫码登录 Amazon Quick

客户实施包 **v1.1.0**：企业微信负责扫码认证，Keycloak 转换为 SAML / OIDC，Quick 继续使用获批用户。新客户从部署第一步开始，Keycloak 就不保存持久员工账号，同一有效浏览器会话可复用扫码。

## 从这里开始

| 客户当前情况 | 操作说明 |
|---|---|
| 只有 Keycloak 26.6.4 和社区 wecom 插件 | [首次部署图文](docs/扫码登录快速实施.md)，先安装附带扩展，再直接初始化临时模式 |
| 已有兼容的 Quick、IAM、Keycloak 及验证过的企微绑定 | [临时用户配置与清理](docs/管理员映射临时用户实施.md)，不重复建 Quick 用户 |
| 需要逐项手动配置 | [手动配置图文](docs/完整手动配置图文说明.md)，也是从零配置临时模式，不建员工或 Link account |

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

- `scripts/new_customer.py`：直接创建临时模式 Realm、批准映射、AWS 配置和经批准的 Quick 用户；包含启停、只读核验。
- `scripts/store_secret.py`：隐藏输入企微 Secret，保存到客户 SSM。
- `scripts/wecom_sso.py`：仅供旧持久账号环境的可选接入，也提供共享底层 API；新客户不执行。
- `scripts/migrate_mapped_transient.py`：仅旧持久账号迁移；`scripts/migrate_mapped_sso.py`：启用受控会话复用。
- `scripts/retire_mapped_users.py`：仅旧环境获批准后的精确清理，新客户不需要。
- 其他 `scripts/*.py` 是上述命令的必需依赖，**不用单独执行，也不要删除**。

根目录不放开发源码、测试工程、构建工具或实施过程记录；扩展已编译，无需安装 Maven / Node.js。

仓库只保留客户实施需要的内容。验证日志、真实环境截图、备份、运行状态和旧交付包不纳入 Git；手册引用的示例截图保留。

## 下载后先做什么

需要最新脚本修复时，使用 GitHub **main 分支 → Code → Download ZIP**，解压后从 `README.md` 开始；源码包含运行脚本和 JAR，Markdown 图文手册可直接在 GitHub 阅读。

固定版本离线交付包 `quick-wecom-transient-sso-v1.1.0.zip` 额外包含 HTML，解压后打开包内 `quick-wecom-transient-sso/README.html`。**推送 main 不会自动更新已发布的离线包**；不要把旧包解压覆盖最新脚本。

在项目根目录执行以下命令，只查看示例计划，不访问云资源：

```bash
python3 scripts/new_customer.py plan --config config/new-customer.example.json
```

正式实施需要 Python 3.10+、[Python 依赖](scripts/requirements.txt)、客户凭据及批准的服务器变更窗口。脚本不会新建 Keycloak 服务器或 Quick 订阅。参数怎么填写见[方案与参数](docs/方案与参数.md)，权限及失败恢复见[权限与恢复](docs/首次部署权限与恢复.md)。

## 实施边界

首次部署直接达到 **Keycloak Users=0**，没有过渡账号、手工绑定或删除员工步骤。企微成员认证后只产生临时身份；Quick 用户、批准映射和会话仍需保留，不是完全无身份数据。旧账号环境的迁移/清理是独立可选路径，不属于新客户步骤。

本方案需要附带的自建扩展 1.1.0，社区企微插件不改动；Keycloak `transient-users` 是实验功能，升级必须重新验证。当前支持固定初始名单最多 25 人，不提供通讯录同步或自动离职撤权。映射、在线/离线会话和日志仍按客户安全策略管理。

测试通过不代替客户真实 Web / Desktop 扫码验收。首次扫码、退出重登和 Desktop 登录后均需确认进入正确 Quick 身份且 Users 保持为零。参见[安全说明](docs/安全说明.md)、[第三方声明](docs/第三方声明.md)和 [MIT 许可](LICENSE)。
