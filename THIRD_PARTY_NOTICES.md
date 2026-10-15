# 第三方组件与声明

本项目不是 AWS、Keycloak 或腾讯的官方产品。Amazon Quick、AWS、Keycloak、企业微信及相关商标和控制台界面归各自权利人所有。文档中的界面截图仅用于操作说明；不授予第三方商标或服务使用权。客户仍需遵守各产品条款、许可证和收费政策。

## 社区 wecom 插件

源码：[hqqw2h-lgtm/keycloak-services-social-wecom](https://github.com/hqqw2h-lgtm/keycloak-services-social-wecom)。构建材料固定到提交 `a777528752f8b75edd1cf769297ef8c52d72678c`，不附带或修改 Java 源码/JAR；可选构建会下载并编译上游。上游 LICENSE 已按该提交核对，全文如下：

```text
MIT License

Copyright (c) 2026 keycloak-services-social-wecom contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 运行与文档依赖

`mapped-provider/` 是本项目独立开发的 MIT 身份映射及受控会话扩展，不是修改后的社区 wecom 插件。Git 只包含源码；正式离线 Release 通过 `--with-provider` 加入自有构建 JAR，不打包 Keycloak/JUnit 依赖。Keycloak SPI 为 provided 依赖，由客户现有 Keycloak 提供。升级前需审核新增扩展和兼容性。

Keycloak、Boto3/Botocore 使用 Apache-2.0；Marked 使用 MIT。其源码、二进制或依赖安装目录不随本包打包。安装或再分发时保留各上游许可证及 NOTICE，镜像内传递依赖也需客户完成供应链审核。具体版本见 `requirements.txt`、`package-lock.json` 和 `community-provider/` 固定构建材料。

本项目自有代码与文档以 [MIT License](LICENSE) 发布。第三方组件、控制台截图、商标及服务仍适用各自权利与条款，不因本项目采用 MIT 而改变。
