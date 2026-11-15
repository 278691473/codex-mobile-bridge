# 智谱中继适配分支

本仓库是 https://github.com/try2love/codex-mobile-bridge 的 fork，智谱版源码在 `zcode-relay` 分支：
https://github.com/278691473/codex-mobile-bridge/tree/zcode-relay

当前合并上游正式版 **v2.2.1**（`1004e5aeb6ee38a75ab18b4bad1720a38553aada`）。原版 `web/` 和 `mobile/shared/` 资源保持上游内容；智谱适配集中在 Android 原生连接模块及 Python 网络模块。链路仍由本机 Codex Desktop 执行。协议、认证和使用限制见 [智谱中继说明](docs/zcode-relay.md)。

## 安装与更新身份

- 普通 Android 智谱版使用 `io.github.try2love.codexbridge.zcode`，名称“Codex Bridge 智谱”，与上游版及之前的本地预览包并存。旧版连接和草稿不会自动迁入；保留旧 App，不卸载、不清数据。
- 智谱版用独立的固定签名。相同包名、相同签名和递增 versionCode 才能保留智谱版数据覆盖升级；不能用上游签名 APK 覆盖。
- `mobile/zcode-fork.json` 只保存非秘密的应用标识、名称和修订号。版本取上游 `package.json`，例如上游 2.2.1 + 修订 1 生成 `2.2.1-preview.101`；versionCode 为上游构建号 × 100 + 修订号，首包 6001。preview 编号从 101 开始，避开现有上游预览标签。
- 手机检查更新固定指向本 fork 的 GitHub Releases。电脑协助更新还校验仓库身份；旧电脑端返回官方更新源时会拒绝，不能误装上游包。
- 签名密钥、密码、智谱 JWT、网关登录和运行数据全部留在仓库外。升级重用原密钥，构建器不会临时生成替代密钥。应私下备份密钥及密码；没有它们不能为已安装智谱版签发可覆盖升级的包。

## 跟进上游

`upstream` 指向原项目，`origin` 指向本 fork。先在没有未提交更改的 `zcode-relay` 分支执行：

```text
git fetch upstream main --tags
git log --oneline HEAD..upstream/main
git merge --no-ff <已核对的上游正式版标签>
```

上游功能通过真实 Git 合并进入，不重写聊天界面。处理冲突时保留上游功能和智谱连接特例，重点检查 MainActivity 生命周期、多信道绑定、公开资源白名单、Cookie/CSRF 及更新仓库。不能直接用 GitHub 的丢弃本地提交或强推覆盖适配分支。

同一上游版本再次发布时递增 `revision`；跨上游版本发布前也核对新 versionCode 大于已发智谱包。合并完成并通过相关回归后，才构建、签名和发布；源码合并不代表 APK 已自动发布或手机已安装。

```text
python -B scripts/test-backend.py --source-only -p test_zcode_relay.py
python -B scripts/test-backend.py --source-only -p test_mobile_updates.py
python -B scripts/check-boundaries.py
node --test mobile/tests/*.test.cjs
python -B scripts/test-mobile-releases.py
python -B scripts/test-mobile-downloads.py
python -B scripts/test-zcode-connection.py
python -B scripts/test-zcode-release-channel.py
python -B scripts/test-zcode-capability-headers.py
python -B scripts/test-zcode-account.py
python -B scripts/build-mobile-android.py --zcode-fork --keystore <私有固定签名文件>
```

构建需要 JDK 17、Android SDK/Build-Tools 35 和 `.tmp/mobile-tools` 中经发布 SHA-1 校验的 ZXing 3.5.3、Java-WebSocket 1.5.7、SLF4J API/NOP 2.0.16。更新通道 JVM 测试另需 Android 兼容的 `com.vaadin.external.google:android-json:0.0.20131108.vaadin1` 测试 jar 与其发布 SHA-1。签名密码通过 `CMB_ANDROID_STORE_PASSWORD` 环境变量传入，不放命令行或源码。

发布资产沿用 `Codex-Mobile-Bridge-<版本>-Android.apk` 命名，与本 fork 的 `v<版本>` 标签一致。发布前核对源码提交、包名、版本、证书和 SHA-256；发布后重新下载核验。每次合并是否通过、APK 是否已发布、手机是否实测，分别记录。

`ZCode fork regression` 工作流在适配分支推送、PR 和手动运行时执行相关回归；它不保存签名密钥、不发布 APK。上游整套桌面发布工作流仅在上游仓库执行，防止 fork 标签调用原作者签名流程。

## 当前范围

本轮交付普通 Android 智谱版。可选 Firebase 推送构建和 iOS 不作为本轮安装产物；不发布冒充上游签名的桌面安装包。手机 OAuth、蜂窝网络与功能仍以真实手机验收为准。
