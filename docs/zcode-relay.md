# 原版 Android App 经智谱中继

本实现已在独立 fork 的 `zcode-relay` 分支合并上游 v2.2.1。Android 安装身份、固定签名、更新源和后续同步步骤见 [FORK.md](../FORK.md)。此前 2.0.3 包已被本轮智谱 fork 包替代，保留旧 App 和数据。

保留本项目原版 HTML、聊天、项目分组、模型、历史、问询和审批页面，只新增传输连接层。链路为 Android App 本地 loopback 网关 → `zcode.z.ai` WSS → 本机 `bridge.features.network.zcode_relay` → `127.0.0.1:8787` → 已有 Codex Desktop owner。Android 无需公网 IP，不使用 Cloudflare。

## 电脑

先按本项目原流程运行网关，确保 `http://127.0.0.1:8787` 正常。另安装 `requirements-zcode.txt`，然后运行：

```text
python -B -m bridge.features.network.zcode_relay --config <仓库外私有 desktop-config.json>
```

配置复用手工模式账号 JWT，至少包含 `credentials_mode=manual`、`manual_jwt`、固定 `device_mid`；可填 `device_name`、`app_version=3.18.2`。端点固定 `https://zcode.z.ai`。JWT 等同账号凭据，只保存在当前用户私有目录，不能写进仓库、日志、安装包或命令行参数。重启复用同一 mid；每次连接重新签发短期 device token。KICKED 会停止，避免抢占。

正常日志包括 `ZCR_READY`、`ZCR_STATE waiting_terminal`、`ZCR_PAIR_URL`。该 URL 只有公开设备身份，供原版 App 的智谱入口读取；云端 ZCode 页面不是本方案的聊天入口。

隔离测试可使用 `--mid <独立临时值> --delete-on-exit`；正式设备不要使用删除参数。现有 AK-NEW 常驻方式、日志与回滚位置记录在部署工作区的验收文档。

## 安卓

1. 使用本项目包含智谱连接模块的 APK。首页点击“智谱中继连接”，粘贴本机本轮打印的完整配对链接。
2. 未保存智谱登录时，先选“Z.ai（国际）”或“BigModel（国内）”，再在系统浏览器登录与电脑绑定设备时相同的账号，返回 App。两种账号均经 `zcode.z.ai` 国内中继；账号类型不决定中继区域。App 核对账号下同一 sid/mid 后才保存登录；JWT 通过 Android Keystore AES/GCM 加密保存。已有有效登录时直接复用；选错账号可用“退出智谱并移除连接”后重新扫码选择。
3. 进入原版 Bridge 登录页，使用原网关账号密码登录。这层认证和 CSRF 均保留，智谱账号登录不替代网关登录。
4. 在原版页面选择“按项目”、已有会话、模型及推理强度；问询和审批按原页面回应。

当前只保存一个智谱电脑连接。重启沿用同一 loopback 端口，保留原生 Cookie 和绑定；端口占用直接报错。普通断网后，新请求在发送前尝试重新连接；已发请求断开或超时仍报告结果未知，不自动重放。也可通过原生菜单“刷新页面”重新连接。被其他终端接管时停止自动恢复，先断开那个终端，再从智谱入口重新连接。请避免同时打开该设备的云端 ZCode 配对页面。手机本地代理的错误返回 JSON，原版登录页可以正常显示错误消息。

“退出智谱并移除连接”会清除本机智谱登录和该连接的本地登录状态；仅移除电脑保留智谱账号登录。App 进程终止会关闭手机隧道。普通 APK 的通知仍沿用原项目的前台巡检能力，不能把它视为 Android 后台常驻或云推送保证。

## 保留的边界

本地代理只绑定 `127.0.0.1`，需要随机本地 capability；该凭据不转发电脑。Host、Origin、CSRF、Cookie、文件路径、会话归属和写请求未知不重放均由原有边界继续校验。上游固定为本机 8787，不能指定任意主机或 URL。SSE 明确返回 406，使用原项目已有长轮询回退。分块大小 49152 字节，请求最大 20 MiB、16 并发和 32 MiB 请求体聚合限制；手机响应另有全局 32 MiB 额度，持有至写完或断开才释放；本通道响应最大 20 MiB，不能宣称支持原网关任意大小下载。

手机远控沿用 Desktop 当前实际权限；不能以其他 CLI 的 `sandbox` 配置声称 Desktop 已被沙箱隔离。本接入不会自动提高权限或开启 full-auto。

## 已验证与尚待验证

2026-11-15：桌面连接器 23 项后端测试、原手机脚本资源 28 项回归、配对链接 11 项断言、Java 网关 95 项断言通过。连接取消/超时并发回归通过。Android 35/JDK17/D8(min API26) 真实编译及 APK 签名验证通过。

真实智谱临时设备与正式设备均完成 Java 原生传输往返，原 HTML/JS/CSS 字节一致，原登录/退出、17 项目、首批 100 会话及认证边界通过。内置浏览器已通过该传输查看原版项目分组和历史，并在专用会话通过 DeepSeek/max 的计划模式真实 request_user_input 卡片提交，Desktop 回 `NATIVE_QUESTION_ACK:20261115`。第一次指定异步工具的测试只得到普通文本，不计问询成功；成功记录来自第二次真实工具卡片。

这些结果不代表 Android 真机已验收。手机系统浏览器 OAuth、Keystore、WebView Cookie/恢复、附件及蜂窝网络仍需手机实际行为验证。安装包使用本地 preview 签名；不能覆盖官方签名版本。遇到签名冲突时应保留原 App 和数据，不要直接卸载旧版。
