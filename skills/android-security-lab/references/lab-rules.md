# Android 安全测试机操作规则

这些规则适用于用户自有或已获授权的 Android 安全测试机。独立安装 skill 时，将下文 `./bin/android-lab` 替换为 `bash /absolute/path/to/skill/scripts/android-lab`（ZIP 安装可能不保留执行权限），并从选定实验室目录执行。

## 默认工作方式

- 优先使用 `./bin/android-lab`，不要假定设备序列号；多设备时通过 `ANDROID_SERIAL` 或 `-s SERIAL` 明确选择。
- 探查和诊断默认只读。可以直接执行 `doctor`、`devices`、`apps`、`package-info`、`frida-status`、`frida-ps`、`ui-dump` 和 `screenshot`。
- 使用 root 前先确认普通 shell 是否足够。执行任意 root 命令时使用 `android-lab root 'COMMAND'`，避免错误的远端 shell 引号导致部分命令脱离 root 上下文。
- 仅测试用户明确拥有或获授权测试的应用、账号和网络。

## 必须先说明的手机侧变更

执行前说明精确目标、影响和回滚方式：安装/卸载应用或 Magisk 模块、改系统证书、改代理或防火墙、启停常驻服务、清除应用数据、修改系统设置、重启、写入 `/data` 或系统分区。

禁止默认启用 Wi-Fi ADB、`adb tcpip 5555`，也不要把 Frida 的 27042/27043 端口暴露到局域网。Frida 保持监听手机 `127.0.0.1`，主机经 USB/ADB 临时转发访问。

## mitmproxy USB 抓包复用流程

- 抓包前运行 `./bin/android-lab doctor`，确认设备在线、系统代理状态和主机 mitmproxy 可用。多设备时先设置 `ANDROID_SERIAL`，并给直接调用的 adb 命令添加 `-s "$ANDROID_SERIAL"`。
- 只监听主机回环地址，通过 USB ADB reverse 转发，不把代理端口或 mitmweb 暴露到局域网。
- 已安装并验证系统 CA 时不要重复安装；证书或 Magisk 模块变更仍须按上文要求先说明影响和回滚方式。

启动前记录原有代理与 `adb forward --list` / `adb reverse --list`；若 8080 映射已被占用，不要覆盖。结束时恢复原值，只删除本次创建的映射。以下清理示例假设原先没有代理。

启动抓包时先创建产物目录并建立 USB 代理链路：

```bash
capture_dir="artifacts/mitm/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$capture_dir"
adb reverse tcp:8080 tcp:8080
./bin/android-lab proxy set 127.0.0.1 8080
mitmweb \
  --listen-host 127.0.0.1 --listen-port 8080 \
  --web-host 127.0.0.1 --web-port 8081 \
  --set web_open_browser=false \
  --save-stream-file "$capture_dir/phone-capture.mitm"
```

`mitmweb` 在前台持续运行，Web 界面使用它输出的本地 `127.0.0.1:8081` 地址。另开终端发起并验证 HTTPS 请求：

```bash
capture_dir="$(find artifacts/mitm -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
./bin/android-lab open-url "https://example.com/?mitmproxy_test=$(date +%s)"
mitmdump -nr "$capture_dir/phone-capture.mitm" '~u mitmproxy_test'
```

结束抓包时先恢复手机网络，再删除临时 reverse，最后停止 mitmweb：

```bash
./bin/android-lab proxy clear
adb reverse --remove tcp:8080
./bin/android-lab proxy status
adb reverse --list
# 回到运行 mitmweb 的终端按 Ctrl-C
```

多设备时，上述两个 `adb reverse` 命令分别改为 `adb -s "$ANDROID_SERIAL" reverse ...`。结束后报告抓包文件路径，以及系统 CA、Magisk 模块等仍保留的持久变更。若普通 HTTPS 已成功而特定应用仍失败，优先判断证书固定，不要反复改系统代理或重复安装 CA。

## 本地产物

- APK、截图、UI XML、日志和抓包统一放到 `artifacts/`；该目录不进入 Git。
- 不把令牌、密码、私钥、应用私有数据或设备唯一标识写入仓库。
- 结束测试时清理临时代理和 ADB 转发，并报告手机上仍然存在的持久变更。
