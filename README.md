# Android Security Lab

面向 Codex 等支持 `SKILL.md` 的智能体，以及命令行用户的 Android 安全测试 skill。提供设备诊断、APK 提取与静态分析流程、Frida 进程检查、USB HTTPS 抓包和原生库分析指引。

仅用于自有或已获授权的设备、应用、账号与网络。默认从只读检查开始；不包含任何设备数据、账号、证书、APK 或预设设备标识。

## 快速安装

### 一条命令（Codex、Claude Code 等）

主机已有 Node.js / npm 时，在终端运行：

```bash
npx skills add zyc945/Android-Security-Lab
```

按提示选择使用的智能体及项目级或全局安装。只安装到 Codex 的全局 skill 目录：

```bash
npx skills add zyc945/Android-Security-Lab --skill android-security-lab -a codex -g
```

安装由第三方 [Skills CLI](https://github.com/vercel-labs/skills) 完成，自动发现本仓库的 `skills/` 目录。

### Codex 一句话安装

在提供内置 `skill-installer` 的 Codex 会话中发送：

```text
使用 $skill-installer 安装：
https://github.com/zyc945/Android-Security-Lab/tree/main/skills/android-security-lab
```

此方式不要求 Node.js / npm，也不需要手动 clone 和复制。若同名 skill 已存在，先检查已有自定义内容再决定如何更新。

### 开始使用

安装后，在 Codex 中使用 `$android-security-lab`，例如：

> 使用 $android-security-lab 检查我已授权的 USB 测试机，先只读诊断。

若当前会话未发现新 skill，开启新会话后重试。skill 自带脚本、依赖声明和操作规则，不依赖原克隆目录。

**安装 skill 不等于安装 Android 测试环境。** ADB、Frida、mitmproxy 等仅在使用相应功能时准备；安装 skill 本身不会修改手机。

## 按需准备环境

- macOS 或 Linux、Bash。
- 设备操作：ADB（Android Platform Tools）；手机开启 USB 调试并授权主机。
- Frida：Python 3 与 venv，以及匹配版本的手机 server。
- 静态分析或抓包：按任务自行安装 JADX、apktool、mitmproxy 等工具。
- 普通 ADB 功能不要求 root；`doctor` 默认不调用 `su`，`--root` 才启用只读 root 查询，可能触发设备授权提示。缺少 root、CA 或 Frida server 不代表普通 ADB 不可用。
- 手机端服务、Magisk 模块或 CA 的安装属于单独的设备变更。

独立安装后的 Frida 环境可这样准备（将 `skill_dir` 改为安装器报告的实际目录，先核对手机 server 版本）：

```bash
skill_dir="${CODEX_HOME:-$HOME/.codex}/skills/android-security-lab"
python3 -m venv "$skill_dir/.venv"
"$skill_dir/.venv/bin/python" -m pip install -r "$skill_dir/requirements.txt"
bash "$skill_dir/scripts/android-lab" help
```

`requirements.txt` 是一组固定的兼容版本示例；Frida client 应与手机 server 一致。需要其他版本时调整该版本对，不要假定所有设备已安装 server。

## 更新与卸载

通过 Skills CLI 安装的全局 skill：

```bash
npx skills update android-security-lab -g
npx skills remove android-security-lab -a codex -g
```

项目级安装的更新使用 `-p`，卸载省略 `-g`。卸载或更新前，将 skill 目录内需要保留的 `artifacts/` 移到独立实验室目录；建议日常通过 `ANDROID_LAB_ROOT` 将实验数据与安装文件分开。

## 手动安装（备选）

```bash
git clone https://github.com/zyc945/Android-Security-Lab.git
cd Android-Security-Lab
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
# 若目标已存在，先检查并备份；不要覆盖已有自定义 skill。
cp -R -n skills/android-security-lab "${CODEX_HOME:-$HOME/.codex}/skills/"
```

其他支持 skills 的工具可将整个 `skills/android-security-lab` 目录放入其技能目录。

## 从仓库使用

```bash
./bin/android-lab help
make check
./bin/android-lab devices
./bin/android-lab doctor
./bin/android-lab doctor --json --for adb
# 离线 APK 检查不要求 ADB 或手机：
./bin/android-lab doctor --json --for apk
# 需要 Frida 时，先匹配版本再安装：
make setup
make frida-ps
```

多台设备必须明确选择：

```bash
ANDROID_SERIAL=YOUR_DEVICE_SERIAL ./bin/android-lab doctor
./bin/android-lab -s YOUR_DEVICE_SERIAL apps
```

常用命令：

```bash
./bin/android-lab package-info com.example.app
./bin/android-lab pull-apk com.example.app
./bin/android-lab apk-inspect artifacts/apks/com.example.app/YOUR_PULL_DIR
./bin/android-lab apk-inspect artifacts/example.apk
./bin/android-lab logcat-dump com.example.app 500
./bin/android-lab screenshot
./bin/android-lab ui-dump
./bin/android-lab capture
```

`ANDROID_LAB_ROOT` 可指定另一实验室目录，`.venv` 和 `artifacts/` 都随之定位；`ADB_BIN` 可指定 ADB 路径。`LAB_FRIDA_PORT` 可指定未占用的主机 Frida 转发端口（默认 27042），避免覆盖既有转发。

HTTPS 抓包按 [USB 抓包流程](skills/android-security-lab/references/lab-rules.md) 操作。代理与 Web UI 只监听 `127.0.0.1`，使用 USB ADB reverse；结束时恢复原代理，仅清理本次转发。已有 CA 不重复安装，应用解密失败也不能直接认定为证书固定。

## 会话清理与提取结果

`frida-ps` 创建转发前检查占用，并用 ADB `--no-rebind` 防止覆盖其他会话。命令退出、失败或收到 Ctrl+C / SIGTERM 时，只删除仍匹配所选设备和端口的本次转发；被替换的映射保留并报告清理失败。ADB 调用失败或超时不能证明资源归属，不强行删除。

`capture [DIR]` 在前台运行 mitmweb，固定使用回环地址 8080/8081。先验证两个监听属于本次进程，再创建 USB reverse 并设置手机代理。退出时恢复原 `http_proxy`、核对并删除本次 reverse，然后停止本次子进程；某步清理失败也继续其他步骤。已占用的端口或映射会拒绝启动，外部修改的代理或映射保留。最后将结果、清理错误和 `https_decryption: "not_tested"` 写入 `DIR/session.json`。监听就绪不等于 HTTPS 已解密，仍需实际请求验证。

`pull-apk PACKAGE [DIR]` 为每个成功 APK 记录来源路径、产物路径、字节数和 SHA-256 到 `DIR/manifest.json`；单个 split 失败后继续，保留成功文件并删除本次失败残片。结果 `coverage` 为 `complete` / `partial` / `none`，退出码分别是 0 / 1 / 2；只在完整成功时向 stdout 输出目录，失败时 stderr 指向 manifest。设备枚举失败与“没有 APK 路径”分别记录。

两个命令默认使用带时间和进程号的新产物目录，显式指定的 `DIR` 必须不存在，避免覆盖或混入旧产物。Python helper 使用 Python 3.9+ 标准库，无新增第三方依赖。

结果保留原有字段和退出码，并增加 `schema_version`、操作名、UTC 开始/结束时间、工具路径与版本（未知为 `null`）及限制。`failures` 增加失败阶段、稳定错误码和 `error_truncated`；错误摘录最多 2048 字符。APK 来源枚举、拉取、摘要、完成文件和清理分别报告；manifest 无法写入时通过 stderr 和退出码报告。新 APK 记录还包含相对 manifest 目录的 `relative_path`，旧 `local_path` 保留。

## 离线诊断与 APK 摘要

`doctor --json` 在没有手机时仍输出主机检查。`--for adb|frida|capture|apk` 选择必需项；省略时审查设备连接和可选工具。`apk` 指离线摘要，设备拉取需要 `adb` 就绪。缺少可选工具不导致所选流程失败；必需项未知或未检查不能算通过。退出码 0 表示必需检查通过，1 表示未就绪，2 表示参数无效。就绪不证明实际 attach、抓包解密或分析成功；捕获端口和代理归属仍由启动流程核对。

`apk-inspect APK...` 或 `apk-inspect PULL_DIR` 完全离线，只读取本地文件。目录模式按 manifest 的 APK 清单读取，拒绝越界路径和符号链接，并核对已有摘要。输出包含 APK SHA-256、打包 ABI、原生库清单、Flutter/React Native 标记及对应 APK/ZIP 路径。`source_coverage` 表示输入 APK 集合的获取覆盖度，`inventory_coverage` 表示本次检查覆盖度，`coverage` 表示整体结果；退出码为完整 0、部分 1、无结果/无效 2。仅提供部分 APK 时，未发现标记不能说明整个应用未使用某框架；ABI 目录不证明 ELF 架构或运行时加载。该命令不解包、不执行 APK、不解码 Manifest 或资源，也不推测 Dart SDK 版本。预算和范围见 [分析说明](skills/android-security-lab/references/reverse-analysis.md)。

`logcat-dump PACKAGE [COUNT]` 进入采集 helper 后向 stdout 输出一个 JSON 结果，诊断写 stderr；wrapper 参数或设备选择失败时可能仅输出 stderr。默认 500 行，范围 1–10000。只读取采集时单个 PID 的 main 缓冲区尾部，多 PID 会拒绝；历史覆盖度为 partial，空结果不证明没有日志。采集成功退出 0，运行失败/中断退出 1，直接 helper 的参数错误退出 2。原 `logcat` 保留交互式连续输出。

后台 ADB/工具查询同时限制时间和 stdout/stderr 合计字节数：APK 路径枚举 64 KiB、常规查询和拉取进度 1 MiB、工具版本 16 KiB。超限报告 `output_limit`，超时报告 `timeout`；本次子进程会被终止并回收。前台 mitmweb 和交互式 logcat 的输出继续直接交给终端。

ADB 没有会话所有者标识，核对映射和删除并非原子操作；参数相同的删除后重建也无法识别。SIGKILL、主机断电不能执行清理；设备断连或 ADB 无法响应时会报告可能残留，不宣称恢复成功。保留产物后按 [抓包恢复流程](skills/android-security-lab/references/capture.md) 核对当前状态，避免盲目删除映射。

开发验证使用 `make test`：只运行模拟 ADB/mitmweb 的测试，不连接手机。

## 分享与隐私

- `artifacts/`、虚拟环境、本地智能体配置、环境变量文件、APK、抓包和常见私钥格式由 `.gitignore` 排除。
- `.gitignore` 无法代替审查；提交前检查 `git diff --cached` 与文件清单。
- `doctor`、截图、UI XML 和日志可能包含序列号、路径、账号与令牌；不要原样粘贴到公开 issue。
- 本仓库不包含任何特定测试机状态。实际能力以用户环境检查为准。

## License

MIT，见 [LICENSE](LICENSE)。
