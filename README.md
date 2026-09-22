# Android Security Lab

面向 Codex 等支持 `SKILL.md` 的智能体，以及命令行用户的 Android 安全测试 skill。提供设备诊断、APK 提取与静态分析流程、Frida 进程检查、USB HTTPS 抓包和原生库分析指引。

仅用于自有或已获授权的设备、应用、账号与网络。默认从只读检查开始；不包含任何设备数据、账号、证书、APK 或预设设备标识。

## 环境要求

- macOS 或 Linux，Bash、ADB（Android Platform Tools）；手机开启 USB 调试并授权主机。
- Python 3 与 venv：仅 Frida 客户端安装需要。
- 按任务自行安装 JADX、apktool、mitmproxy 等工具。
- 普通 ADB 功能不要求 root；root/Frida 诊断需要相应设备能力。`doctor` 会尝试只读 `su` 查询，可能触发设备授权提示。缺少 root、CA 或 Frida server 不代表普通 ADB 不可用。
- 不自动安装手机端服务、Magisk 模块或 CA，也不修改全局智能体配置。

## 安装为 skill

```bash
git clone https://github.com/zyc945/Android-Security-Lab.git
cd Android-Security-Lab
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
# 若目标已存在，先检查并备份；不要覆盖已有自定义 skill。
cp -R -n skills/android-security-lab "${CODEX_HOME:-$HOME/.codex}/skills/"
```

在新的智能体会话中使用 `$android-security-lab`，例如：“检查我已授权的 USB 测试机，先只读诊断。”其他支持 skills 的工具可将整个 `skills/android-security-lab` 目录放入其技能目录。

skill 自带脚本、依赖声明和操作规则，不依赖原克隆目录。独立安装后的 Frida 环境可这样准备（先核对手机 server 版本）：

```bash
skill_dir="${CODEX_HOME:-$HOME/.codex}/skills/android-security-lab"
python3 -m venv "$skill_dir/.venv"
"$skill_dir/.venv/bin/python" -m pip install -r "$skill_dir/requirements.txt"
"$skill_dir/scripts/android-lab" help
```

`requirements.txt` 是一组固定的兼容版本示例；Frida client 应与手机 server 一致。需要其他版本时调整该版本对，不要假定所有设备已安装 server。

## 从仓库使用

```bash
./bin/android-lab help
make check
./bin/android-lab devices
./bin/android-lab doctor
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
./bin/android-lab screenshot
./bin/android-lab ui-dump
```

`ANDROID_LAB_ROOT` 可指定另一实验室目录，`.venv` 和 `artifacts/` 都随之定位；`ADB_BIN` 可指定 ADB 路径。`LAB_FRIDA_PORT` 可指定未占用的主机 Frida 转发端口（默认 27042），避免覆盖既有转发。

HTTPS 抓包按 [USB 抓包流程](skills/android-security-lab/references/lab-rules.md) 操作。代理与 Web UI 只监听 `127.0.0.1`，使用 USB ADB reverse；结束时恢复原代理，仅清理本次转发。已有 CA 不重复安装，应用解密失败也不能直接认定为证书固定。

## 分享与隐私

- `artifacts/`、虚拟环境、本地智能体配置、环境变量文件、APK、抓包和常见私钥格式由 `.gitignore` 排除。
- `.gitignore` 无法代替审查；提交前检查 `git diff --cached` 与文件清单。
- `doctor`、截图、UI XML 和日志可能包含序列号、路径、账号与令牌；不要原样粘贴到公开 issue。
- 本仓库不包含任何特定测试机状态。实际能力以用户环境检查为准。

## License

MIT，见 [LICENSE](LICENSE)。
