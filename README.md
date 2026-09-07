# CHACHA · 铁道资源加解密

Windows 文件夹加密与还原工具，由独立的加密端和「铁道资源解密」客户端组成。使用 XChaCha20-Poly1305 分块加密，支持无需密钥预览文件清单，以及 1–7 次限次密钥。

> **安全边界：** 文件名、目录结构、大小和修改时间是公开的。限次密钥是离线使用管理，不是不可绕过的 DRM；备份回滚、不同副本或修改客户端均可能绕过次数限制。不要把密钥与加密包作为同一个不受保护的副本传输。

## 下载

从 [最新 Release](https://github.com/nirvanafaith/chacha/releases/latest) 下载便携包。此仓库为私有仓库，仅获授权的 GitHub 用户可以访问源码和下载 Release。

| 文件 | 内容 |
| --- | --- |
| `chacha-v2.1.0-windows-x86.zip` | 加密端与解密端完整便携包 |
| `chacha-enc-v2.1.0-windows-x86.zip` | 仅加密端 |
| `railway-resource-dec-v2.1.0-windows-x86.zip` | 仅「铁道资源解密」客户端 |
| `SHA256SUMS.txt` | 三个压缩包的 SHA-256 校验和 |

完整解压后运行 `enc/chacha-enc.exe` 或 `dec/chacha-dec.exe`。单端包中的 EXE 位于压缩包根目录。请保留 EXE 同目录下的 `.exe.manifest` 文件，不要直接在压缩软件内部运行程序。无需安装，程序会在自身目录保存上次路径设置，因此建议放在可写目录。

发布产物是 **32 位 Windows GUI 程序**，也可在支持运行 32 位程序的 64 位 Windows 上使用。工具链和 PE 子系统以 XP SP3 兼容为目标，但 XP 实机/虚拟机、全部 CPU、DPI 和文件系统组合尚未验证。当前依赖系统 `msvcrt.dll`，不是完全静态 CRT。

校验下载内容：

```powershell
Get-FileHash .\chacha-v2.1.0-windows-x86.zip -Algorithm SHA256
```

将结果与同一 Release 的 `SHA256SUMS.txt` 对照。校验和用于检查下载完整性，不是代码签名。

## 功能

- 整个文件夹加密，保留普通文件内容、目录结构及受支持范围内的修改时间。
- 无密钥查看明文清单；导入密钥后认证完整清单，解密时逐块验证内容。
- 加密端设置密钥可用次数：1–7 次，默认 1 次。
- 解密端持久化扣次，耗尽后提示「密钥次数已耗尽」并禁止继续还原。
- 已有包、密钥文件和还原目标均拒绝覆盖；失败只清理本任务拥有的暂存内容。
- GUI 提供进度、取消、密钥复制，以及密钥首次保存失败后的另存恢复。
- 根据 CPU 能力选择 AVX2、SSE2 或标量内核；实际工作池最多 8 个线程。

## 使用方法

### 加密

1. 运行 `chacha-enc.exe`，选择源文件夹。
2. 确认加密包和密钥保存位置。
3. 在「可用次数」中选择 1–7，点击「开始加密」。
4. 分开保管加密包和密钥，保留原始数据，完成试解核验后再自行决定是否删除原件。

**试解也会消耗次数。** 软件不会主动删除源文件。密钥保存失败时请勿关闭加密端，先使用「另存密钥」恢复；关闭会丢失内存中的密钥。

### 解密

1. 运行 `chacha-dec.exe`，窗口标题为「铁道资源解密」。
2. 选择包含 `package.chx` 的加密包目录，查看文件清单。
3. 导入匹配的密钥文件并选择还原位置。
4. 点击「解密还原」。程序在所选位置下创建与源文件夹同名的新目录，已有目录（即使为空）不会合并覆盖。

预览不代表清单已认证，清单认证也不代表所有数据块已验证。只有整个还原任务成功后的最终结果才可使用。

### 密钥次数规则

- 一次整包还原任务消耗一次，不按文件或数据块计次；仅导入、预览和认证不扣次。
- 次数作为内部字段与内容密钥一同封装，解密界面不显示剩余次数。
- 实际输出明文前，程序独占打开密钥文件，重新读取、减一、同步写盘并读回校验。同一文件被占用、只读或写回失败时拒绝解密。
- 最后一次允许完成；其后再次读取会提示「密钥次数已耗尽」。重启软件不会重置文件计数。
- 错误密钥、包不配对、已有目标等前置检查失败不扣次。实际扣次后取消、密文认证失败或异常退出不退次数。
- 写回中断可能导致密钥损坏，不保证掉电原子更新。恢复备份可能恢复计数，这是离线文件的固有限制。
- 「复制密钥」复制完整封装的十六进制文本，不是裸密钥。粘贴到纯文本文件后可以导入；首次使用会写回二进制格式。复制保留生成该密钥时的次数，不受之后下拉框选择影响。
- 不同副本不共享计数。需要跨电脑、不可回滚的全局次数限制时，必须使用可信服务器或受信硬件。

## 命令行

```text
chacha-enc --encrypt <源文件夹> --package <新包目录> --keyout <新密钥文件> --uses 3
chacha-dec --decrypt <包目录> --key <密钥文件> --out <还原父目录>
chacha-dec --info <包目录>
chacha-enc --self-test
chacha-dec --self-test
chacha-enc --bench
```

`--uses` 可省略，默认 1；仅接受 1–7。退出码非零表示失败，不能仅凭输出中出现 PASS 或成功字样判断任务完成。

GUI 预填（不自动执行）：

```text
chacha-enc <源文件夹> --to <保存父目录>
chacha-dec <包目录> --key <密钥文件> --out <还原父目录>
chacha-dec <密钥文件>
```

## 格式与兼容性

```text
example.chacha/
  package.chx
  blobs/
    000000.chx
    000001.chx
example.chacha.key
```

- 新写入包采用 **格式 2**，完整认证文件/目录清单及元数据。每个密文对象有固定 32 字节头，内容按 1 MiB 分块，nonce 为 24 字节，认证标签为 16 字节。
- 新密钥使用 `CHAKY002`，共 137 字节，内部包括 32 字节随机内容密钥及 0–7 计数字段。自包含封装只隐藏字段，不防持有者分析或主动修改。
- 旧 `CHAKY001`（68 字节）和 64 字符裸密钥仍兼容，但**没有次数限制**。旧客户端不能读取新密钥；要应用限次规则，请使用新版两端重新生成。
- **拒绝格式 1 包**，不会自动迁移。旧版存在已知安全风险，因此本仓库和 Release 不分发旧版 EXE。保留旧包的用户应先使用自己已有的旧版，在隔离环境恢复本人可信数据，再用新版重新加密。
- 当前限制：16 MiB 清单、100,000 个文件/目录、64 层相对路径、1 TiB 总内容、1,048,576 个数据块。拒绝含 `~` 的名称以保守避免 Windows 8.3 别名冲突。
- 不保证 ACL、ADS、硬链接关系、创建时间及 1970 年前时间的无损恢复；符号链接、重解析点和无法无损表示的名称不静默忽略。FAT 时间精度可能较低。

## 从源码构建

源码不含 Rust 工具链、构建缓存、用户密钥或可执行文件；可执行文件通过 Release 分发。项目无外部 Cargo 依赖。

在 Windows 上安装 [rustup](https://rustup.rs/)，然后从仓库根目录执行以下命令。环境脚本将工具链放在本仓库 `tools` 下，不改动其他项目的 Rust 默认配置：

```powershell
. .\tools\env.ps1
rustup toolchain install 1.44.0-i686-pc-windows-gnu --profile minimal
powershell -File .\build.ps1
```

构建锁定 Rust 1.44.0、`i686-pc-windows-gnu`。脚本使用该工具链随附的 GNU 链接器；如提示找不到 `i686-w64-mingw32-gcc`，需提供对应的 32 位 MinGW 工具链并加入 PATH。不要随意替换现代工具链后仍宣称兼容 XP。

输出目录：`dist/enc`、`dist/dec`。测试需 Python 3.9+、Windows PowerShell 和上述 Rust 环境：

```powershell
. .\tools\env.ps1
cargo test --lib --target i686-pc-windows-gnu
python tools\key-usage-regression.py -v
python tools\security-regression.py -v
python tools\pe.py dist\enc\chacha-enc.exe dist\dec\chacha-dec.exe
powershell -STA -File tools\key-uses-gui.ps1
```

GUI 回归会打开窗口并短暂使用剪贴板；结束时恢复原设置和剪贴板（若没有外部改动），清理独占临时样例。截图保存在 `target/key-usage-gui`。旧的 `install-rust.ps1`、`dist-install.ps1`、`verify.py`、`drive-gui.ps1` 等辅助脚本包含旧盘符或格式假设，仅作为历史资料，不要直接执行；以本节命令为准。

## 验证与安全说明

v2.1.0 发布前验证包含：8 项 Rust 单元测试、10 组限次回归、12 组安全回归（421 次 CLI 调用）、原生 GUI 次数/复制/另存恢复/耗尽重开测试，以及 PE 静态兼容性检查。窗口改名后另行检查了标题和提示文字。

这不等于独立密码学审计，也不覆盖完整 XP/CPU/DPI 矩阵。暂存文件普通删除不保证物理安全擦除；跨卷包/密钥原子提交、断电恢复、同权限恶意进程竞态、VSS 快照和密钥内存/分页防护仍不作保证。

[SECURITY_REVIEW_AND_IMPROVEMENT_PLAN.md](SECURITY_REVIEW_AND_IMPROVEMENT_PLAN.md) 和 [FIX_STATUS.md](FIX_STATUS.md) 保留为历史审查与修复记录，不代表全部长期建议已完成。不要将本项目作为重要数据的唯一备份。
