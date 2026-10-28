<div align="center">

<img width="256" height="256" alt="GeDefense Windows" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />

# VGT GeDefense Titan

### 主权终端安全中心与 Kinetic 威胁防御体系

[English](README.md) · [Deutsch](README.de.md) · [Русский](README.ru.md) · **中文**

[![许可证](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](LICENSE)
[![版本](https://img.shields.io/badge/Version-5.3.0-orange?style=for-the-badge)](#release-history-v5)
[![状态](https://img.shields.io/badge/Status-Public_Beta-yellow?style=for-the-badge)](#public-beta-advisory)
[![平台](https://img.shields.io/badge/Platform-Windows_11_x64-lightgrey?style=for-the-badge&logo=windows)](#system-requirements)
[![控制平面](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#local-sovereignty-and-privacy)
[![架构](https://img.shields.io/badge/Architecture-Zero_Go_Dependencies-blue?style=for-the-badge)](#architecture)
[![证据](https://img.shields.io/badge/Evidence-HMAC--SHA256_Ledger-gold?style=for-the-badge)](#what-is-geodefense-titan)
[![签名](https://img.shields.io/badge/Signing-Self--Signed_Beta_Only-lightgrey?style=for-the-badge)](#verification-and-trust)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**DEFENDER · WFP 防火墙 · ASR · APP CONTROL · Kinetic Defense · MHX EDR/XDR · TITAN 完整性 · 原生流量 · GEOIP/ASN**

<br />

[安装与发布版本](https://github.com/visiongaiatechnology/gedefensewin/releases) · [架构](ARCHITECTURE.md) · [Titan 概念](docs/TITAN.md) · [构建指南](docs/BUILDING.md) · [运维](docs/OPERATIONS.md) · [安全政策](SECURITY.md)

</div>

---

<img width="1536" height="1024" alt="GeDefense_ Real Security, Many Feathers" src="https://github.com/user-attachments/assets/68406427-a185-4fa5-b06a-af874a747dcb" />

<a id="public-beta-advisory"></a>

## ⚠️ 公开测试版公告

> [!IMPORTANT]
> **状态：公开测试版——GeDefense Windows 5.3.0。**
>
> GeDefense Titan 正在积极开发中。**此测试版可能包含错误，包括安全缺陷。**我们持续进行加固、测试和修复，并欢迎每一份可复现的报告。
>
> - 请先在测试系统上使用测试版，保留备份，不要将其作为生产环境中唯一的安全控制措施。
> - 请通过 [GitHub Issues](https://github.com/visiongaiatechnology/gedefensewin/issues) 报告错误、安全问题和功能请求，或按照 [SECURITY.md](SECURITY.md) 负责任地进行披露。
> - 此版本为**自签名**，**没有公共 CA 信任**；目前尚无 RFC 3161 时间戳、CRL/OCSP 撤销路径或外部锚定的防回滚通道。因此，5.3.0 **不是可公开信任的发布版本**。参见[验证与信任](#verification-and-trust)。
> - 核心架构由自动化发布门禁验证（Go race、Go vet、govulncheck、SBOM、来源证明、安装程序和发布门禁）。实际安装和安全策略变更仍应在隔离的测试虚拟机上执行。

---

<a id="what-is-geodefense-titan"></a>

## 什么是 GeDefense Titan？

GeDefense Titan 是面向 Windows 11 的本地主权安全控制台。它将 Windows 的各安全层统一到一个操作员界面中，并增加自有的授权、证据与完整性层：

- **Windows 控制体系：**对 Defender、ASR、Windows 防火墙/WFP、App Control、审核策略、SMB/RDP/LSA/UAC 设置和加固组件进行度量，与基线比较，并可在留存证据的情况下以幂等方式应用。
- **MHX EDR/XDR：**原生进程、Defender 和网络关联，进程祖先关系，所属 PID 解析，编码命令检测以及受控响应操作。
- **威胁情报：**精选情报源、逐情报源验证的权威性、WFP 封禁生成以及严格的生命周期限制。
- **Kinetic Defense：**针对真实入站 WFP 封禁事件进行突发关联分析（默认 `OBSERVE_ONLY`；`ARMED` 需要操作员明确确认，且遥测已验证处于活动状态）。
- **原生网络遥测与本地 GeoIP/ASN 地图：**RX/TX 接口计数器，以及基于本地 CSV 对实际观测到的来源进行国家/ASN 归属——不进行外部 IP 查询，也不虚构主机位置。
- **Titan：**下文所述的完整性、授权与证据层。
- **纯本地控制平面：**服务监听回环地址（`127.0.0.1:17831`）。没有云控制平面，也不会向第三方静默发送遥测数据。

### Titan——主权终端完整性

Titan 回答了一个传统防病毒工具常常含糊处理的问题：*这项变更是否经过所有者授权？*每项变更都会根据已存储的所有者策略被归类为 `AUTHORIZED`、`TOLERATED`、`UNEXPECTED` 或 `COMPROMISED`，而不是依据进程已签名或由管理员启动这一事实来归类。

Titan 结合了以下内容：

- 原生 Windows 传感器（`ReadDirectoryChangesW`，采用重叠 I/O），用于受保护的系统、启动、驱动程序、任务和用户入口路径；
- SHA-256 证据、区域标识符、原生进程列表、TCP 上下文以及进程/网络的时间关联——不虚构文件到 PID 的归属；
- 持久化与安全清单（服务、Run/RunOnce 项，Defender/防火墙/LSA/UAC/SMB/RDP/PowerShell 日志记录控制，安全启动状态），其基线仅在证据成功写入后才会推进；
- 仅追加、以 HMAC/SHA-256 链式关联的证据日志，带有 Ed25519 签名检查点、完整性验证和已签名的保留归档；
- AES-256-GCM 隔离保管库，具有文件大小上限、SHA-256 验证、原始路径可追溯性和受控恢复能力，且绝不会覆盖现有目标；
- 所有者策略（`OBSERVE`、`CONTAIN`、`STRICT`）、所有者许可、开发树标记、审查决定和原生 Windows 拦截通知。

**坦诚的局限：**不声称具备完整归属能力，无法防护内核/固件的完全失陷，不提供 TPM 度量启动证明，且此阶段不提供基于微过滤器的执行阻止。这些局限已在 UI 和 [`docs/TITAN.md`](docs/TITAN.md) 中记录。

---

<a id="release-history-v5"></a>

## 5.3.0 新增内容

- **Sentinel / Killerdom 执行平面：**实时签名与行为响应、严格父子谱系、规范 System32 路径检查、AMSI 扫描缓冲区完整性监控以及默认拒绝的偏执门限。
- **以执行来源取代免检通行：**精选系统应用和允许列表条目通过路径、PE OriginalFilename、Authenticode 签名者/发布者以及可选的 SHA-256 固定值进行校验；允许列表绝不会压制高置信度的终止操作。
- **Titan → Killerdom 桥接：**Titan 完整性违规可通过经验证的 PID 终止来消除恶意持久化；每个操作和失败都会记录到 HMAC 链式证据中。
- **真正生效的 Ghost Mode：**通过基于 WFP 的 Windows 防火墙规则阻止出站遥测程序和服务，将 Microsoft 遥测主机重定向到 sinkhole，在启动时核对状态并如实报告（`applied` / `lastError`）。
- **误报加固：**收窄了 PowerShell 混淆、base64 数据块和破坏性 `cmd /c` 模式的签名；encoded-command 解析器现在仅适用于 PowerShell 主机。正常管理/测试命令和 `govulncheck` 不再被终止。
- **加固与供应链：**作用域会话、降低保护时的类型化确认和原因、SHA-256/签名者固定的允许列表条目、不可变自我保护、v5 API 别名、签名安装程序、SBOM/provenance、零第三方 Go 依赖以及 `govulncheck` 0。
- **UI 与本地化：**Sentinel/Killerdom 表格独立渲染并支持空状态；所有四种 UI 语言（德语、英语、俄语、简体中文）均覆盖新页面；间距和 Glass 2100 布局已修正。

## 为关键场景而构建

GeDefense Windows 5.3.0 面向需要在隔离、受监管或离线环境中保持控制权的 Windows 11 终端：仅本地控制平面、无云依赖、可验证证据、受限资源和明确响应边界。这**并非**完整保护的声明：内核/固件失陷、恶意本地管理员和完整供应链失陷仍超出产品边界；该构建为自签名，仍属公开测试版。

## V5 发布历史

### 5.3.0 — Sentinel 执行平面、来源加固与关键场景就绪

- Sentinel/Killerdom 控制台，包含签名开关、系统应用隔离、允许列表固定、强制 Ghost Mode 与 Titan 关联。
- VGT-100 安全审计：81/81 适用控制项 PASS，0 FAIL，无未解决的 CRITICAL/HIGH；发布门禁 `ELIGIBLE_FOR_REVIEW`。
- 实际验证：Ghost Mode 9 条防火墙规则、hosts sinkhole 与回滚；Sentinel 渲染 6/9/14 行；`govulncheck` 0；签名安装程序。
- 已记录限制：公开测试版、自签名、本地 admin/SYSTEM 失陷在产品边界之外。

**完整变更日志：** [CHANGELOG.md](CHANGELOG.md)

### 5.2.0 — 国际化与整洁源码发布

- **四种 UI 语言：**德语、英语、俄语和简体中文，页眉中带有语言切换器，并可根据系统/浏览器语言自动检测。
- **整洁的仓库：**生成的构建输出（`work/`、`payload/`、`release/`、`sbom/`）、交接/代理产物和历史验证报告不再属于源码树；`.gitignore` 和发布门禁强制实施这一分离。
- **README 整合：**发布历史、Titan 说明、安全修复摘要、许可和第三方归属现在集中在一份以四种语言维护的文档中。
- **归属声明：**jsVectorMap 地图几何数据（MIT，`world-merc.js` 1.7.0）和 ASN 数据库来源 **iplocate/ip-address-databases**（CC BY-SA 4.0）均已明确署名（参见[许可证与归属](#licenses-and-attribution)）。
- **版本标识：**`VERSION`/Go 产品版本 5.2.0；确定性 SBOM、来源证明和已签名安装程序由构建流水线生成。
- **安装与升级可靠性：** 当用户缓存不可用时，安装程序改用安全的临时暂存目录；发布者信任通过证书存储导入，不再触发交互式 `Import-Certificate`；旧版 hardening/MHX 基线会被归档并迁移，而不是阻止升级；审计策略备份与签名脚本处理在重装时保持稳健；服务在自相对 DACL 校验下可正确启动。
- **UI 标识：** TITAN 5.2 徽标与窗口标题“GeDefense V5 · Windows Security Center”标识当前版本。

### 5.1.4 — 审计整改 2（其余可在本地修复的发现项）

- **操作员身份验证：**Center 和 Tray 不再读取长期有效的 `dashboard.token`。新的回环操作员代理会验证调用者的 Windows 进程令牌（是否为 `VGT GeDefense Operators` 或 Administrators 组成员），签发短期的范围受限会话，并审计操作系统账户。数据根目录和主令牌仅限 SYSTEM/Administrators 访问。
- **降级保护：**安装程序拒绝覆盖较新的安装（`-AllowDowngrade` 仅用于明确且已记录的回滚）。
- **证据与交接：**交付包中已移除剩余的实时日志（以 SHA-256 归档）；可选的外部证据见证机制带截断检测；分发卫生门禁会在发现日志、密钥、令牌和 `.git` 元数据时直接判定失败。
- **主机加固：**外部或预先创建的单实例对象不再被认可为权威依据；浏览器可执行文件在启动前会进行 Authenticode 验证。
- **供应链：**确定性 SBOM/来源证明/sidecar 链，带交叉验证、默认拒绝式发布门禁以及 CI 工作流定义。
- **已接受的外部阻塞项：**公共 CA 签名身份、RFC 3161 时间戳、CRL/OCSP、外部锚定的防回滚通道和情报源签名密钥仍由所有者决定保持未解决；它们**不计为通过**。

### 5.1.3 — 安全审计整改与供应链

- Go 1.26.10；将 `govulncheck -mode=binary` 作为强制发布门禁（全部四个二进制文件中 0 个可达漏洞）。
- 真正的 CycloneDX SBOM、确定性且可复现的源码归档、来源证明工件、包卫生检查以及默认拒绝式发布验证。
- **API/身份验证：**服务端作用域（read/operate/policy/window）、范围受限会话、撤销/注销、轮换、绝对/空闲过期、按类别限流、强制重放 ID、早期拒绝时附带安全响应头、不透明的引擎错误，以及针对降低安全性的变更要求输入确认文本并说明原因。浏览器引导不再在 Chromium 参数中携带机密。
- **Titan/数据平面：**受继承保护的机密目录、已签名的情报源权威性验证器、具有明确 `UNCONFIGURED` 状态和硬性 TTL 的情报源、经 HMAC 认证的覆盖项、可安全处理重解析点的路径、有界 ADS 读取、保管库配额/保留、轮换证据归档、追加错误显现以及时钟回拨处理。
- **主机/MHX：**完整的编码命令前缀规范化、监视器拒绝 UNC/设备/重解析点映像路径、仅本地 XDR 签名检查、PID 复用安全的进程树终止、按身份限定范围的单实例对象，以及 MHX 基线与完整性绑定。
- **结果：**48 项深度审计发现中已修复 33 项、部分缓解 10 项、记录了 5 项外部信任阻塞项（在 5.1.4 中继续处理）。

### 5.1.2 — 可读性、Titan 视觉更新与快速就绪

- 安全中心和 Titan 全域采用白色字体排印；通过字号、字重、间距和表面建立层级；语义状态通过着色表面、边框和状态圆点保持可见。
- Titan 采用 Glass 2100 材质语言：紧凑的控制区、冰蓝色主信号、仅以青铜色作为证据强调色、分段式标签页和密集的传感器行。
- 通过缓存健康状态实现更快的启动门禁，策略协调时间上限为 3 秒，后台同步情报源，无阻塞式网络同步。
- 当映像路径、服务类型和账户保持不变时，BITS/维护服务的启动类型变更会被视为 `TOLERATED`；相同的未解决发现会在十分钟内合并为一条通知；最多可批量审查 100 项发现；监视器心跳稳定，并减少临时文件删除噪声。

### 5.1.1 — Titan 现场修复

- 针对 PowerShell 策略测试文件、驱动程序转储和非可执行临时工件的噪声过滤；对非可执行的中等评分入口文件采用容忍分类。
- 对 `C:\Windows` 与 `%SystemRoot%` 以及大小写漂移进行服务规范化。
- 所有者许可（路径、可选 SHA-256、操作、到期时间、一次性）和开发树标记，每项均带有一个证据事件。
- 更多 Titan/服务器测试以及扩展的浏览器测试夹具。

### 5.1.0 — GeDefense Titan

- 新增 Titan 控制中心页面，包含安全态势、入口时间线、隔离区、所有者策略和证据。
- 信任与授权模型（`AUTHORIZED`、`TOLERATED`、`UNEXPECTED`、`COMPROMISED`）。
- 原生 Windows 传感器、持久化/安全清单、已签名证据链、隔离保管库、所有者策略与响应、原生通知。
- 明确说明坦诚的局限，并将品牌更新为 **GeDefense Titan**。

### 5.0.0 — 可配置的安全防护体系

- 服务端设置引擎，覆盖 Defender、防火墙、加固、MHX、Kinetic、威胁情报、启动和通知，包含 55 项经过验证的控制项。
- 自定义防护配置文件，带服务端强制下限和确认短语。
- 深入的 Defender 遥测，提供真实测量值，并对不可测量字段显式使用 `null`。
- 经过验证的 Defender/防火墙/加固应用路径，支持证据、基线和回滚。
- MHX XDR 自动响应、通知，以及通过真实 Windows 防火墙程序规则实现的应用程序允许/拒绝。
- 威胁情报页面，具备逐情报源验证的权威性和生成验证；Kinetic Defense 保持活动状态，并在重启后重新验证。
- 仅在需要时启用启动门禁，服务自愈监督程序，加固/审计/证据用户体验改进。
- 全新的 V5“Glass 2100”控制台布局、原生 Windows 拦截通知、WFP 基数和同步速度修复、误报调优。
- 全新的原生 Win32 安装程序设计，包含实测进度、阶段导轨和信任侧边栏。

---

## 我们在安全加固中修复了什么

深度审计（`VGT-AUDIT-20261022-GEDEF-512`）覆盖了 48 项发现，涉及 HTTP/API/身份验证、数据平面（解析器、文件、证据、Titan、威胁情报）、主机权限/服务/MHX/WFP/加固以及 PowerShell 引擎。在 5.1.3 和 5.1.4 中：

- **已在本地修复：**身份验证与作用域、会话/轮换/重放、令牌与机密 ACL、从浏览器参数中移除引导机密、证据链与检查点处理、情报源 TTL/权威性验证、保管库/保留/ADS/重解析点加固、PID 复用安全的进程处理、单实例权威性、浏览器 Authenticode 验证、安装程序降级防护、发布通道卫生、SBOM/来源证明/sidecar 链、交接卫生以及仓库整洁性。
- **已缓解并记录残余风险：**Center 主机仍是以外部 Chromium kiosk 模式运行，且不具备嵌入式渲染器；浏览器路径为全机范围、管理员可写、无重解析点，并且经过 Authenticode 验证。
- **外部阻塞项（所有者已接受，不声称已通过）：**具备 RFC 3161 时间戳和 CRL/OCSP 撤销的公共代码签名身份、干净主机信任预配、外部锚定的防回滚通道以及 VGT 情报源签名密钥。在密钥预置完成前，情报源验证器保持处于默认拒绝的 `UNCONFIGURED` 状态。
- **验证：**完整发布门禁（使用 `vgt_bundle` 的 Go race、Go vet、govulncheck-binary、PowerShell 解析、前端安全不变量、SBOM、来源证明、分发卫生、安装程序安全性、发布通道、sidecar 绑定和发布门禁）、确定性源码归档、已签名安装程序构建、离线发布验证，以及针对每个涉及包的单元/集成测试。

---

<a id="architecture"></a>

## 架构

```text
GeDefenseCenter.exe / GeDefenseTray.exe        operator surfaces (unprivileged)
        │  operator broker session (Windows process token verified)
        ▼
127.0.0.1:17831                                authenticated loopback API
        │
        ▼
VGTGeDefense Windows Service (LocalSystem)     sovereign control plane
        ├── Defender / ASR / Firewall / WFP / App Control / Hardening
        ├── MHX EDR/XDR process and network correlation
        ├── Threat Intelligence feeds and WFP generation
        ├── Kinetic Defense burst correlation
        ├── Native traffic + local GeoIP/ASN map
        ├── Titan sensor, quarantine, owner policy and signed evidence
        └── HMAC/SHA-256 evidence ledger + Ed25519 checkpoints
```

- **零外部 Go 模块。**仅使用 Go 标准库和少量内部 Win32 包装器。
- **本地主机 UI。**嵌入式 Web UI 在本地提供；原生 Win32 宿主以 kiosk 模式启动已安装的 Chromium 浏览器（外部渲染器，无嵌入式 WebView2）。
- **无运行时 CDN。**所有 UI 资源、地图几何数据和 GeoIP/ASN CSV 均为本地资源。

---

<a id="system-requirements"></a>

## 系统要求

- Windows 11 x64（建议 build 22621 或更高版本）。
- 安装和策略配置需要本地管理员权限。Center 和 Tray 在操作员的非特权用户上下文中运行。
- Windows PowerShell 5.1 x64。
- 用于 Center UI 的本地已安装 Chromium 浏览器（Edge、Chrome 或 Brave）。
- 可选：用于地图的本地 GeoIP/ASN CSV（`data/geoip.csv` 及 `.sha256`）；若没有该文件，地图会显示“未加载”，产品其余部分仍可正常工作。

<a id="installation"></a>

## 安装

1. 从[发布页面](https://github.com/visiongaiatechnology/gedefensewin/releases)下载 `GeDefense-Setup-x64-v5.3.0.exe`。
2. 测量并检查工件：

   ```powershell
   Get-FileHash -Algorithm SHA256 .\GeDefense-Setup-x64-v5.3.0.exe
   Get-AuthenticodeSignature .\GeDefense-Setup-x64-v5.3.0.exe
   ```

   当前安装程序为**自签名**。只有在已经信任 VGT 证书的主机上，`Get-AuthenticodeSignature` 才会报告 `Valid`；对于其他所有主机，预期状态为 `NotTrusted`/`UnknownError`。测得的 SHA-256 必须与 `SHA256SUMS.txt` 以及发布版本的 `.sha256` sidecar 一致。
3. 以管理员身份运行安装程序。它会安装服务、Center、Tray、加固/XDR 资产以及证据/Titan 运行时数据根目录。
4. 启动 Center。Center 和 Tray 通过回环代理获取短期操作员会话；长期有效的主令牌是仅限 SYSTEM/Administrators 使用的紧急访问凭据。
5. 打开**保护中心**并遵循就绪指引。防御性默认值为 `OBSERVE_ONLY`；高强度的 Kinetic 关联（`ARMED_TI_CORRELATION`）需要操作员明确确认。

### 首次运行设置

安装或更新后首次启动 Center 时，会打开**首次运行助手**，直到服务器端完成设置。它引导操作员完成四个步骤：使用场景、建议、激活和验证：

1. **使用场景：**个人电脑、企业/办公、服务器/高风险或开发/构建。
2. **建议：****Enterprise Balanced** 是个人和企业用途的默认值；**Isolation** 还会禁用 USB 存储和 RDP，仅适用于相应的服务器/高风险环境。保护级别表说明 `OBSERVE`、`BALANCED` 和 `ISOLATION` 的含义。
3. **激活：**通过现有操作员 API 应用加固配置文件、完整性监控、Titan 策略和 MHX 策略协调。助手会显示错误和被拒绝的前提条件；绝不会假装应用成功。
4. **验证：**只有在 Defender、ASR（11/11 blocking）、受控文件夹访问、防火墙、保护策略和完整性监控均经过实际验证后，才能完成设置。

完成标记存储在服务器端并经过身份验证。其他浏览器、机器或会话不会重置它；新的程序版本可能要求重新设置。该向导不是授权绕过：变更仍绑定到本地操作员会话和服务器端确认短语。

### 重要操作说明

1. **本地主权：**控制平面仅在回环地址上运行；没有云控制平面，也不会向第三方静默发送遥测数据。
2. **防御性默认：**Kinetic Defense 以仅观察模式启动。
3. **Windows 审核策略：**入站 WFP 封禁遥测（事件 ID 5157）要求启用 Windows 筛选平台审核策略。
4. **卸载：**先导出相关证据，然后在配置允许的范围内移除受管保护策略。

### UI 语言

Center UI 提供**德语、英语、俄语和简体中文**。语言会根据系统/浏览器语言自动检测，并可随时通过页眉中的语言切换器更改。选择会保存在本地（cookie，不使用外部服务）。README 也以相同的四种语言提供。

---

<a id="local-sovereignty-and-privacy"></a>

## 本地主权与隐私

- 无外部云控制平面。
- 不会向第三方静默发送遥测数据。
- 威胁情报源从各自文档中载明的上游来源获取；情报源内容不会发送到其他任何地方。
- GeoIP/ASN 归属基于本地 CSV；IP 地址不会发送到外部地理位置服务。
- 证据和隔离数据保留在本地主机上并受 ACL 保护；证据导出是操作员的明确操作。

---

<a id="verification-and-trust"></a>

## 验证与信任

- **发布门禁：**Go race 测试套件（包括 `vgt_bundle`）、Go vet、`govulncheck -mode=binary`（0 个可达漏洞）、四个 Windows 构建、PowerShell 5.1 解析、前端安全不变量、CycloneDX SBOM、确定性源码归档、本地未签名的来源证明、分发卫生、安装程序安全性、发布通道卫生、sidecar 绑定和离线发布验证。
- **工件：**已签名安装程序、`.sha256` sidecar、JSON 发布 sidecar（实测字节/哈希/签名者以及 SBOM/来源证明绑定）、工件 SBOM、来源证明和 `SHA256SUMS.txt`。
- **签名状态：**当前安装程序使用**本地自签名身份**签名（无公共 CA、无 RFC 3161 时间戳、无在线撤销）。这是测试版的局限，也是记录在案的外部阻塞项——**不声称具有公共信任**。
- **来源证明：**有意采用未签名的本地形式；它证明构建输入/哈希以及源码归档的可复现性，而非远程证明。
- **CI：**当仓库打上标签且 CI 可用时，`.github/workflows/security-gate.yml` 会在 Windows 运行器上运行发布门禁。

---

<a id="licenses-and-attribution"></a>

## 许可证与归属

### 软件许可证

GeDefense Windows 源代码和文档依据 **GNU Affero General Public License v3.0 only（AGPL-3.0-only）** 许可——参见 [LICENSE](LICENSE)。名称、徽标和视觉品牌资产受 [TRADEMARKS.md](TRADEMARKS.md) 保护；第三方组件列于下文以及 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)、[LICENSE-MATRIX.md](LICENSE-MATRIX.md) 和 [DEPENDENCIES.md](DEPENDENCIES.md) 中。

### 世界地图几何数据 — jsVectorMap（MIT）

随附的本地世界地图几何数据（`src/GeDefense/windows/internal/server/web/world-merc.js`、`world-merc.js`）取自开源 **jsVectorMap** 项目，并与其墨卡托世界地图 **1.7.0** 版本一致：

- 项目：[themustafaomar/jsvectormap](https://github.com/themustafaomar/jsvectormap)
- 地图文件：[world-merc.js 1.7.0](https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world-merc.js)
- 许可证：[MIT License](https://github.com/themustafaomar/jsvectormap/blob/main/LICENSE) · Copyright © 2020 Mustafa Omar
- 完整许可证文本：[LICENSES/jsVectorMap-LICENSE](LICENSES/jsVectorMap-LICENSE)

本地文件被封装为 ES 模块；jsVectorMap 运行时库本身未被使用。

### GeoIP/ASN 数据 — iplocate 和 DB-IP（必须署名）

可选的本地 CSV（`data/geoip.csv`，包含在安装程序载荷中，不在公开 Git 仓库中）合并了公开的 IP 到国家/地区及 IP 到 ASN 数据。再分发和衍生作品必须署名：

- **ASN 数据：**[iplocate/ip-address-databases](https://github.com/iplocate/ip-address-databases) — 公开的 IP 到国家/地区和 IP 到 ASN 数据库，依据 **CC BY-SA 4.0** 许可（[许可证](https://creativecommons.org/licenses/by-sa/4.0/)）。一个具体示例：在网络 `1.0.4.0/22` 的条目中，ASN 为 `38803`，组织为 `Gtelecom Pty Ltd`，与随附 CSV 一致。来源署名：© iplocate/ip-address-databases contributors，CC BY-SA 4.0。
- **地理位置数据（先前/合并基础）：**DB-IP Lite——[DB-IP](https://db-ip.com)，**CC BY 4.0**（[许可证](https://creativecommons.org/licenses/by/4.0/)）。
- **状态：**随附 CSV 的确切上游快照日期和完整性尚未得到独立确认；SHA-256 sidecar 已根据实际字节更正。详情：[GEOIP_LICENSE_AND_DEPLOYMENT.md](GEOIP_LICENSE_AND_DEPLOYMENT.md)。
- 该数据不授予任何强制执行权限；国家/地区和 ASN 描述的是近似的网络注册来源，而非个人的实际位置。

### 其他第三方材料

- Go 标准库和工具链：Go/BSD 许可证；工具链哈希锁定于 [TOOLCHAINS.lock](TOOLCHAINS.lock)，不随附分发。
- Microsoft Windows、Defender、防火墙/WFP 和 App Control：Microsoft 许可证；不属于本仓库的一部分。
- 威胁情报源（Feodo Tracker、Spamhaus DROP、FireHOL、CINS、blocklist.de、Emerging Threats、IPsum、Tor 出口节点）：适用提供商条款；快照未随附分发。参见 [docs/THREAT-INTELLIGENCE.md](docs/THREAT-INTELLIGENCE.md)。
- Windows PowerShell 5.1：Microsoft 平台组件，不随附分发。

---

## 从源代码构建

要求：Windows 11 x64、Windows PowerShell 5.1 x64、Go **1.26.10**（参见 `TOOLCHAINS.lock`）以及适用于 Go race 检测器的 C 编译器。

```powershell
$env:GOTOOLCHAIN = 'go1.26.10'
# 1) deterministic source archive + SOURCE-MANIFEST
& .\build\Build-SourceRelease.ps1
# 2) full release gate + signed payload/installer + SBOM/provenance/sidecar/SHA256SUMS
& .\build\Build-GeDefenseStandalone.ps1
# 3) offline publish verification (no Git/VCS required with the explicit override)
& .\build\Publish-GitHubRelease.ps1 -VerifyOnly -AllowMissingVcs
```

签名身份必须预置到构建账户的证书存储中（私钥、代码签名 EKU）；`certificates/release-thumbprint.txt` 仅通过指纹引用该身份。私钥绝不提交到仓库。参见 [docs/BUILDING.md](docs/BUILDING.md)。

---

## 反馈与贡献

- 错误报告、误报报告和功能请求：[GitHub Issues](https://github.com/visiongaiatechnology/gedefensewin/issues)。
- 安全披露：请遵循 [SECURITY.md](SECURITY.md)——在修复方案可用之前，请勿公开可利用细节。
- 贡献：参见 [CONTRIBUTING.md](CONTRIBUTING.md) 和 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。适用[贡献者许可协议](CONTRIBUTOR-LICENSE-AGREEMENT.md)。

**感谢您测试 GeDefense Titan 测试版。**可复现的反馈——包括诚实的失败报告——正是让下一个版本更好的关键。
