<div align="center">

<img width="256" height="256" alt="GeDefense Windows" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />

# VGT GeDefense Titan

### 主权终端安全中心与 Kinetic 威胁防御体系

[English](README.md) · [Deutsch](README.de.md) · [Русский](README.ru.md) · **中文**

[![许可证](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](LICENSE)
[![版本](https://img.shields.io/badge/Version-5.3.0-orange?style=for-the-badge)](https://github.com/visiongaiatechnology/gedefensewin/releases)
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

> [!IMPORTANT]
> **安装程序更新（5.3.0）：**此前的自签名 PowerShell 引导程序在全新 Windows 系统上可能因 VGT 证书不受信任而失败。本版本现使用品牌化的 **Inno Setup 安装程序**，在您接受许可证后自动导入测试版证书——无需再手动处理证书。
>
> **[下载 GeDefense Windows 5.3.0 安装程序](https://github.com/visiongaiatechnology/gedefensewin/releases/download/v5.3.0/GeDefense-Setup-x64-v5.3.0.exe)**

## 🌐 GeDefense 宇宙

GeDefense 是一套本地优先的安全架构，覆盖 Linux、Windows、Android 和 WordPress。所有同系项目遵循同一理念：本地控制、诚实可见性、无静默遥测。

| 项目 | 方向 |
| --- | --- |
| [![Android TV](https://img.shields.io/badge/Android_TV-3DDC84?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense_androidtv) **GeDefense TV** | Android TV / Google TV 安全控制台：回环 VPN、流量地图、XDR-Light 与可逆 Kinetic-Lite 遏制。 |
| [![Linux](https://img.shields.io/badge/Linux-D4AF37?style=flat-square&logo=linux&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefense) **GeDefense Linux** | 内核级网络防御：eBPF/XDP 执行、L7 WAF、带签名证据的主机 XDR、可逆加固（Rust/Go，完全本地）。 |
| [![Windows](https://img.shields.io/badge/Windows-8B5CF6?style=flat-square&logo=windows&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewin) **GeDefense Windows** *（本仓库）* | 本地自主的 Windows 11 安全控制台：Defender/ASR/WFP/App Control、加固、MHX EDR/XDR、本地威胁情报与 HMAC 链式证据。 |
| [![Android](https://img.shields.io/badge/Android-22D3EE?style=flat-square&logo=android&logoColor=0B1220)](https://github.com/visiongaiatechnology/gedefenseandroid) **GeDefense Android** | 原生 Android 安全平台：本地 VPN 执行、端点遥测、XDR/EDR 关联、威胁情报、应用风险分析与加密证据。 |
| [![WordPress](https://img.shields.io/badge/WordPress-1F8FFF?style=flat-square&logo=wordpress&logoColor=ffffff)](https://github.com/visiongaiatechnology/gedefensewp) **GeDefense WordPress** | AGPL-3.0 开源核心 WordPress 套件：ZEUS WAF、AEGIS 深度包检测、TRINITY XDR、ThroneGuard 锁定与 HADES 后台隐藏。 |


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
