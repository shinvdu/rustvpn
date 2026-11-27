# Authenticode 代码签名科普：为什么 Windows 需要一个“证书”

> 面向没有安全背景的读者。读完你应该能回答三个问题：
> 1. 签名到底解决了什么问题？
> 2. 为什么“自签”不算数，而 CA 签的证书才算？
> 3. 对 RustVPN 来说，签不签、什么时候签、花多少钱？

---

## 1. 从一个场景说起

你把 `rustvpn-0.2.0.msi` 发到 GitHub Releases。一个陌生用户下载后双击，Windows 弹出：

```
用户账户控制
你要允许此应用对你的设备进行更改吗？
程序名称: rustvpn-0.2.0.msi
发布者: 未知发布者        ← 问题在这里
```

用户有三个疑问，Windows 也无法替他回答：

1. **这文件真的是你发布的吗？** 会不会有人把官网的下载链接替换成了带木马的同名安装包？
2. **文件在传输过程中被改过吗？** 下载站、代理、被入侵的镜像都可能篡改。
3. **这个“发布者”能不能被我自己的安全策略信任？** 公司 IT 说“只允许装经过批准厂商的软件”。

哈希校验（SHA-256）只能部分回答第 2 个问题，而且前提是“你从可信渠道拿到了正确的哈希值”。**Authenticode 代码签名就是把“文件内容 + 发布者身份”打包成 Windows 能自动验证的东西。**

---

## 2. 签名到底签的是什么

### 2.1 第一步：哈希——文件的指纹

对文件内容做 SHA-256，得到一个 32 字节的摘要（比如 `a3f1…9c2e`）。

- 文件哪怕改动 1 个 bit，哈希就完全不同；
- 但哈希**不能**告诉你“是谁算的”，任何人都能算。

所以需要第二步。

### 2.2 第二步：非对称密钥——私钥签名，公钥验证

一对密钥：

| 密钥 | 谁持有 | 作用 |
|---|---|---|
| **私钥**（private key） | 只有你（或你的签名服务） | 生成签名 |
| **公钥**（public key） | 任何人都可以拿到 | 验证签名 |

签名过程（简化）：

```
签名 = Sign(私钥, 文件哈希)
```

验证过程：

```
文件哈希' = SHA-256(当前文件)
Verify(公钥, 签名, 文件哈希') == true ?
```

- 文件没被改 → 哈希一致 → 验证通过；
- 文件被改 → 哈希对不上 → 验证失败；
- 别人没有你的私钥 → 造不出能通过验证的签名。

### 2.3 第三步：把签名塞进文件

Authenticode 是微软的代码签名方案，签名（一个 PKCS#7 结构，里面包含文件哈希、证书链、时间戳）被附加在 PE 文件（`.exe`/`.dll`）或 MSI 包的结构里。Windows 的 `WinVerifyTrust` API 负责验证它。

```
┌──────────────────────────────┐
│  rustvpn-client-ui.exe       │
│  ┌────────────────────────┐  │
│  │ 程序代码 + 资源         │  │
│  ├────────────────────────┤  │
│  │ Authenticode 签名       │  │
│  │  · 文件哈希             │──┼──→ 用证书公钥验证
│  │  · 签名者证书链         │──┼──→ 链到受信任根
│  │  · 时间戳               │──┼──→ 证明“何时签的”
│  └────────────────────────┘  │
└──────────────────────────────┘
```

此时还剩最后一个漏洞：**验证方怎么知道这个公钥真的属于“RustVPN”，而不是攻击者自己生成的一对密钥？**

---

## 3. 公钥凭什么可信？——证书与 CA

### 3.1 证书 = 身份 + 公钥的绑定

证书（X.509）本质上是 CA 签发的一份声明：

> “公钥 `04:ab:…` 属于组织 `RustVPN Project`，有效期 2026-01-01 至 2027-01-01。”

CA（Certificate Authority，证书颁发机构，如 DigiCert、Sectigo、Certum）在签发前会核验你的身份：个人身份证件、公司营业执照、电话回拨、域名控制权等。核验通过，CA 用自己的私钥给你的公钥盖章。

### 3.2 信任链

Windows 预装了根证书（Root CA）列表。验证时从你的证书往上追：

```
Windows 内置根证书（受信任）
        │ 签名
        ▼
   中间 CA 证书
        │ 签名
        ▼
   RustVPN 的代码签名证书
        │ 签名
        ▼
   rustvpn-client-ui.exe
```

链条完整 + 每一环签名有效 + 证书未过期/未吊销 + 用途包含“代码签名”（EKU），Windows 就认为签名有效，并把证书里的主体名显示为“发布者”。

### 3.3 为什么自签不算数

用 `New-SelfSignedCertificate` 生成的证书，签发者就是它自己，链的尽头不在 Windows 受信任列表里。结果：

- `signtool verify /pa` 失败；
- UAC 仍显示“未知发布者”；
- SmartScreen 照样警告；
- 只有当你手动把这张根证书导入每台客户端的“受信任的根证书颁发机构”和“受信任的发布者”后，本机才认它。

所以自签适合：**企业内网、自己的测试机、MDM/GPO 统一推送信任根**。不适合公开下载。

---

## 4. Authenticode 在 Windows 里具体做了什么

### 4.1 时间戳：证书过期后签名还能用

签名时向 RFC 3161 时间戳服务器（如 `http://timestamp.digicert.com`）请求一份“盖章证明”：证明这个哈希在某个时刻已经存在。

有了时间戳，即使证书以后过期，**旧签名仍然长期有效**——验证方只需确认“签名时刻证书是有效的”。没有时间戳，证书一过期，已发布安装包的签名就会被判无效。这就是构建脚本默认带 `RUSTVPN_TIMESTAMP_URL` 的原因。

### 4.2 Windows 在哪些地方检查签名

| 位置 | 检查什么 | 未签名的表现 |
|---|---|---|
| **UAC** | 安装包/程序的签名主体 | “未知发布者” |
| **SmartScreen** | 文件 + 证书的信誉 | “Windows 已保护你的电脑”，需“更多信息 → 仍要运行” |
| **Smart App Control**（Win11） | 是否已签名/受信任 | 可能直接阻止运行 |
| **AppLocker / WDAC**（企业） | 发布者规则、哈希规则 | 按策略拒绝 |
| **Microsoft Defender** | 签名只是信号之一，主要看行为 | 未签名新文件更容易被启发式拦截 |
| **企业软件分发系统** | 发布者白名单 | 无法自动批准安装 |

注意：这些检查是**互相独立**的。签名只让你“有资格被信任”，并不保证一定放行；SmartScreen 还会看下载量和时间积累起来的名誉。

### 4.3 签名能保证什么、不能保证什么

**能保证：**

- 文件内容没有被篡改（改动即验签失败）；
- 签名者身份经过 CA 核验；
- 企业策略可以基于发布者做白名单；
- UAC 会显示真实发布者名，而不是“未知”。

**不能保证：**

- 程序本身没有漏洞或恶意行为——签名只证明“谁发布”，不证明“安全”；
- 私钥不会泄露（2020 年 SolarWinds 事件就是签名流程被入侵）；
- 没有管理员权限的人不能绕过——签名不是权限模型；
- 不会加密你的流量、不会防止抓包，与 VPN 的加密毫无关系。

一句话：**签名是“身份证 + 封条”，不是“安检”。**

---

## 5. 证书的种类与成本

| 类型 | 签发者 | 公开用户默认信任 | SmartScreen | 典型成本 |
|---|---|---|---|---|
| 自签证书 | 你自己 | ❌ | 仍警告 | 0 |
| OV（Organization Validation） | 公共 CA | ✅ | 需要时间积累信誉 | 约 $200–400/年 + 硬件 token |
| EV（Extended Validation） | 公共 CA | ✅ | **立即**有信誉 | 约 $400–700/年 + 硬件 token |
| 云签名（DigiCert KeyLocker、SSL.com eSigner 等） | 公共 CA | ✅ | 同 OV | 按年/按签名量计费 |
| Azure Trusted Signing | 微软 | ✅（WinVerifyTrust 信任） | 同 OV/使用情况而定 | 约 $10/月起（含额度） |
| SignPath Foundation | SignPath（OSS 赞助） | ✅ | 同 OV | 开源项目免费 |
| Certum Open Source Code Signing | Certum | ✅ | 同 OV | 约 €100/年起（开源项目） |

> 价格和资格随年份/地区/渠道变化，一律以 CA 官网为准。

### 5.1 为什么 2023 年之后买不到“直接用的 PFX 文件”了

CA/Browser Forum（浏览器和 CA 共同制定的基线要求）从 2023 年 6 月起规定：**代码签名私钥必须存放在满足 FIPS 140-2 Level 2 或 Common Criteria EAL4+ 的硬件中**。

实际表现：

- 你收到的是一枚 USB token（如 SafeNet eToken）或云端 HSM 账户；
- `signtool` 只把“文件哈希”发给 token，token 内部完成签名，私钥永远不出硬件；
- 因此“把 `.pfx` 拷到构建机”这种老做法，对主流公共 CA 已经不合规。

### 5.2 开源项目为什么可以零成本

- **SignPath Foundation**：为符合条件的开源项目免费提供签名服务，密钥由 SignPath 托管，CI 里调用；
- **Certum**：有专门的开源代码签名证书，价格远低于商业 OV；
- 代价是审核（项目必须公开、OSI 许可证、活跃维护），且证书主体/用途受限。

---

## 6. 落到 RustVPN

仓库里已经完成了签名侧的工程工作，缺的只是“证书”这个外部输入：

| 位置 | 作用 |
|---|---|
| `packaging/windows/sign-artifacts.ps1` | 用证书签 GUI、守护进程、MSI；没有证书时**验证它们确实未签名**并写 `UNSIGNED.txt` |
| `packaging/windows/build-msi.ps1` | 打包前签名可执行文件，链接后签名 MSI，逐个 `signtool verify /pa` |
| `docs/windows-install.md` §6 | 环境变量与验收说明 |
| `crates/rustvpn-client-gui/src/daemon_identity.rs` | GUI 在发送口令前校验守护进程的 Authenticode 发布者，要求主体含 `rustvpn`（M6 后应改为固定证书指纹） |

签名需要提供的三个输入（任选其一）：

```powershell
# 方式 A：证书在当前用户证书存储里（token / 云签名服务通常是这种）
$env:RUSTVPN_SIGN_CERT_THUMBPRINT = '<SHA-1 thumbprint>'

# 方式 B：PFX 文件（自签或非主流渠道）
$env:RUSTVPN_SIGN_CERT_FILE = 'D:\secure\rustvpn.pfx'
$env:RUSTVPN_SIGN_CERT_PASSWORD = '<password>'

# 公共时间戳，默认就是 DigiCert
$env:RUSTVPN_TIMESTAMP_URL = 'http://timestamp.digicert.com'
```

构建后验收入口：

```powershell
signtool verify /pa /v dist\windows\rustvpn-client-ui.exe
signtool verify /pa /v dist\windows\<name>.msi
# 签名成功时：dist\windows\UNSIGNED.txt 不存在，SIGNING.txt 写明已签名
```

两个项目相关的坑：

1. **证书主体必须含 “RustVPN”**，否则便携版“签名守护进程”信任规则不放行；正式发布时应改成固定证书 thumbprint（WIN-019 的修复方向）。
2. **自签证书要装信任根**。只签不改信任，`WinVerifyTrust` 仍失败，GUI 会把守护进程视为未签名（`Program Files\RustVPN` 下的安装路径是例外）。
3. **Wintun 驱动不需要你签**：它是上游 WireGuard 已签名的组件；Windows 内核驱动签名是另一套机制（Microsoft 硬件开发者中心 / attestation signing），与 Authenticode 不是一回事。

---

## 7. 什么时候可以不签

| 场景 | 结论 |
|---|---|
| 本地开发、自己测试、虚拟机验收 | 不需要。未签名构建已明确标记，不要伪装成已签名 |
| 给少数朋友/内网手动安装 | 可以暂缓，但每次要教用户点“仍要运行” |
| 企业批量部署 | 基本必须，否则 AppLocker/WDAC/Intune 策略会拒绝 |
| 公开发布 / 生产分发 | 实际必须；开源项目可用 SignPath/Certum 把成本降到 0 或很低 |

法律没有任何一条要求代码签名。它约束的是**用户和企业的信任策略**：不签，等于把“是否信任”的决定权交给每一个看到红色警告的用户。

---

## 8. 常见问题（FAQ）

**Q1：证书过期了，已经发的安装包还能装吗？**
能。只要签名时带了时间戳，Windows 会以签名时刻判断证书有效性。但没有时间戳的签名，证书一过期就失效。

**Q2：签了名杀毒软件就不报了吗？**
不保证。签名减少的是“未知发布者”类拦截和策略拒绝；行为检测、启发式扫描仍可能误报，签名者信誉差时也会被拉黑。

**Q3：别人偷了我的私钥会怎样？**
他可以签出看起来“由你发布”的恶意程序。应对手段是向 CA 申请吊销证书（CRL/OCSP），但已经分发出去的旧副本、离线机器可能仍会信任。因此现代证书要求私钥放在硬件 token/HSM 里，且签发流程要有审批。

**Q4：既然能算哈希，为什么还要证书？**
哈希只能证明“内容一致”，但“正确的哈希值”本身也需要可信分发。证书把信任锚定到操作系统预装的根证书，不需要用户手动比对哈希。

**Q5：为什么我只能拿到 USB token，不能要一个 .pfx？**
2023 年 CA/B 规则要求私钥驻留 FIPS 140-2 L2 硬件。PFX 文件可以随意复制，无法满足该要求。云签名服务用 HSM 达到同样的效果。

**Q6：签 EXE 和签 MSI 是一回事吗？**
同属 Authenticode，但分别签：EXE/DLL 的签名影响 UAC 显示、Smart App Control 和 GUI 的发布者校验；MSI 的签名影响安装器的 UAC 发布者和企业分发策略。发布时两者都要签。

**Q7：签名会让程序变慢或变大吗？**
几乎不会。签名只增加几 KB 数据，验证发生在启动/安装时，耗时毫秒级。

**Q8：开源项目一定要花钱吗？**
不一定。SignPath Foundation 对符合条件的公开开源项目免费；Certum 也有廉价 OSS 证书。审核门槛主要是项目公开、许可证合规、持续维护。

**Q9：没有签名，别人还能装得进去吗？**
绝大多数情况能，只是多几步提示：

- 浏览器下载 MSI/EXE → SmartScreen 红屏 → “更多信息”→“仍要运行”；
- UAC 显示“未知发布者” → 点“是”；
- 从 U 盘/本地拷贝的文件通常没有 Mark-of-the-Web，不触发 SmartScreen，只剩 UAC 提示；
- 安装后的用户态服务不要求签名（只有内核驱动强制签）。

真正的例外：

- 企业 AppLocker/WDAC/Intune 策略禁止未签名程序；
- Windows 11 开启 Smart App Control 的全新安装机器可能直接拦截，且关闭 SAC 基本不可逆；
- 本项目 Release 版便携模式只接受 `Program Files\RustVPN` 下的未签名守护进程，便携未签名守护进程会被 GUI 身份校验拒绝（debug 版例外）。

另外，MSI 的 SmartScreen/UAC 看的是 **MSI 文件本身**的签名，MSI 内 EXE 的签名是运行时另外检查的，所以发布时要两者都签。

---

## 9. 术语表

| 术语 | 含义 |
|---|---|
| **Authenticode** | 微软的代码签名格式/机制，用于 PE 和 MSI |
| **哈希 / 摘要** | 对内容计算出的固定长度指纹（本项目用 SHA-256） |
| **数字签名** | 用私钥对哈希生成、用公钥验证的密码学证明 |
| **CA** | 证书颁发机构，负责核验身份并签发证书 |
| **X.509 证书** | 绑定“身份”与“公钥”的标准数据结构 |
| **信任链 / 根证书** | 从操作系统预置根证书一路验证到签名者证书 |
| **EKU** | 证书用途扩展；代码签名证书必须含 Code Signing EKU |
| **RFC 3161 时间戳** | 由时间戳机构出具的“某时刻已存在”的证明 |
| **WinVerifyTrust** | Windows 验证 Authenticode 签名的 API |
| **SmartScreen** | Windows 基于文件/证书信誉的下载与运行拦截 |
| **OV / EV** | 组织验证 / 扩展验证级别的公共证书 |
| **HSM / token** | 硬件安全模块 / USB 密钥，私钥不可导出 |
| **吊销（CRL/OCSP）** | CA 提前作废证书的机制 |

---

## 10. 附录：Windows 代码签名时间线（为什么感觉“以前不用”）

普通桌面应用**从来没有**被 Windows 全局强制要求 Authenticode 证书。变的是“不签名的摩擦”和“买证书的方式”；驱动则是另一条更严格的线。

| 时间 | 事件 | 影响 |
|---|---|---|
| 1996–1998 | Authenticode 随 IE4 / Windows 98 出现 | 可选功能，几乎没人用 |
| 2007 | Windows Vista 的 UAC 显示“未知发布者” | 普通应用能装，但用户开始看到警告 |
| 2007 | Vista x64 强制内核驱动签名 | **驱动**从此必须签 |
| 2009 | Windows 7 引入 AppLocker | 企业可自选“只允许签名程序” |
| 2012 | Windows 8 引入 SmartScreen 应用信誉 | 下载的未知 EXE/MSI 开始被拦截提示 |
| 2015 | Windows 10 / Edge 默认启用 SmartScreen | 拦截面扩大到所有下载文件 |
| 2016 | Windows 10 1607 起，新内核驱动必须微软签名 | 驱动门槛进一步收紧 |
| 2017 | CA/B 代码签名基线要求生效 | 证书签发开始规范化 |
| 2021–2022 | Windows 11 发布；22H2 引入 Smart App Control | 全新安装的 Win11 可能直接拦截未签名/低信誉程序 |
| 2023-06-01 | CA/B 强制私钥存放在硬件 token / HSM | 改变的是怎么买证书，不是“开始要证书” |
| 2024– | Microsoft 推广 Azure Trusted Signing，企业策略普及 | 签名成为公开分发的事实标准 |

结论：

1. 普通 EXE/MSI 至今没有系统级“无证书禁止运行”的规则，例外是开启 Smart App Control 的 Windows 11（默认仅在全新安装时开启）。
2. 以前“不需要证书”的体验是真实的：本地/内网/USB 分发的文件没有 Mark-of-the-Web，不触发 SmartScreen；UAC 警告可以手动放行。
3. 真正的转折点是 2012 年 Windows 8 的 SmartScreen：从“警告可跳过”变成“默认劝退 + 信誉系统”。2022 年的 Smart App Control 把它推到“可能直接不让跑”。
4. 驱动是另一条线：Windows Vista x64（2007）起强制签名，2016 年起新驱动还需微软签发；Wintun 已由上游 WireGuard 签好。

---

## 11. 延伸阅读

- [Windows 安装与签名流程](windows-install.md) —— 本项目的操作手册
- [Windows 客户端状态](windows-client-status.md) —— WIN-019 当前状态
- `docs/windows-client-dev/issues/WIN-019-authenticode-signing-cert.md` —— 签名阻塞项详情
- Microsoft Learn: *Authenticode* / *WinVerifyTrust* / *SmartScreen*
- CA/Browser Forum: *Baseline Requirements for the Issuance and Management of Publicly-Trusted Code Signing Certificates*