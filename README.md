## 0. 导读与规范 (Introduction & Standards)

- **红队定义与目标**: 红队 vs 渗透测试的区别
    
- **ROE (交战规则)**: 法律边界、范围界定、禁止事项
    
- **OPSEC (行动安全)**:
    
    - 攻击源隐藏 (Tor, VPN, Proxychains)
        
    - 身份伪装与数字足迹擦除
        
    - 时间控制 (Jitter, Sleep)
        
- **MITRE ATT&CK 映射**: 战术、技术与流程 (TTPs) 速查
    

## 1. 基础设施建设 (Infrastructure)

### 1.1 C2 框架 (Command & Control)

- **商业/闭源 C2**: Cobalt Strike (Profile定制, 插件开发), Brute Ratel
    
- **开源/现代 C2**:
    
    - Sliver (搭建, 证书伪造, 流量混淆)
        
    - Havoc (配置, Payload生成)
        
    - Mythic (Agent开发)
        
- **C2 隐蔽技术**:
    
    - Domain Fronting (域前置)
        
    - Redirectors (重定向器: Nginx/Apache 反代)
        
    - CDN 隐藏与云函数转发
        
    - 流量特征修改 (Malleable C2 Profile 编写指南)
        

### 1.2 武器化环境 (Weaponization)

- **开发环境**: VS Code, Go, Rust, MinGW 配置
    
- **编译流水线 (CI/CD)**: 自动化构建免杀 Payload
    
- **钓鱼基础设施**: Gophish 搭建, 邮件服务器配置 (SPF/DKIM/DMARC)
    

## 2. 侦察与信息收集 (Reconnaissance)

### 2.1 OSINT (开源情报)

- **企业画像**: 组织架构, 员工社交媒体 (LinkedIn), 技术栈指纹
    
- **代码泄露**: GitHub/GitLab 敏感信息搜索
    
- **历史数据**: Whois, DNS 历史, 泄露数据库 (社工库) 利用
    

### 2.2 资产发现 (Asset Discovery)

- **子域名枚举**: 爆破, 证书透明度 (CT) 日志
    
- **端口与服务**: Masscan/Nmap 策略, 边缘资产识别
    
- **云资产发现**: S3 存储桶, Azure Blob 泄漏
    

## 3. 初始访问 (Initial Access)

### 3.1 社会工程学 (Social Engineering)

- **钓鱼攻击 (Phishing)**: Office 宏, LNK 文件, CHM 电子书
    
- **水坑攻击 (Watering Hole)**: 针对性网站挂马
    
- **即时通讯钓鱼**: 微信/钉钉/Slack 投递
    

### 3.2 外部边界突破

- **Web 漏洞**: 注入, 反序列化, 文件上传 (重点关注入口点)
    
- **已知漏洞利用 (N-day)**: VPN, Exchange, RDP, OA 系统漏洞
    
- **弱口令与凭证填充**: 针对 VPN/VDI/Mail 的密码喷洒 (Password Spraying)
    

## 4. 防御规避与免杀 (Defense Evasion)

### 4.1 静态免杀 (Static Evasion)

- **Shellcode 加载器**:
    
    - 分离免杀 (Loader + Payload)
        
    - 异或/AES 加密
        
    - 隐写术 (图片/音频藏码)
        
- **源码级混淆**:
    
    - Go/Rust 混淆 (Garble, Obfuscator-LLVM)
        
    - 签名伪造与白名单利用 (LOLBins)
        

### 4.2 动态对抗 (Dynamic/Runtime Evasion)

- **内存扫描规避**:
    
    - 堆栈欺骗 (Stack Spoofing)
        
    - 内存加密 (Sleep Obfuscation/Ekko)
        
- **API Hooking 绕过**:
    
    - 直接系统调用 (Direct Syscalls)
        
    - 间接系统调用 (Indirect Syscalls)
        
    - Unhooking 技术
        
- **沙箱检测**: 检查 CPU 核心, 运行时间, 鼠标移动
    

## 5. 权限提升与持久化 (PrivEsc & Persistence)

### 5.1 Windows

- **提权**: 内核漏洞, 服务配置错误, AlwaysInstallElevated, Token 窃取
    
- **持久化**: 计划任务, 注册表启动项, 服务, DLL 劫持, WMI 订阅, COM 劫持
    

### 5.2 Linux

- **提权**: SUID, Kernel Exploits, Cron Jobs, Sudo 配置错误
    
- **持久化**: Cron, SSH Keys, Shell 配置文件 (.bashrc), Systemd 服务
    

### 5.3 macOS (红队新兴领域)

- **提权与持久化**: LaunchDaemons, LaunchAgents, TCC 绕过
    

## 6. 域渗透与横向移动 (AD & Lateral Movement)

### 6.1 信息收集

- **域环境探测**: BloodHound 分析, AdFind, LDAP 查询, SPN 扫描
    

### 6.2 凭证获取

- **内存凭证**: Mimikatz (LSASS Dump 及其对抗), RdpHijack
    
- **凭证存储**: 浏览器密码, WiFi 密码, 注册表凭证
    

### 6.3 横向移动技术

- **协议利用**: SMB (PsExec), WMI, WinRM, DCOM
    
- **哈希传递**: PtH (Pass the Hash), PtT (Pass the Ticket)
    
- **漏洞利用**: ZeroLogon, PetitPotam, NTLM Relay
    

### 6.4 域权限维持

- **黄金/白银票据 (Golden/Silver Ticket)**
    
- **AdminSDHolder**
    
- **DCShadow**
    
- **Skeleton Key**
    

## 7. 云原生与容器安全 (Cloud & Container)

- **AWS/Azure 攻防**: IAM 权限滥用, Lambda 后门, EC2 元数据窃取
    
- **Kubernetes (K8s)**: Pod 逃逸, API Server 未授权访问, Etcd 敏感信息
    
- **Docker**: 容器逃逸, 镜像投毒
    

## 8. 数据渗出 (Exfiltration)

- **隐蔽信道**: DNS 隧道, ICMP 隧道
    
- **Web 服务**: 利用 Google Drive, Dropbox, OneDrive API 传数据
    
- **流量伪装**: 伪装成 Windows Update 流量
    

## 9. 报告与复盘 (Reporting)

- **报告模板**: 发现摘要, 攻击路径图, 风险评级, 修复建议
    
- **复盘会议**: 攻击时间线 vs 防守方检测时间线 (TtD/TtR 分析)
    

## 10. 常用工具库 (Arsenal)

- **扫描**: Nmap, Masscan, Nuclei
    
- **Web**: Burp Suite (插件集), Yakit
    
- **AD**: Impacket, Rubeus, Certify, SharpHound
    
- **C2**: Cobalt Strike, Sliver, Havoc
    
- **免杀**: ScareCrow, Go-Bypass
