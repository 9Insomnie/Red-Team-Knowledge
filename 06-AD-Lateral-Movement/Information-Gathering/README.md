# 域渗透与横向移动 - 信息收集

## 域环境探测

### BloodHound分析

#### BloodHound数据采集
```powershell
# bloodhound_collection.ps1

# 安装SharpHound
# 下载地址: https://github.com/BloodHoundAD/SharpHound

# 基本数据收集
.\SharpHound.exe -c All

# 收集特定信息
.\SharpHound.exe -c Session,ACL,ObjectProps,LocalGroup,PSRemote

# 使用不同的收集方法
.\SharpHound.exe -c All --LdapUsername domainuser --LdapPassword password
.\SharpHound.exe -c All --LdapPort 636 --SecureLdap

# 排除特定域控制器
.\SharpHound.exe -c All --ExcludeDC DC01.corp.local

# 指定域
.\SharpHound.exe -c All --Domain corp.local

# 使用JSON输出
.\SharpHound.exe -c All --OutputDirectory C:\temp\bh_data --OutputPrefix corp_bh

# 增量收集
.\SharpHound.exe -c Session --RefreshInterval 1
```

#### PowerShell BloodHound采集
```powershell
# SharpHound-PS.ps1

# 导入模块
Import-Module .\SharpHound.psm1

# 运行BloodHound收集
Invoke-BloodHound -CollectionMethod All

# 收集会话信息
Invoke-BloodHound -CollectionMethod Session

# 收集ACL信息
Invoke-BloodHound -CollectionMethod ACL

# 收集本地管理员信息
Invoke-BloodHound -CollectionMethod LocalGroup

# 组合收集
$CollectionMethods = @("Session", "LocalGroup", "ACL", "ObjectProps", "PSRemote")
Invoke-BloodHound -CollectionMethod $CollectionMethods

# 指定域
Invoke-BloodHound -CollectionMethod All -Domain corp.local

# 使用凭据
$SecPassword = ConvertTo-SecureString 'password' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('CORP\user', $SecPassword)
Invoke-BloodHound -CollectionMethod All -Credential $Cred
```

#### BloodHound数据分析脚本
```python
# bloodhound_analyzer.py
import json
import networkx as nx
from neo4j import GraphDatabase
import pandas as pd
from datetime import datetime

class BloodHoundAnalyzer:
    def __init__(self, neo4j_uri="bolt://localhost:7687", neo4j_user="neo4j", neo4j_password="password"):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        
    def get_domain_info(self):
        """获取域基本信息"""
        query = """
        MATCH (d:Domain)
        RETURN d.name as domain_name, d.objectid as domain_sid, 
               d.functionallevel as functional_level
        """
        with self.driver.session() as session:
            result = session.run(query)
            return pd.DataFrame([dict(record) for record in result])
    
    def get_high_value_targets(self):
        """获取高价值目标"""
        query = """
        MATCH (n)
        WHERE n.highvalue = true
        RETURN n.name as name, n.objectid as sid, labels(n) as type
        ORDER BY n.name
        """
        with self.driver.session() as session:
            result = session.run(query)
            return pd.DataFrame([dict(record) for record in result])
    
    def get_kerberoastable_accounts(self):
        """获取可Kerberoasting的账户"""
        query = """
        MATCH (u:User)
        WHERE u.hasspn = true
        RETURN u.name as username, u.serviceprincipalnames as spns, 
               u.pwdlastset as pwd_last_set, u.lastlogon as last_logon
        ORDER BY u.name
        """
        with self.driver.session() as session:
            result = session.run(query)
            return pd.DataFrame([dict(record) for record in result])
    
    def get_asreproastable_accounts(self):
        """获取可AS-REP Roasting的账户"""
        query = """
        MATCH (u:User)
        WHERE u.dontreqpreauth = true
        RETURN u.name as username, u.pwdlastset as pwd_last_set,
               u.lastlogon as last_logon
        ORDER BY u.name
        """
        with self.driver.session() as session:
            result = session.run(query)
            return pd.DataFrame([dict(record) for record in result])
    
    def get_unconstrained_delegations(self):
        """获取无约束委派"""
        query = """
        MATCH (c:Computer)
        WHERE c.unconstraineddelegation = true
        RETURN c.name as computer_name, c.operatingsystem as os,
               c.enabled as enabled
        ORDER BY c.name
        """
        with self.driver.session() as session:
            result = session.run(query)
            return pd.DataFrame([dict(record) for record in result])
    
    def get_shortest_paths_to_da(self):
        """获取到域管理员的最短路径"""
        query = """
        MATCH (g:Group)
        WHERE g.objectid ENDS WITH "-512"
        MATCH p = shortestPath((n:User) - [*1..5] -> (g))
        WHERE n <> g
        RETURN n.name as user, length(p) as path_length,
               [node in nodes(p) | labels(node)] as node_types
        ORDER BY path_length
        LIMIT 20
        """
        with self.driver.session() as session:
            result = session.run(query)
            return pd.DataFrame([dict(record) for record in result])
    
    def get_local_admin_rights(self):
        """获取本地管理员权限"""
        query = """
        MATCH (u:User)-[r:AdminTo]->(c:Computer)
        RETURN u.name as user, c.name as computer,
               r.isacl as is_acl, r.islocal as is_local
        ORDER BY c.name, u.name
        """
        with self.driver.session() as session:
            result = session.run(query)
            return pd.DataFrame([dict(record) for record in result])
    
    def get_outbound_control_rights(self):
        """获取出站控制权限"""
        query = """
        MATCH (n)-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|AllExtendedRights]->(m)
        WHERE n <> m
        RETURN n.name as source, type(r) as right, m.name as target,
               labels(n) as source_type, labels(m) as target_type
        ORDER BY n.name
        """
        with self.driver.session() as session:
            result = session.run(query)
            return pd.DataFrame([dict(record) for record in result])
    
    def find_attack_paths(self, target_user):
        """查找特定用户的攻击路径"""
        query = f"""
        MATCH (target:User {{name: "{target_user}"}})
        MATCH p = shortestPath((source:User) - [*1..6] -> (target))
        WHERE source <> target
        RETURN source.name as source_user, length(p) as path_length,
               [rel in relationships(p) | type(rel)] as relationships,
               [node in nodes(p) | labels(node)] as node_labels
        ORDER BY path_length
        LIMIT 10
        """
        with self.driver.session() as session:
            result = session.run(query)
            return pd.DataFrame([dict(record) for record in result])
    
    def generate_attack_report(self):
        """生成攻击报告"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'domain_info': self.get_domain_info(),
            'high_value_targets': self.get_high_value_targets(),
            'kerberoastable_accounts': self.get_kerberoastable_accounts(),
            'asreproastable_accounts': self.get_asreproastable_accounts(),
            'unconstrained_delegations': self.get_unconstrained_delegations(),
            'shortest_paths_to_da': self.get_shortest_paths_to_da(),
            'local_admin_rights': self.get_local_admin_rights(),
            'outbound_control_rights': self.get_outbound_control_rights()
        }
        
        return report
    
    def close(self):
        """关闭数据库连接"""
        self.driver.close()

# 使用示例
analyzer = BloodHoundAnalyzer()
report = analyzer.generate_attack_report()

# 保存报告
with open('bloodhound_report.json', 'w') as f:
    json.dump({k: v.to_dict('records') if hasattr(v, 'to_dict') else v 
               for k, v in report.items()}, f, indent=2, default=str)

analyzer.close()
```

### AdFind工具使用

#### 基础AdFind命令
```bash
# adfind_commands.sh

# 安装AdFind
# 下载地址: https://www.joeware.net/freetools/tools/adfind/

# 基本域信息
adfind -default -f "objectcategory=domain" name dnsroot ncdname

# 获取域控制器
adfind -default -f "objectcategory=computer" -f "userAccountControl:AND:=8192" name operatingSystem

# 获取所有用户
adfind -default -f "objectcategory=user" name samaccounttype pwdlastset lastlogon

# 获取所有计算机
adfind -default -f "objectcategory=computer" name operatingsystem lastlogon

# 获取所有组
adfind -default -f "objectcategory=group" name grouptype member

# 获取组织单位
adfind -default -f "objectcategory=organizationalUnit" name distinguishedName

# 获取GPO
adfind -default -f "objectcategory=groupPolicyContainer" displayname
```

#### 高级AdFind查询
```bash
# adfind_advanced.sh

# 查找Kerberoastable账户
adfind -default -f "(&(objectcategory=user)(serviceprincipalname=*))" serviceprincipalname samaccountname

# 查找AS-REP Roastable账户
adfind -default -f "(&(objectcategory=user)(useraccountcontrol:AND:=4194304))" samaccountname

# 查找无约束委派
adfind -default -f "(&(objectcategory=computer)(useraccountcontrol:AND:=524288))" name

# 查找约束委派
adfind -default -f "(&(objectcategory=user)(msds-allowedtodelegateto=*))" samaccountname msds-allowedtodelegateto

# 查找LAPS启用账户
adfind -default -f "(&(objectcategory=computer)(ms-mcs-admpwd=*))" name ms-mcs-admpwd ms-mcs-admpwdexpirationtime

# 查找高价值组
adfind -default -f "(&(objectcategory=group)(admincount=1))" name member

# 查找非活动用户（90天未登录）
adfind -default -f "(&(objectcategory=user)(lastlogontimestamp<=$((($(date +%s) - 7776000) * 10000000)))" samaccountname lastlogontimestamp

# 查找密码永不过期的用户
adfind -default -f "(&(objectcategory=user)(useraccountcontrol:AND:=65536))" samaccountname

# 查找具有SPN的管理员
adfind -default -f "(&(objectcategory=user)(admincount=1)(serviceprincipalname=*))" samaccountname serviceprincipalname
```

#### AdFind自动化脚本
```python
# adfind_automation.py
import subprocess
import json
import csv
from datetime import datetime

class AdFindAutomation:
    def __init__(self, domain=None, username=None, password=None):
        self.domain = domain
        self.username = username
        self.password = password
        self.base_command = ["adfind"]
        
        if domain:
            self.base_command.extend(["-h", domain])
        if username and password:
            self.base_command.extend(["-u", username, "-up", password])
    
    def run_adfind_query(self, query_filter, attributes=None):
        """运行AdFind查询"""
        command = self.base_command.copy()
        command.extend(["-default", "-f", query_filter])
        
        if attributes:
            command.extend(attributes)
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return self.parse_adfind_output(result.stdout)
            else:
                print(f"[!] AdFind error: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print("[!] AdFind query timed out")
            return []
    
    def parse_adfind_output(self, output):
        """解析AdFind输出"""
        entries = []
        current_entry = {}
        
        lines = output.strip().split('\n')
        for line in lines:
            if line.startswith('>dn: '):
                if current_entry:
                    entries.append(current_entry)
                current_entry = {'dn': line[4:]}
            elif line.startswith('>') and current_entry:
                if ':' in line:
                    key, value = line[1:].split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key in current_entry:
                        if isinstance(current_entry[key], list):
                            current_entry[key].append(value)
                        else:
                            current_entry[key] = [current_entry[key], value]
                    else:
                        current_entry[key] = value
        
        if current_entry:
            entries.append(current_entry)
        
        return entries
    
    def get_domain_users(self):
        """获取域用户"""
        query_filter = "(objectcategory=user)"
        attributes = ["samaccountname", "userprincipalname", "pwdlastset", "lastlogon", "useraccountcontrol"]
        
        users = self.run_adfind_query(query_filter, attributes)
        
        # 处理用户数据
        processed_users = []
        for user in users:
            processed_user = {
                'username': user.get('samaccountname', ''),
                'upn': user.get('userprincipalname', ''),
                'pwd_last_set': self.convert_ad_timestamp(user.get('pwdlastset', '0')),
                'last_logon': self.convert_ad_timestamp(user.get('lastlogon', '0')),
                'status': 'Enabled' if int(user.get('useraccountcontrol', '0')) & 2 == 0 else 'Disabled'
            }
            processed_users.append(processed_user)
        
        return processed_users
    
    def get_domain_computers(self):
        """获取域计算机"""
        query_filter = "(objectcategory=computer)"
        attributes = ["name", "operatingsystem", "operatingsystemversion", "lastlogon", "useraccountcontrol"]
        
        computers = self.run_adfind_query(query_filter, attributes)
        
        processed_computers = []
        for computer in computers:
            processed_computer = {
                'name': computer.get('name', ''),
                'os': computer.get('operatingsystem', ''),
                'os_version': computer.get('operatingsystemversion', ''),
                'last_logon': self.convert_ad_timestamp(computer.get('lastlogon', '0')),
                'unconstrained_delegation': bool(int(computer.get('useraccountcontrol', '0')) & 524288)
            }
            processed_computers.append(processed_computer)
        
        return processed_computers
    
    def get_domain_groups(self):
        """获取域组"""
        query_filter = "(objectcategory=group)"
        attributes = ["samaccountname", "grouptype", "member", "description"]
        
        groups = self.run_adfind_query(query_filter, attributes)
        
        processed_groups = []
        for group in groups:
            processed_group = {
                'name': group.get('samaccountname', ''),
                'type': self.decode_group_type(int(group.get('grouptype', '0'))),
                'members': group.get('member', []) if isinstance(group.get('member'), list) else [group.get('member', '')],
                'description': group.get('description', '')
            }
            processed_groups.append(processed_group)
        
        return processed_groups
    
    def get_kerberoastable_accounts(self):
        """获取可Kerberoasting的账户"""
        query_filter = "(&(objectcategory=user)(serviceprincipalname=*))"
        attributes = ["samaccountname", "serviceprincipalname", "pwdlastset"]
        
        accounts = self.run_adfind_query(query_filter, attributes)
        
        kerberoastable = []
        for account in accounts:
            kerberoastable.append({
                'username': account.get('samaccountname', ''),
                'spns': account.get('serviceprincipalname', []) if isinstance(account.get('serviceprincipalname'), list) else [account.get('serviceprincipalname', '')],
                'pwd_last_set': self.convert_ad_timestamp(account.get('pwdlastset', '0'))
            })
        
        return kerberoastable
    
    def convert_ad_timestamp(self, timestamp_str):
        """转换AD时间戳"""
        try:
            timestamp = int(timestamp_str)
            if timestamp == 0:
                return "Never"
            
            # AD时间戳是从1601年1月1日开始的100纳秒间隔数
            epoch_start = datetime(1601, 1, 1)
            seconds_since_epoch = timestamp / 10000000
            ad_date = epoch_start + timedelta(seconds=seconds_since_epoch)
            
            return ad_date.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return "Invalid"
    
    def decode_group_type(self, group_type):
        """解码组类型"""
        if group_type & 0x80000000:
            return "Security Group"
        else:
            return "Distribution Group"
    
    def generate_domain_report(self):
        """生成域报告"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'domain': self.domain,
            'users': self.get_domain_users(),
            'computers': self.get_domain_computers(),
            'groups': self.get_domain_groups(),
            'kerberoastable_accounts': self.get_kerberoastable_accounts()
        }
        
        return report
    
    def export_to_csv(self, data, filename):
        """导出数据到CSV文件"""
        if not data:
            return
        
        # 获取所有可能的键
        all_keys = set()
        for item in data:
            all_keys.update(item.keys())
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=list(all_keys))
            writer.writeheader()
            writer.writerows(data)
        
        print(f"[+] Data exported to {filename}")

# 使用示例
adfind = AdFindAutomation(domain="corp.local", username="domainuser", password="password")
report = adfind.generate_domain_report()

# 导出到CSV
adfind.export_to_csv(report['users'], 'domain_users.csv')
adfind.export_to_csv(report['computers'], 'domain_computers.csv')
adfind.export_to_csv(report['groups'], 'domain_groups.csv')

# 保存JSON报告
with open('domain_report.json', 'w') as f:
    json.dump(report, f, indent=2, default=str)
```

---

## LDAP查询

### 基础LDAP查询
```bash
# ldap_queries.sh

# 安装LDAP工具
# Ubuntu/Debian: apt-get install ldap-utils
# CentOS/RHEL: yum install openldap-clients

# 基本LDAP查询
ldapsearch -x -h dc01.corp.local -p 389 -D "corp\\user" -w "password" -b "dc=corp,dc=local" "(objectClass=user)" sAMAccountName

# 匿名查询（如果允许）
ldapsearch -x -h dc01.corp.local -b "dc=corp,dc=local" "(objectClass=*)"

# 获取域信息
ldapsearch -x -h dc01.corp.local -D "corp\\user" -w "password" -b "" -s base "(objectClass=*)" namingContexts

# 获取所有用户
ldapsearch -x -h dc01.corp.local -D "corp\\user" -w "password" -b "dc=corp,dc=local" "(&(objectClass=user)(objectCategory=person))" sAMAccountName description memberOf

# 获取所有计算机
ldapsearch -x -h dc01.corp.local -D "corp\\user" -w "password" -b "dc=corp,dc=local" "(objectClass=computer)" name operatingSystem lastLogon
```

### 高级LDAP查询
```bash
# ldap_advanced.sh

# 查找具有SPN的用户（Kerberoasting）
ldapsearch -x -h dc01.corp.local -D "corp\\user" -w "password" -b "dc=corp,dc=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# 查找不需要预认证的用户（AS-REP Roasting）
ldapsearch -x -h dc01.corp.local -D "corp\\user" -w "password" -b "dc=corp,dc=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# 查找无约束委派
ldapsearch -x -h dc01.corp.local -D "corp\\user" -w "password" -b "dc=corp,dc=local" "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" name

# 查找LAPS启用的计算机
ldapsearch -x -h dc01.corp.local -D "corp\\user" -w "password" -b "dc=corp,dc=local" "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))" name ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime

# 查找管理员组
ldapsearch -x -h dc01.corp.local -D "corp\\user" -w "password" -b "dc=corp,dc=local" "(&(objectClass=group)(adminCount=1))" sAMAccountName member

# 查找信任关系
ldapsearch -x -h dc01.corp.local -D "corp\\user" -w "password" -b "cn=system,dc=corp,dc=local" "(objectClass=trustedDomain)" cn trustAttributes trustDirection
```

### LDAP自动化查询
```python
# ldap_automation.py
import ldap
import ldap.modlist
import json
import csv
from datetime import datetime

class LDAPAutomation:
    def __init__(self, server, username, password, base_dn):
        self.server = server
        self.username = username
        self.password = password
        self.base_dn = base_dn
        self.connection = None
    
    def connect(self):
        """连接到LDAP服务器"""
        try:
            # 初始化LDAP连接
            self.connection = ldap.initialize(f"ldap://{self.server}")
            self.connection.protocol_version = ldap.VERSION3
            
            # 绑定到LDAP服务器
            self.connection.simple_bind_s(self.username, self.password)
            print(f"[+] Connected to LDAP server: {self.server}")
            return True
            
        except ldap.LDAPError as e:
            print(f"[!] LDAP connection error: {e}")
            return False
    
    def disconnect(self):
        """断开LDAP连接"""
        if self.connection:
            self.connection.unbind_s()
            print("[+] Disconnected from LDAP server")
    
    def search(self, search_filter, attributes=None, scope=ldap.SCOPE_SUBTREE):
        """执行LDAP搜索"""
        if not self.connection:
            print("[!] Not connected to LDAP server")
            return []
        
        try:
            if attributes is None:
                attributes = []
            
            result = self.connection.search_s(
                self.base_dn,
                scope,
                search_filter,
                attributes
            )
            
            # 解析结果
            entries = []
            for dn, entry in result:
                if dn:
                    parsed_entry = {'dn': dn}
                    for attr, values in entry.items():
                        # 解码字节值
                        decoded_values = []
                        for value in values:
                            if isinstance(value, bytes):
                                try:
                                    decoded_value = value.decode('utf-8')
                                except UnicodeDecodeError:
                                    decoded_value = value.decode('latin-1')
                                decoded_values.append(decoded_value)
                            else:
                                decoded_values.append(str(value))
                        
                        parsed_entry[attr] = decoded_values if len(decoded_values) > 1 else decoded_values[0]
                    
                    entries.append(parsed_entry)
            
            return entries
            
        except ldap.LDAPError as e:
            print(f"[!] LDAP search error: {e}")
            return []
    
    def get_all_users(self):
        """获取所有用户"""
        search_filter = "(&(objectClass=user)(objectCategory=person))"
        attributes = ["sAMAccountName", "userPrincipalName", "displayName", "description", 
                     "memberOf", "pwdLastSet", "lastLogon", "userAccountControl"]
        
        users = self.search(search_filter, attributes)
        
        # 处理用户数据
        processed_users = []
        for user in users:
            processed_user = {
                'username': user.get('sAMAccountName', ''),
                'upn': user.get('userPrincipalName', ''),
                'display_name': user.get('displayName', ''),
                'description': user.get('description', ''),
                'groups': user.get('memberOf', []),
                'pwd_last_set': self.convert_ad_timestamp(user.get('pwdLastSet', '0')),
                'last_logon': self.convert_ad_timestamp(user.get('lastLogon', '0')),
                'status': 'Enabled' if int(user.get('userAccountControl', '0')) & 2 == 0 else 'Disabled'
            }
            processed_users.append(processed_user)
        
        return processed_users
    
    def get_all_computers(self):
        """获取所有计算机"""
        search_filter = "(objectClass=computer)"
        attributes = ["name", "operatingSystem", "operatingSystemVersion", 
                     "operatingSystemServicePack", "lastLogon", "userAccountControl"]
        
        computers = self.search(search_filter, attributes)
        
        processed_computers = []
        for computer in computers:
            processed_computer = {
                'name': computer.get('name', ''),
                'os': computer.get('operatingSystem', ''),
                'os_version': computer.get('operatingSystemVersion', ''),
                'service_pack': computer.get('operatingSystemServicePack', ''),
                'last_logon': self.convert_ad_timestamp(computer.get('lastLogon', '0')),
                'unconstrained_delegation': bool(int(computer.get('userAccountControl', '0')) & 524288)
            }
            processed_computers.append(processed_computer)
        
        return processed_computers
    
    def get_domain_groups(self):
        """获取域组"""
        search_filter = "(objectClass=group)"
        attributes = ["sAMAccountName", "groupType", "member", "description", "adminCount"]
        
        groups = self.search(search_filter, attributes)
        
        processed_groups = []
        for group in groups:
            processed_group = {
                'name': group.get('sAMAccountName', ''),
                'type': self.decode_group_type(int(group.get('groupType', '0'))),
                'members': group.get('member', []),
                'description': group.get('description', ''),
                'is_admin': bool(group.get('adminCount', 0))
            }
            processed_groups.append(processed_group)
        
        return processed_groups
    
    def get_kerberoastable_accounts(self):
        """获取可Kerberoasting的账户"""
        search_filter = "(&(objectClass=user)(servicePrincipalName=*))"
        attributes = ["sAMAccountName", "servicePrincipalName", "pwdLastSet"]
        
        accounts = self.search(search_filter, attributes)
        
        kerberoastable = []
        for account in accounts:
            kerberoastable.append({
                'username': account.get('sAMAccountName', ''),
                'spns': account.get('servicePrincipalName', []),
                'pwd_last_set': self.convert_ad_timestamp(account.get('pwdLastSet', '0'))
            })
        
        return kerberoastable
    
    def convert_ad_timestamp(self, timestamp_str):
        """转换AD时间戳"""
        try:
            timestamp = int(timestamp_str)
            if timestamp == 0:
                return "Never"
            
            # AD时间戳是从1601年1月1日开始的100纳秒间隔数
            epoch_start = datetime(1601, 1, 1)
            seconds_since_epoch = timestamp / 10000000
            ad_date = epoch_start + timedelta(seconds=seconds_since_epoch)
            
            return ad_date.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return "Invalid"
    
    def decode_group_type(self, group_type):
        """解码组类型"""
        if group_type & 0x80000000:
            return "Security Group"
        else:
            return "Distribution Group"
    
    def get_organizational_units(self):
        """获取组织单位"""
        search_filter = "(objectClass=organizationalUnit)"
        attributes = ["name", "distinguishedName", "description"]
        
        ous = self.search(search_filter, attributes)
        
        processed_ous = []
        for ou in ous:
            processed_ous.append({
                'name': ou.get('name', ''),
                'distinguished_name': ou.get('distinguishedName', ''),
                'description': ou.get('description', '')
            })
        
        return processed_ous
    
    def get_group_policy_objects(self):
        """获取组策略对象"""
        search_filter = "(objectClass=groupPolicyContainer)"
        attributes = ["displayName", "cn", "gPCFileSysPath", "gPCFunctionalityVersion"]
        
        gpos = self.search(search_filter, attributes)
        
        processed_gpos = []
        for gpo in gpos:
            processed_gpos.append({
                'display_name': gpo.get('displayName', ''),
                'common_name': gpo.get('cn', ''),
                'file_sys_path': gpo.get('gPCFileSysPath', ''),
                'functionality_version': gpo.get('gPCFunctionalityVersion', '')
            })
        
        return processed_gpos
    
    def generate_ldap_report(self):
        """生成LDAP报告"""
        if not self.connect():
            return None
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'server': self.server,
            'base_dn': self.base_dn,
            'users': self.get_all_users(),
            'computers': self.get_all_computers(),
            'groups': self.get_domain_groups(),
            'kerberoastable_accounts': self.get_kerberoastable_accounts(),
            'organizational_units': self.get_organizational_units(),
            'group_policy_objects': self.get_group_policy_objects()
        }
        
        self.disconnect()
        return report

# 使用示例
ldap_auto = LDAPAutomation(
    server="dc01.corp.local",
    username="corp\\user",
    password="password",
    base_dn="dc=corp,dc=local"
)

report = ldap_auto.generate_ldap_report()
if report:
    with open('ldap_report.json', 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    # 导出到CSV
    ldap_auto.export_to_csv(report['users'], 'ldap_users.csv')
    ldap_auto.export_to_csv(report['computers'], 'ldap_computers.csv')
    ldap_auto.export_to_csv(report['groups'], 'ldap_groups.csv')
```

---

## 实战检查清单

### BloodHound分析
- [ ] SharpHound已部署
- [ ] 数据已收集
- [ ] BloodHound数据库已导入
- [ ] 高价值目标已识别
- [ ] 攻击路径已分析

### AdFind查询
- [ ] 域基础信息已收集
- [ ] 用户账户已枚举
- [ ] 计算机账户已识别
- [ ] 组信息已分析
- [ ] 特殊账户已发现

### LDAP查询
- [ ] LDAP连接已建立
- [ ] 用户数据已提取
- [ ] 计算机数据已获取
- [ ] 组信息已收集
- [ ] 域结构已映射