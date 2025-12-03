# 武器化环境 (Weaponization)

## 开发环境配置

### VS Code配置

#### 必备插件
```json
{
  "recommendations": [
    "ms-vscode.cpptools",
    "rust-lang.rust",
    "golang.go",
    "ms-python.python",
    "ms-vscode.powershell",
    "ms-dotnettools.csharp",
    "llvm-vs-code-extensions.vscode-clangd"
  ]
}
```

#### 工作区配置
```json
{
  "folders": [
    {
      "path": "payloads"
    },
    {
      "path": "loaders"
    },
    {
      "path": "tools"
    }
  ],
  "settings": {
    "files.associations": {
      "*.c": "c",
      "*.h": "c",
      "*.cpp": "cpp",
      "*.hpp": "cpp"
    },
    "C_Cpp.default.configurationProvider": "ms-vscode.cmake-tools",
    "rust-analyzer.cargo.allFeatures": true,
    "go.toolsManagement.checkForUpdates": "local"
  }
}
```

### Go环境配置

#### 安装与配置
```bash
# 安装Go
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# 配置环境
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.io,direct
go env -w GOSUMDB=off

# 创建工作目录
mkdir -p ~/go/{bin,src,pkg}
export GOPATH=~/go
export PATH=$PATH:$GOPATH/bin
```

#### 免杀开发库
```go
// go.mod
module payload-generator

go 1.21

require (
    github.com/fatih/color v1.15.0
    github.com/Binject/debug v0.0.0-20210312092933-6277045c1fdf
    github.com/awgh/rawreader v0.0.0-20200626064944-56820a8c6da4
    golang.org/x/sys v0.12.0
    github.com/Ne0nd0g/go-clr v1.0.2
)
```

### Rust环境配置

#### 安装与配置
```bash
# 安装Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 安装工具链
rustup install stable nightly
rustup default stable

# 安装交叉编译工具
rustup target add x86_64-pc-windows-gnu
rustup target add i686-pc-windows-gnu

# 安装MinGW
sudo apt install gcc-mingw-w64
```

#### Cargo配置
```toml
# ~/.cargo/config
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
ar = "x86_64-w64-mingw32-ar"

[target.i686-pc-windows-gnu]
linker = "i686-w64-mingw32-gcc"
ar = "i686-w64-mingw32-ar"
```

### MinGW配置

#### 安装与配置
```bash
# 安装MinGW-w64
sudo apt update
sudo apt install mingw-w64 mingw-w64-tools

# 配置环境变量
export MINGW_PREFIX=/usr/bin/x86_64-w64-mingw32
export PATH=$PATH:$MINGW_PREFIX/bin

# 测试编译
echo '#include <windows.h>' > test.c
echo 'int main(){MessageBoxA(0,"Test","Test",0);return 0;}' >> test.c
x86_64-w64-mingw32-gcc test.c -o test.exe -mwindows
```

#### 交叉编译脚本
```bash
#!/bin/bash
# cross-compile.sh

TARGET="$1"
OUTPUT="$2"
SOURCE="$3"

case $TARGET in
    win64)
        x86_64-w64-mingw32-gcc $SOURCE -o $OUTPUT.exe -s -O2 -static
        ;;
    win32)
        i686-w64-mingw32-gcc $SOURCE -o $OUTPUT.exe -s -O2 -static
        ;;
    linux64)
        gcc $SOURCE -o $OUTPUT -s -O2 -static
        ;;
    *)
        echo "Usage: $0 [win64|win32|linux64] output source"
        exit 1
        ;;
esac
```

---

## 编译流水线 (CI/CD)

### GitHub Actions配置
```yaml
# .github/workflows/build.yml
name: Build Payloads

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build-windows:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
        
    - name: Set up Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        target: x86_64-pc-windows-gnu
        override: true
        
    - name: Install MinGW
      run: |
        sudo apt update
        sudo apt install -y gcc-mingw-w64
        
    - name: Build Go Payloads
      run: |
        cd payloads/go
        GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -H=windowsgui" -o ../../build/go-loader.exe main.go
        
    - name: Build Rust Payloads
      run: |
        cd payloads/rust
        cargo build --release --target x86_64-pc-windows-gnu
        cp target/x86_64-pc-windows-gnu/release/rust-loader.exe ../../build/
        
    - name: Obfuscate Payloads
      run: |
        # 使用garble进行Go代码混淆
        go install mvdan.cc/garble@latest
        cd payloads/go
        garble -literals -tiny -seed=random build -ldflags "-s -w -H=windowsgui" -o ../../build/go-loader-obf.exe main.go
        
    - name: Upload Artifacts
      uses: actions/upload-artifact@v3
      with:
        name: payloads
        path: build/
```

### 自动化构建脚本
```bash
#!/bin/bash
# auto-build.sh

set -e

BUILD_DIR="build"
PAYLOADS_DIR="payloads"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "[+] Starting automated build process..."

# 清理旧的构建
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# 构建Go载荷
echo "[+] Building Go payloads..."
cd $PAYLOADS_DIR/go

# 标准构建
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -H=windowsgui" -o ../../$BUILD_DIR/go-loader.exe main.go

# 混淆构建
garble -literals -tiny -seed=$(date +%s) build -ldflags "-s -w -H=windowsgui" -o ../../$BUILD_DIR/go-loader-obf.exe main.go

# 加壳构建
cd ../../$BUILD_DIR
upx --best --lzma go-loader.exe -o go-loader-packed.exe

cd ../..

# 构建Rust载荷
echo "[+] Building Rust payloads..."
cd $PAYLOADS_DIR/rust

cargo build --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/rust-loader.exe ../../$BUILD_DIR/

# 混淆版本
cargo obfusticate --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/rust-loader-obf.exe ../../$BUILD_DIR/

cd ../..

# 构建C/C++载荷
echo "[+] Building C/C++ payloads..."
cd $PAYLOADS_DIR/c

# 标准版本
x86_64-w64-mingw32-gcc loader.c -o ../../$BUILD_DIR/c-loader.exe -s -O2 -static

# 混淆版本（使用宏定义）
x86_64-w64-mingw32-gcc loader.c -o ../../$BUILD_DIR/c-loader-obf.exe -s -O2 -static -DOBFUSCATE

cd ../..

# 生成报告
echo "[+] Generating build report..."
cat > $BUILD_DIR/build-report.txt << EOF
Build Report - $TIMESTAMP
========================

Go Payloads:
- go-loader.exe: $(stat -c%s $BUILD_DIR/go-loader.exe) bytes
- go-loader-obf.exe: $(stat -c%s $BUILD_DIR/go-loader-obf.exe) bytes
- go-loader-packed.exe: $(stat -c%s $BUILD_DIR/go-loader-packed.exe) bytes

Rust Payloads:
- rust-loader.exe: $(stat -c%s $BUILD_DIR/rust-loader.exe) bytes
- rust-loader-obf.exe: $(stat -c%s $BUILD_DIR/rust-loader-obf.exe) bytes

C/C++ Payloads:
- c-loader.exe: $(stat -c%s $BUILD_DIR/c-loader.exe) bytes
- c-loader-obf.exe: $(stat -c%s $BUILD_DIR/c-loader-obf.exe) bytes

Checksums:
$(cd $BUILD_DIR && sha256sum *.exe)
EOF

echo "[+] Build completed successfully!"
echo "[+] Artifacts saved to: $BUILD_DIR/"
```

---

## 钓鱼基础设施

### Gophish搭建

#### Docker部署
```yaml
# docker-compose.yml
version: '3.8'

services:
  gophish:
    image: gophish/gophish:latest
    container_name: gophish
    ports:
      - "3333:3333"  # 管理界面
      - "8080:80"    # 钓鱼页面
      - "8443:443"   # HTTPS钓鱼页面
    volumes:
      - ./data:/opt/gophish/data
      - ./certs:/opt/gophish/certs
    environment:
      - GOPHISH_ADMIN_IP=0.0.0.0
      - GOPHISH_ADMIN_PORT=3333
    restart: unless-stopped
    
  mailhog:
    image: mailhog/mailhog:latest
    container_name: mailhog
    ports:
      - "1025:1025"  # SMTP端口
      - "8025:8025"  # Web界面
    restart: unless-stopped
```

#### 配置详解
```json
# config.json
{
    "admin_server": {
        "listen_url": "0.0.0.0:3333",
        "use_tls": true,
        "cert_path": "gophish_admin.crt",
        "key_path": "gophish_admin.key"
    },
    "phish_server": {
        "listen_url": "0.0.0.0:443",
        "use_tls": true,
        "cert_path": "gophish_phish.crt",
        "key_path": "gophish_phish.key"
    },
    "db_name": "gophish.db",
    "db_path": "data/gophish.db",
    "migrations_prefix": "db/db_",
    "contact_address": "",
    "logging": {
        "filename": "data/gophish.log",
        "level": "debug"
    }
}
```

### 邮件服务器配置

#### Postfix配置
```bash
# 安装Postfix
sudo apt install postfix mailutils

# 配置main.cf
sudo nano /etc/postfix/main.cf
```

```
# /etc/postfix/main.cf
myhostname = mail.targetdomain.com
mydomain = targetdomain.com
myorigin = $mydomain
inet_interfaces = all
inet_protocols = ipv4
mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain
mynetworks = 127.0.0.0/8
home_mailbox = Maildir/
smtpd_banner = $myhostname ESMTP $mail_name
biff = no
append_dot_mydomain = no
readme_directory = no

# SMTP认证
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination

# TLS配置
smtpd_tls_cert_file = /etc/ssl/certs/mail.crt
smtpd_tls_key_file = /etc/ssl/private/mail.key
smtpd_use_tls = yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
```

#### SPF记录配置
```
# DNS TXT记录
targetdomain.com. IN TXT "v=spf1 mx ip4:192.168.1.100 include:_spf.google.com ~all"
```

#### DKIM配置
```bash
# 安装OpenDKIM
sudo apt install opendkim opendkim-tools

# 配置/etc/opendkim.conf
AutoRestart             Yes
AutoRestartRate         10/1h
Syslog                  yes
UMask                   002
Canonicalization        relaxed/simple
Mode                    sv
SubDomains              no
Socket                  inet:12301@localhost
PidFile                 /var/run/opendkim/opendkim.pid
UserID                  opendkim:opendkim
TemporaryDirectory      /var/tmp
KeyTable                /etc/opendkim/key.table
SigningTable            /etc/opendkim/signing.table
ExternalIgnoreList      /etc/opendkim/trusted.hosts
InternalHosts           /etc/opendkim/trusted.hosts

# 生成DKIM密钥
opendkim-genkey -t -s mail -d targetdomain.com
```

#### DMARC配置
```
# DNS TXT记录
_dmarc.targetdomain.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@targetdomain.com; ruf=mailto:dmarc@targetdomain.com; fo=1"
```

### 钓鱼邮件模板

#### Office 365模板
```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Microsoft Teams Notification</title>
</head>
<body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f3f2f1;">
    <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <div style="background-color: #6264a7; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
            <img src="https://teams.microsoft.com/favicon.ico" alt="Teams" style="width: 24px; height: 24px; vertical-align: middle; margin-right: 10px;">
            <span style="font-size: 20px; font-weight: bold;">Microsoft Teams</span>
        </div>
        
        <div style="padding: 30px;">
            <h2 style="color: #323130; margin-bottom: 20px;">You have a new message</h2>
            
            <p style="color: #605e5c; font-size: 16px; line-height: 1.5;">
                <strong>{{.FirstName}}</strong> sent you a message in <strong>{{.TeamName}}</strong> team.
            </p>
            
            <div style="background-color: #faf9f8; border-left: 4px solid #6264a7; padding: 15px; margin: 20px 0;">
                <p style="margin: 0; color: #323130;">Hi {{.FirstName}}, please review the attached document and provide your feedback by EOD.</p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{{.URL}}" style="background-color: #6264a7; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                    View Message
                </a>
            </div>
            
            <p style="color: #605e5c; font-size: 14px; margin-top: 30px;">
                This message was sent from an unmonitored mailbox. Please do not reply.
            </p>
        </div>
        
        <div style="background-color: #faf9f8; padding: 20px; border-radius: 0 0 8px 8px; text-align: center;">
            <p style="margin: 0; color: #605e5c; font-size: 12px;">
                © 2024 Microsoft Corporation. All rights reserved.
            </p>
        </div>
    </div>
</body>
</html>
```

#### 财务部门模板
```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Urgent: Invoice Processing</title>
</head>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
    <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.12);">
        <div style="background-color: #0078d4; color: white; padding: 20px; border-radius: 6px 6px 0 0;">
            <h1 style="margin: 0; font-size: 24px;">Finance Department</h1>
        </div>
        
        <div style="padding: 30px;">
            <h2 style="color: #323130; margin-bottom: 20px;">Urgent: Invoice Processing Required</h2>
            
            <p style="color: #323130; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                Dear {{.FirstName}},
            </p>
            
            <p style="color #323130; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                We have received multiple invoices that require your immediate attention and approval. 
                The payment deadline is approaching and we need to process these invoices today to avoid late fees.
            </p>
            
            <div style="background-color: #fff4ce; border: 1px solid #ffb900; border-radius: 4px; padding: 15px; margin: 20px 0;">
                <p style="margin: 0; color: #323130; font-weight: bold;">
                    ⚠️ Action Required: 12 invoices pending approval
                </p>
            </div>
            
            <p style="color: #323130; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                Please access the finance portal to review and approve the pending invoices:
            </p>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{{.URL}}" style="background-color: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                    Access Finance Portal
                </a>
            </div>
            
            <p style="color: #323130; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                If you have any questions, please contact the finance team at extension 2345.
            </p>
            
            <p style="color: #323130; font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                Best regards,<br>
                Finance Department
            </p>
        </div>
        
        <div style="background-color: #f5f5f5; padding: 20px; border-radius: 0 0 6px 6px; text-align: center;">
            <p style="margin: 0; color: #605e5c; font-size: 12px;">
                This is an automated message from the Finance Department. Please do not reply to this email.
            </p>
        </div>
    </div>
</body>
</html>
```

---

## 实战检查清单

### 环境准备
- [ ] VS Code和插件已安装
- [ ] Go环境已配置
- [ ] Rust工具链已安装
- [ ] MinGW交叉编译器已配置
- [ ] CI/CD流水线已设置

### 武器化构建
- [ ] Payload代码已编写
- [ ] 混淆策略已实施
- [ ] 加壳工具已使用
- [ ] 多架构版本已构建
- [ ] 自动化测试已通过

### 钓鱼基础设施
- [ ] Gophish已部署
- [ ] 邮件服务器已配置
- [ ] SPF/DKIM/DMARC已设置
- [ ] 钓鱼模板已创建
- [ ] 目标列表已准备