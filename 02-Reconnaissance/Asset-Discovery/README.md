# 资产发现 (Asset Discovery)

## 子域名枚举

### 爆破技术

#### 子域名爆破工具
```bash
# 安装子域名爆破工具
git clone https://github.com/aboul3la/Sublist3r.git
git clone https://github.com/projectdiscovery/subfinder.git
git clone https://github.com/owasp-amass/amass.git
git clone https://github.com/danielmiessler/SecLists.git

# 安装依赖
cd Sublist3r && pip install -r requirements.txt
cd subfinder && go build
cd amass && go build
```

#### 综合子域名枚举脚本
```python
# subdomain_enumerator.py
import subprocess
import json
import concurrent.futures
import dns.resolver
from datetime import datetime
import os

class SubdomainEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        
        # 常用子域名字典
        self.wordlists = [
            '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
            '/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt',
            '/usr/share/seclists/Discovery/DNS/namelist.txt',
            '/usr/share/seclists/Discovery/DNS/combined_words.txt'
        ]
    
    def run_subfinder(self):
        """运行subfinder"""
        try:
            cmd = ['subfinder', '-d', self.domain, '-silent', '-o', f'/tmp/subfinder_{self.domain}.txt']
            subprocess.run(cmd, timeout=300)
            
            if os.path.exists(f'/tmp/subfinder_{self.domain}.txt'):
                with open(f'/tmp/subfinder_{self.domain}.txt', 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain:
                            self.subdomains.add(subdomain)
        except Exception as e:
            print(f"[!] Subfinder error: {e}")
    
    def run_amass(self):
        """运行amass"""
        try:
            cmd = ['amass', 'enum', '-passive', '-d', self.domain, '-o', f'/tmp/amass_{self.domain}.txt']
            subprocess.run(cmd, timeout=600)
            
            if os.path.exists(f'/tmp/amass_{self.domain}.txt'):
                with open(f'/tmp/amass_{self.domain}.txt', 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain:
                            self.subdomains.add(subdomain)
        except Exception as e:
            print(f"[!] Amass error: {e}")
    
    def run_sublist3r(self):
        """运行sublist3r"""
        try:
            cmd = ['python3', 'Sublist3r/sublist3r.py', '-d', self.domain, '-o', f'/tmp/sublist3r_{self.domain}.txt']
            subprocess.run(cmd, timeout=300)
            
            if os.path.exists(f'/tmp/sublist3r_{self.domain}.txt'):
                with open(f'/tmp/sublist3r_{self.domain}.txt', 'r') as f:
                    for line in f:
                        subdomain = line.strip()
                        if subdomain:
                            self.subdomains.add(subdomain)
        except Exception as e:
            print(f"[!] Sublist3r error: {e}")
    
    def dns_bruteforce(self, wordlist):
        """DNS爆破"""
        try:
            with open(wordlist, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            
            # 多线程DNS解析
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for word in words:
                    subdomain = f"{word}.{self.domain}"
                    futures.append(executor.submit(self.resolve_subdomain, subdomain))
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.subdomains.add(result)
        except Exception as e:
            print(f"[!] DNS bruteforce error: {e}")
    
    def resolve_subdomain(self, subdomain):
        """解析子域名"""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            return subdomain
        except:
            return None
    
    def validate_subdomains(self):
        """验证子域名有效性"""
        valid_subdomains = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            for subdomain in self.subdomains:
                futures.append(executor.submit(self.check_subdomain, subdomain))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    valid_subdomains.append(result)
        
        return valid_subdomains
    
    def check_subdomain(self, subdomain):
        """检查子域名"""
        try:
            # A记录
            a_records = []
            try:
                answers = self.resolver.resolve(subdomain, 'A')
                a_records = [str(rdata) for rdata in answers]
            except:
                pass
            
            # CNAME记录
            cname_records = []
            try:
                answers = self.resolver.resolve(subdomain, 'CNAME')
                cname_records = [str(rdata) for rdata in answers]
            except:
                pass
            
            # 如果没有任何记录，返回None
            if not a_records and not cname_records:
                return None
            
            # HTTP服务检查
            http_status = self.check_http_service(subdomain)
            
            return {
                'subdomain': subdomain,
                'a_records': a_records,
                'cname_records': cname_records,
                'http_status': http_status,
                'ports': self.scan_common_ports(subdomain)
            }
        except Exception as e:
            print(f"[!] Error checking subdomain {subdomain}: {e}")
            return None
    
    def check_http_service(self, subdomain):
        """检查HTTP服务"""
        try:
            import requests
            
            urls = [f"http://{subdomain}", f"https://{subdomain}"]
            results = {}
            
            for url in urls:
                try:
                    response = requests.get(url, timeout=5, allow_redirects=True)
                    results[url] = {
                        'status_code': response.status_code,
                        'title': self.extract_title(response.text),
                        'server': response.headers.get('Server', 'Unknown'),
                        'content_length': len(response.content)
                    }
                except:
                    results[url] = None
            
            return results
        except Exception as e:
            print(f"[!] HTTP check error for {subdomain}: {e}")
            return None
    
    def extract_title(self, html):
        """提取页面标题"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.find('title')
            return title.text.strip() if title else 'No Title'
        except:
            return 'No Title'
    
    def scan_common_ports(self, subdomain):
        """扫描常用端口"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        
        import socket
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((subdomain, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except:
                pass
        
        return open_ports
    
    def run_full_enumeration(self):
        """运行完整的子域名枚举"""
        print(f"[*] Starting subdomain enumeration for {self.domain}")
        start_time = datetime.now()
        
        # 运行被动枚举工具
        print("[*] Running subfinder...")
        self.run_subfinder()
        
        print("[*] Running amass...")
        self.run_amass()
        
        print("[*] Running sublist3r...")
        self.run_sublist3r()
        
        # DNS爆破
        print("[*] Starting DNS bruteforce...")
        for wordlist in self.wordlists:
            if os.path.exists(wordlist):
                print(f"[*] Using wordlist: {wordlist}")
                self.dns_bruteforce(wordlist)
        
        print(f"[*] Found {len(self.subdomains)} unique subdomains")
        
        # 验证子域名
        print("[*] Validating subdomains...")
        valid_subdomains = self.validate_subdomains()
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print(f"[*] Enumeration completed in {duration:.2f} seconds")
        print(f"[*] Found {len(valid_subdomains)} valid subdomains")
        
        return {
            'domain': self.domain,
            'total_found': len(self.subdomains),
            'valid_count': len(valid_subdomains),
            'duration': duration,
            'subdomains': valid_subdomains,
            'timestamp': datetime.now().isoformat()
        }

# 使用示例
enumerator = SubdomainEnumerator("targetdomain.com")
results = enumerator.run_full_enumeration()
print(json.dumps(results, indent=2))
```

### 证书透明度 (CT) 日志

#### CT日志搜索
```python
# ct_log_search.py
import requests
import json
import base64
import subprocess

class CTLogSearcher:
    def __init__(self):
        self.ct_apis = [
            'https://crt.sh/?q=%.{domain}&output=json',
            'https://certspotter.com/api/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names',
            'https://api.certificate-transparency.org/ct/v1/get-entries?start=0&end=100'
        ]
    
    def search_ct_logs(self, domain):
        """搜索证书透明度日志"""
        certificates = []
        
        # crt.sh搜索
        try:
            crt_results = self.search_crt_sh(domain)
            certificates.extend(crt_results)
        except Exception as e:
            print(f"[!] crt.sh error: {e}")
        
        # CertSpotter搜索
        try:
            spotter_results = self.search_certspotter(domain)
            certificates.extend(spotter_results)
        except Exception as e:
            print(f"[!] CertSpotter error: {e}")
        
        # 使用certbot获取CT日志
        try:
            certbot_results = self.search_with_certbot(domain)
            certificates.extend(certbot_results)
        except Exception as e:
            print(f"[!] Certbot error: {e}")
        
        # 去重
        unique_certificates = self.remove_duplicates(certificates)
        
        return unique_certificates
    
    def search_crt_sh(self, domain):
        """搜索crt.sh"""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            
            certificates = []
            for cert in data:
                # 提取所有DNS名称
                dns_names = []
                
                if cert.get('name_value'):
                    dns_names = cert['name_value'].split('\n')
                
                certificates.append({
                    'id': cert.get('id'),
                    'issuer': cert.get('issuer_name'),
                    'dns_names': dns_names,
                    'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after'),
                    'source': 'crt.sh'
                })
            
            return certificates
        
        return []
    
    def search_certspotter(self, domain):
        """搜索CertSpotter"""
        url = f"https://certspotter.com/api/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            
            certificates = []
            for cert in data:
                certificates.append({
                    'id': cert.get('id'),
                    'issuer': cert.get('issuer'),
                    'dns_names': cert.get('dns_names', []),
                    'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after'),
                    'source': 'certspotter'
                })
            
            return certificates
        
        return []
    
    def search_with_certbot(self, domain):
        """使用certbot搜索CT日志"""
        try:
            # 使用certbot命令获取CT日志
            cmd = ['certbot', 'search_ct', '--domain', domain, '--format', 'json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                return data
        except:
            pass
        
        return []
    
    def remove_duplicates(self, certificates):
        """去重证书"""
        seen = set()
        unique_certs = []
        
        for cert in certificates:
            # 使用DNS名称作为去重键
            dns_names = tuple(sorted(cert.get('dns_names', [])))
            
            if dns_names not in seen:
                seen.add(dns_names)
                unique_certs.append(cert)
        
        return unique_certs
    
    def extract_subdomains(self, certificates):
        """从证书中提取子域名"""
        subdomains = set()
        
        for cert in certificates:
            for dns_name in cert.get('dns_names', []):
                # 清理DNS名称
                dns_name = dns_name.strip().lower()
                if dns_name.startswith('*.'):
                    dns_name = dns_name[2:]  # 移除通配符
                
                subdomains.add(dns_name)
        
        return sorted(list(subdomains))
    
    def analyze_certificate_patterns(self, certificates):
        """分析证书模式"""
        patterns = {
            'total_certificates': len(certificates),
            'unique_issuers': set(),
            'wildcard_certificates': 0,
            'subdomain_count': 0,
            'date_range': {
                'earliest': None,
                'latest': None
            }
        }
        
        all_subdomains = set()
        
        for cert in certificates:
            # 统计签发者
            if cert.get('issuer'):
                patterns['unique_issuers'].add(cert['issuer'])
            
            # 统计通配符证书
            dns_names = cert.get('dns_names', [])
            for dns_name in dns_names:
                if dns_name.startswith('*.'):
                    patterns['wildcard_certificates'] += 1
                
                all_subdomains.add(dns_name)
            
            # 统计日期范围
            not_before = cert.get('not_before')
            not_after = cert.get('not_after')
            
            if not_before:
                if not patterns['date_range']['earliest'] or not_before < patterns['date_range']['earliest']:
                    patterns['date_range']['earliest'] = not_before
            
            if not_after:
                if not patterns['date_range']['latest'] or not_after > patterns['date_range']['latest']:
                    patterns['date_range']['latest'] = not_after
        
        patterns['subdomain_count'] = len(all_subdomains)
        patterns['unique_issuers'] = len(patterns['unique_issuers'])
        
        return patterns

# 使用示例
ct_searcher = CTLogSearcher()
certificates = ct_searcher.search_ct_logs("targetdomain.com")
subdomains = ct_searcher.extract_subdomains(certificates)
patterns = ct_searcher.analyze_certificate_patterns(certificates)

print(f"Found {len(certificates)} certificates")
print(f"Extracted {len(subdomains)} subdomains")
print(json.dumps(patterns, indent=2))
```

---

## 端口与服务

### Masscan策略

#### 大规模端口扫描
```bash
# masscan安装与配置
sudo apt install masscan

# 基础扫描策略
sudo masscan 192.168.1.0/24 -p1-65535 --rate 1000 -oL masscan-results.txt

# 快速扫描常用端口
sudo masscan 192.168.1.0/24 -p21,22,23,25,53,80,110,143,443,993,995,1433,3306,3389,5432,8080,8443 --rate 10000 -oL quick-scan.txt

# 全端口扫描（慢速）
sudo masscan targetdomain.com -p1-65535 --rate 100 --wait 1 -oL full-scan.txt
```

#### Masscan高级配置
```bash
# 排除文件配置
echo "192.168.1.1" > exclude.txt
echo "192.168.1.255" >> exclude.txt

# 使用排除文件扫描
sudo masscan 192.168.1.0/24 -p1-65535 --rate 1000 --excludefile exclude.txt -oL results.txt

# 随机化扫描顺序
sudo masscan 192.168.1.0/24 -p1-65535 --rate 1000 --randomize-hosts -oL results.txt

# 指定源IP和端口
sudo masscan 192.168.1.0/24 -p1-65535 --rate 1000 --source-ip 192.168.1.100 --source-port 40000-41000 -oL results.txt
```

### Nmap策略

#### 服务指纹识别
```bash
# 基础服务扫描
nmap -sV -sC -O -oA service-scan targetdomain.com

# 快速服务扫描
nmap -sV --top-ports 1000 -T4 -oA quick-service-scan targetdomain.com

# 全端口服务扫描
nmap -sV -p1-65535 -T4 -oA full-service-scan targetdomain.com

# 特定服务深度扫描
nmap -sV -sC -p80,443,8080,8443 -oA web-scan targetdomain.com
```

#### Nmap脚本引擎
```bash
# 使用默认脚本扫描
nmap -sC -sV -oA script-scan targetdomain.com

# 使用特定类别脚本
nmap -sV --script "default,discovery,auth" -oA category-scan targetdomain.com

# 使用特定脚本
nmap -sV --script http-enum,http-title,http-methods -p80,443 -oA web-enum-scan targetdomain.com

# 使用漏洞扫描脚本
nmap -sV --script vuln -oA vuln-scan targetdomain.com
```

#### 综合端口扫描脚本
```python
# port_scanner.py
import nmap
import json
import concurrent.futures
from datetime import datetime

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.masscan_path = '/usr/bin/masscan'
    
    def masscan_scan(self, target, ports='1-65535', rate=1000):
        """使用Masscan进行大规模扫描"""
        output_file = f'/tmp/masscan_{target.replace("/", "_")}.txt'
        
        cmd = [
            'sudo', self.masscan_path,
            target,
            f'-p{ports}',
            f'--rate={rate}',
            '-oL', output_file
        ]
        
        try:
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if os.path.exists(output_file):
                open_ports = []
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.startswith('open'):
                            parts = line.strip().split()
                            if len(parts) >= 3:
                                port = int(parts[2])
                                ip = parts[3]
                                open_ports.append({
                                    'ip': ip,
                                    'port': port,
                                    'protocol': parts[1],
                                    'timestamp': parts[0] if len(parts) > 4 else None
                                })
                
                return open_ports
        except Exception as e:
            print(f"[!] Masscan error: {e}")
            return []
    
    def nmap_service_scan(self, hosts, ports):
        """使用Nmap进行服务扫描"""
        results = {}
        
        # 构建端口字符串
        if isinstance(ports, list):
            port_str = ','.join(map(str, ports))
        else:
            port_str = str(ports)
        
        # 构建主机字符串
        if isinstance(hosts, list):
            host_str = ' '.join(hosts)
        else:
            host_str = hosts
        
        try:
            # 扫描参数
            arguments = '-sV -sC -O --script default,discovery -T4'
            
            self.nm.scan(hosts=host_str, ports=port_str, arguments=arguments)
            
            for host in self.nm.all_hosts():
                host_info = {
                    'host': host,
                    'state': self.nm[host].state(),
                    'os': {},
                    'ports': []
                }
                
                # 操作系统信息
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        host_info['os'][osmatch['name']] = int(osmatch['accuracy'])
                
                # 端口信息
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in sorted(ports):
                        port_info = self.nm[host][proto][port]
                        host_info['ports'].append({
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'scripts': port_info.get('script', {})
                        })
                
                results[host] = host_info
        except Exception as e:
            print(f"[!] Nmap error: {e}")
        
        return results
    
    def detect_waf(self, host, port=80):
        """检测WAF"""
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'AWS WAF': ['x-amzn-requestid', 'x-amzn-trace-id'],
            'Akamai': ['akamai', 'x-akamai'],
            'Incapsula': ['incapsula', 'x-iinfo'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'F5 BIG-IP': ['bigip', 'x-waf-event-info']
        }
        
        try:
            import requests
            
            # 发送触发WAF的请求
            test_payloads = [
                "?q=<script>alert(1)</script>",
                "?q=' OR 1=1--",
                "?q=../../../etc/passwd",
                "?q=1 UNION SELECT * FROM users--"
            ]
            
            detected_wafs = []
            
            for payload in test_payloads:
                try:
                    url = f"http://{host}:{port}/test{payload}"
                    response = requests.get(url, timeout=5)
                    
                    # 检查响应头
                    for header_name, header_value in response.headers.items():
                        for waf_name, signatures in waf_signatures.items():
                            for signature in signatures:
                                if signature.lower() in header_name.lower() or signature.lower() in header_value.lower():
                                    if waf_name not in detected_wafs:
                                        detected_wafs.append(waf_name)
                    
                    # 检查响应内容
                    content = response.text.lower()
                    for waf_name, signatures in waf_signatures.items():
                        for signature in signatures:
                            if signature.lower() in content:
                                if waf_name not in detected_wafs:
                                    detected_wafs.append(waf_name)
                
                except:
                    continue
            
            return detected_wafs if detected_wafs else ['No WAF detected']
        except Exception as e:
            print(f"[!] WAF detection error: {e}")
            return ['Detection failed']
    
    def generate_scan_report(self, scan_results):
        """生成扫描报告"""
        report = {
            'scan_time': datetime.now().isoformat(),
            'total_hosts': len(scan_results),
            'services_summary': {},
            'os_distribution': {},
            'potential_vulnerabilities': []
        }
        
        # 服务统计
        for host_info in scan_results.values():
            for port_info in host_info.get('ports', []):
                service = port_info.get('service', 'unknown')
                if service in report['services_summary']:
                    report['services_summary'][service] += 1
                else:
                    report['services_summary'][service] = 1
            
            # 操作系统统计
            for os_name, accuracy in host_info.get('os', {}).items():
                if accuracy > 80:  # 只统计高置信度的OS检测
                    if os_name in report['os_distribution']:
                        report['os_distribution'][os_name] += 1
                    else:
                        report['os_distribution'][os_name] = 1
            
            # 潜在漏洞
            for port_info in host_info.get('ports', []):
                scripts = port_info.get('scripts', {})
                for script_name, script_output in scripts.items():
                    if 'vuln' in script_name.lower() and 'vulnerable' in script_output.lower():
                        report['potential_vulnerabilities'].append({
                            'host': host_info['host'],
                            'port': port_info['port'],
                            'service': port_info['service'],
                            'vulnerability': script_output
                        })
        
        return report

# 使用示例
scanner = PortScanner()

# 先使用Masscan进行快速端口发现
masscan_results = scanner.masscan_scan("192.168.1.0/24", ports="1-65535", rate=1000)
print(f"Masscan found {len(masscan_results)} open ports")

# 提取唯一的主机和端口
hosts_and_ports = {}
for result in masscan_results:
    host = result['ip']
    port = result['port']
    
    if host not in hosts_and_ports:
        hosts_and_ports[host] = []
    hosts_and_ports[host].append(port)

# 使用Nmap进行详细服务扫描
all_results = {}
for host, ports in hosts_and_ports.items():
    print(f"[*] Scanning {host} ports: {len(ports)}")
    scan_results = scanner.nmap_service_scan(host, ports)
    all_results.update(scan_results)

# 生成报告
report = scanner.generate_scan_report(all_results)
print(json.dumps(report, indent=2))
```

---

## 云资产发现

### AWS S3存储桶发现

#### S3存储桶爆破
```python
# s3_bucket_finder.py
import requests
import json
import concurrent.futures
from datetime import datetime

class S3BucketFinder:
    def __init__(self):
        self.regions = [
            'us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1',
            'ap-southeast-1', 'ap-northeast-1', 'ap-south-1', 'sa-east-1'
        ]
        
        # 常见的存储桶名称模式
        self.bucket_patterns = [
            '{company}-backup',
            '{company}-data',
            '{company}-files',
            '{company}-assets',
            '{company}-uploads',
            '{company}-public',
            '{company}-private',
            '{company}-dev',
            '{company}-staging',
            '{company}-prod',
            '{company}-logs',
            '{company}-archive',
            '{company}-media',
            '{company}-documents',
            '{company}-images'
        ]
    
    def check_bucket_exists(self, bucket_name):
        """检查存储桶是否存在"""
        try:
            # 尝试访问存储桶的HTTP端点
            url = f"https://{bucket_name}.s3.amazonaws.com/"
            response = requests.head(url, timeout=5)
            
            if response.status_code == 200:
                return {'exists': True, 'public': True, 'auth': 'none'}
            elif response.status_code == 403:
                return {'exists': True, 'public': False, 'auth': 'required'}
            elif response.status_code == 404:
                return {'exists': False}
            else:
                return {'exists': 'unknown', 'status_code': response.status_code}
        except requests.exceptions.RequestException:
            return {'exists': 'error'}
    
    def check_bucket_permissions(self, bucket_name):
        """检查存储桶权限"""
        permissions = {
            'list_objects': False,
            'get_objects': False,
            'put_objects': False,
            'delete_objects': False,
            'get_bucket_acl': False,
            'get_bucket_policy': False
        }
        
        try:
            # 检查列出对象权限
            url = f"https://{bucket_name}.s3.amazonaws.com/"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200 and 'ListBucketResult' in response.text:
                permissions['list_objects'] = True
            
            # 检查ACL权限
            acl_url = f"https://{bucket_name}.s3.amazonaws.com/?acl"
            acl_response = requests.get(acl_url, timeout=5)
            
            if acl_response.status_code == 200:
                permissions['get_bucket_acl'] = True
            
            # 检查策略权限
            policy_url = f"https://{bucket_name}.s3.amazonaws.com/?policy"
            policy_response = requests.get(policy_url, timeout=5)
            
            if policy_response.status_code == 200:
                permissions['get_bucket_policy'] = True
            
        except requests.exceptions.RequestException:
            pass
        
        return permissions
    
    def generate_bucket_names(self, company_name):
        """生成可能的存储桶名称"""
        bucket_names = []
        
        # 基于公司名称生成
        company_variations = [
            company_name.lower(),
            company_name.lower().replace(' ', '-'),
            company_name.lower().replace(' ', ''),
            company_name.lower().replace('inc', '').replace('corp', '').strip(),
            ''.join(word[0] for word in company_name.split()).lower()
        ]
        
        for variation in company_variations:
            for pattern in self.bucket_patterns:
                bucket_name = pattern.format(company=variation)
                bucket_names.append(bucket_name)
        
        # 添加年份和版本
        year = datetime.now().year
        extended_names = []
        for name in bucket_names:
            extended_names.extend([
                f"{name}-{year}",
                f"{name}-2023",
                f"{name}-2022",
                f"{name}-v1",
                f"{name}-v2",
                f"{name}-test",
                f"{name}-old"
            ])
        
        bucket_names.extend(extended_names)
        
        # 去重
        return list(set(bucket_names))
    
    def find_buckets(self, company_name, max_workers=50):
        """查找S3存储桶"""
        bucket_names = self.generate_bucket_names(company_name)
        print(f"[*] Generated {len(bucket_names)} potential bucket names")
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_bucket = {executor.submit(self.check_bucket_exists, bucket): bucket for bucket in bucket_names}
            
            for future in concurrent.futures.as_completed(future_to_bucket):
                bucket = future_to_bucket[future]
                try:
                    result = future.result()
                    if result.get('exists'):
                        # 检查详细权限
                        permissions = self.check_bucket_permissions(bucket)
                        result['permissions'] = permissions
                        result['bucket_name'] = bucket
                        results.append(result)
                        print(f"[+] Found bucket: {bucket}")
                except Exception as e:
                    print(f"[!] Error checking bucket {bucket}: {e}")
        
        return results
    
    def check_bucket_content(self, bucket_name):
        """检查存储桶内容"""
        try:
            url = f"https://{bucket_name}.s3.amazonaws.com/"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                # 解析XML响应
                import xml.etree.ElementTree as ET
                
                try:
                    root = ET.fromstring(response.content)
                    
                    objects = []
                    for contents in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
                        obj = {
                            'key': contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key').text,
                            'size': contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}Size').text,
                            'last_modified': contents.find('{http://s3.amazonaws.com/doc/2006-03-01/}LastModified').text
                        }
                        objects.append(obj)
                    
                    return {
                        'bucket_name': bucket_name,
                        'object_count': len(objects),
                        'objects': objects[:10]  # 只返回前10个对象
                    }
                except ET.ParseError:
                    return None
            
        except requests.exceptions.RequestException:
            pass
        
        return None

# Azure Blob存储发现
class AzureBlobFinder:
    def __init__(self):
        self.azure_endpoints = [
            'blob.core.windows.net',
            'dfs.core.windows.net'
        ]
    
    def check_blob_container(self, container_name):
        """检查Azure Blob容器"""
        try:
            # 尝试访问Azure Blob端点
            for endpoint in self.azure_endpoints:
                url = f"https://{container_name}.{endpoint}/?comp=list"
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    return {'exists': True, 'endpoint': endpoint, 'public': True}
                elif response.status_code == 403:
                    return {'exists': True, 'endpoint': endpoint, 'public': False}
            
            return {'exists': False}
        except:
            return {'exists': 'error'}
    
    def generate_container_names(self, company_name):
        """生成可能的容器名称"""
        # 类似于S3的模式，但针对Azure
        patterns = [
            '{company}data',
            '{company}blob',
            '{company}storage',
            '{company}files',
            '{company}assets'
        ]
        
        container_names = []
        company_variations = [
            company_name.lower(),
            company_name.lower().replace(' ', ''),
            company_name.lower().replace(' ', '-')
        ]
        
        for variation in company_variations:
            for pattern in patterns:
                container_names.append(pattern.format(company=variation))
        
        return list(set(container_names))

# 使用示例
s3_finder = S3BucketFinder()
buckets = s3_finder.find_buckets("targetcompany")

for bucket in buckets:
    print(f"Bucket: {bucket['bucket_name']}")
    print(f"Public: {bucket.get('public', 'Unknown')}")
    print(f"Permissions: {json.dumps(bucket.get('permissions', {}), indent=2)}")
    
    # 检查内容
    content = s3_finder.check_bucket_content(bucket['bucket_name'])
    if content:
        print(f"Object count: {content['object_count']}")
        for obj in content['objects'][:5]:
            print(f"  - {obj['key']} ({obj['size']} bytes)")
    print()
```

---

## 边缘资产识别

### 云资产发现

#### 多平台云资产扫描
```python
# cloud_asset_finder.py
import requests
import json
import concurrent.futures
from datetime import datetime

class CloudAssetFinder:
    def __init__(self):
        self.cloud_providers = {
            'aws': {
                'ip_ranges': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
                'services': ['EC2', 'S3', 'CloudFront', 'Route53', 'ELB']
            },
            'azure': {
                'ip_ranges': 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519',
                'services': ['VirtualMachine', 'Storage', 'CDN', 'DNS']
            },
            'gcp': {
                'ip_ranges': 'https://www.gstatic.com/ipranges/cloud.json',
                'services': ['ComputeEngine', 'CloudStorage', 'CloudDNS']
            }
        }
    
    def identify_cloud_assets(self, ip_addresses):
        """识别云资产"""
        results = {
            'aws': [],
            'azure': [],
            'gcp': [],
            'unknown': []
        }
        
        # 获取云IP范围
        cloud_ranges = self.get_cloud_ip_ranges()
        
        # 检查每个IP
        for ip in ip_addresses:
            provider = self.check_ip_cloud_provider(ip, cloud_ranges)
            if provider:
                results[provider].append(ip)
            else:
                results['unknown'].append(ip)
        
        return results
    
    def get_cloud_ip_ranges(self):
        """获取云提供商IP范围"""
        ranges = {}
        
        # AWS IP范围
        try:
            response = requests.get(self.cloud_providers['aws']['ip_ranges'], timeout=30)
            if response.status_code == 200:
                data = response.json()
                ranges['aws'] = data.get('prefixes', [])
        except:
            pass
        
        # Azure IP范围
        try:
            # Azure需要特殊处理，因为它是一个下载页面
            response = requests.get(self.cloud_providers['azure']['ip_ranges'], timeout=30)
            if response.status_code == 200:
                # 从页面中提取实际的JSON文件URL
                import re
                json_url_match = re.search(r'https://download.*?\.json', response.text)
                if json_url_match:
                    json_response = requests.get(json_url_match.group(), timeout=30)
                    if json_response.status_code == 200:
                        ranges['azure'] = json_response.json().get('values', [])
        except:
            pass
        
        # GCP IP范围
        try:
            response = requests.get(self.cloud_providers['gcp']['ip_ranges'], timeout=30)
            if response.status_code == 200:
                data = response.json()
                ranges['gcp'] = data.get('prefixes', [])
        except:
            pass
        
        return ranges
    
    def check_ip_cloud_provider(self, ip, cloud_ranges):
        """检查IP属于哪个云提供商"""
        import ipaddress
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # 检查AWS
            if 'aws' in cloud_ranges:
                for prefix in cloud_ranges['aws']:
                    if 'ip_prefix' in prefix:
                        network = ipaddress.ip_network(prefix['ip_prefix'])
                        if ip_obj in network:
                            return 'aws'
            
            # 检查Azure
            if 'azure' in cloud_ranges:
                for value in cloud_ranges['azure']:
                    if 'properties' in value and 'addressPrefixes' in value['properties']:
                        for prefix in value['properties']['addressPrefixes']:
                            network = ipaddress.ip_network(prefix)
                            if ip_obj in network:
                                return 'azure'
            
            # 检查GCP
            if 'gcp' in cloud_ranges:
                for prefix in cloud_ranges['gcp']:
                    if 'ipv4Prefix' in prefix:
                        network = ipaddress.ip_network(prefix['ipv4Prefix'])
                        if ip_obj in network:
                            return 'gcp'
        except:
            pass
        
        return None
    
    def find_cloud_endpoints(self, domain):
        """查找云端点"""
        endpoints = []
        
        # 常见的云端点模式
        cloud_patterns = [
            # AWS
            f'*.s3.amazonaws.com',
            f'{domain}.s3.amazonaws.com',
            f'*.cloudfront.net',
            f'{domain}.cloudfront.net',
            
            # Azure
            f'*.blob.core.windows.net',
            f'{domain}.blob.core.windows.net',
            f'*.azurewebsites.net',
            f'{domain}.azurewebsites.net',
            
            # GCP
            f'*.appspot.com',
            f'{domain}.appspot.com',
            f'*.storage.googleapis.com',
            f'{domain}.storage.googleapis.com'
        ]
        
        # 检查DNS记录
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            # 检查CNAME记录
            try:
                answers = resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata)
                    endpoints.append({
                        'type': 'CNAME',
                        'endpoint': cname,
                        'provider': self.identify_provider_from_hostname(cname)
                    })
            except:
                pass
            
            # 检查其他记录
            for record_type in ['A', 'AAAA', 'TXT']:
                try:
                    answers = resolver.resolve(domain, record_type)
                    for rdata in answers:
                        endpoints.append({
                            'type': record_type,
                            'endpoint': str(rdata),
                            'provider': 'unknown'
                        })
                except:
                    pass
        except:
            pass
        
        return endpoints
    
    def identify_provider_from_hostname(self, hostname):
        """从主机名识别云提供商"""
        provider_signatures = {
            'aws': ['amazonaws.com', 'cloudfront.net', 'elasticbeanstalk.com'],
            'azure': ['azurewebsites.net', 'blob.core.windows.net', 'cloudapp.azure.com'],
            'gcp': ['appspot.com', 'storage.googleapis.com', 'compute.amazonaws.com']
        }
        
        hostname_lower = hostname.lower()
        
        for provider, signatures in provider_signatures.items():
            for signature in signatures:
                if signature in hostname_lower:
                    return provider
        
        return 'unknown'

# 使用示例
finder = CloudAssetFinder()

# 识别云资产
ip_addresses = ['52.84.0.0', '13.107.42.14', '35.201.0.0']  # 示例IP
cloud_assets = finder.identify_cloud_assets(ip_addresses)

for provider, ips in cloud_assets.items():
    if ips:
        print(f"{provider.upper()} assets: {len(ips)} IPs")
        for ip in ips[:5]:  # 只显示前5个
            print(f"  - {ip}")

# 查找云端点
endpoints = finder.find_cloud_endpoints("targetdomain.com")
print(f"Found {len(endpoints)} cloud endpoints")
for endpoint in endpoints:
    print(f"  - {endpoint['type']}: {endpoint['endpoint']} ({endpoint['provider']})")
```

---

## 实战检查清单

### 子域名枚举
- [ ] 被动枚举工具已运行
- [ ] DNS爆破已执行
- [ ] CT日志已搜索
- [ ] 子域名已验证

### 端口扫描
- [ ] Masscan快速扫描已完成
- [ ] Nmap服务扫描已执行
- [ ] WAF检测已进行
- [ ] 扫描报告已生成

### 云资产发现
- [ ] S3存储桶已搜索
- [ ] Azure Blob已检查
- [ ] 云IP范围已分析
- [ ] 云端点已识别