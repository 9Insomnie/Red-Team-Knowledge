# OSINT (开源情报)

## 企业画像

### 组织架构收集

#### LinkedIn信息收集
```python
# linkedin_scraper.py
import requests
from bs4 import BeautifulSoup
import json
import time

class LinkedInScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def search_company(self, company_name):
        """搜索公司信息"""
        search_url = f"https://www.linkedin.com/company/{company_name.lower().replace(' ', '-')}/"
        
        try:
            response = self.session.get(search_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # 提取公司信息
                company_info = {
                    'name': self.extract_company_name(soup),
                    'industry': self.extract_industry(soup),
                    'size': self.extract_company_size(soup),
                    'website': self.extract_website(soup),
                    'specialties': self.extract_specialties(soup),
                    'description': self.extract_description(soup)
                }
                
                return company_info
        except Exception as e:
            print(f"[!] Error searching company: {e}")
            return None
    
    def extract_company_name(self, soup):
        """提取公司名称"""
        try:
            name_element = soup.find('h1', {'class': 'top-card-layout__title'})
            return name_element.text.strip() if name_element else None
        except:
            return None
    
    def extract_industry(self, soup):
        """提取行业信息"""
        try:
            industry_element = soup.find('div', {'class': 'top-card-layout__primary-description'})
            return industry_element.text.strip() if industry_element else None
        except:
            return None
    
    def extract_company_size(self, soup):
        """提取公司规模"""
        try:
            size_element = soup.find('div', {'class': 'top-card-layout__metadata-item'})
            return size_element.text.strip() if size_element else None
        except:
            return None
    
    def extract_website(self, soup):
        """提取网站"""
        try:
            website_element = soup.find('a', {'class': 'company-page-url'})
            return website_element['href'] if website_element else None
        except:
            return None
    
    def extract_specialties(self, soup):
        """提取专业领域"""
        try:
            specialties_element = soup.find('div', {'class': 'specialties'})
            return specialties_element.text.strip() if specialties_element else None
        except:
            return None
    
    def extract_description(self, soup):
        """提取公司描述"""
        try:
            desc_element = soup.find('div', {'class': 'about-us__description'})
            return desc_element.text.strip() if desc_element else None
        except:
            return None

# 使用示例
scraper = LinkedInScraper()
company_info = scraper.search_company("target-company")
print(json.dumps(company_info, indent=2))
```

#### 员工信息收集
```python
# employee_finder.py
import requests
import json
import re

class EmployeeFinder:
    def __init__(self):
        self.api_key = "your_hunter_api_key"
        self.base_url = "https://api.hunter.io/v2"
        
    def find_employees(self, domain, department=None):
        """查找公司员工"""
        url = f"{self.base_url}/domain-search"
        params = {
            'domain': domain,
            'api_key': self.api_key,
            'limit': 100
        }
        
        if department:
            params['department'] = department
        
        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                employees = []
                
                for email in data.get('data', {}).get('emails', []):
                    employee = {
                        'first_name': email.get('first_name'),
                        'last_name': email.get('last_name'),
                        'email': email.get('value'),
                        'position': email.get('position'),
                        'department': email.get('department'),
                        'linkedin': email.get('linkedin'),
                        'twitter': email.get('twitter')
                    }
                    employees.append(employee)
                
                return employees
        except Exception as e:
            print(f"[!] Error finding employees: {e}")
            return []
    
    def generate_email_patterns(self, domain):
        """生成邮箱格式模式"""
        common_patterns = [
            '{first}.{last}@{domain}',
            '{first}{last}@{domain}',
            '{first}@{domain}',
            '{last}@{domain}',
            '{first_initial}{last}@{domain}',
            '{first}{last_initial}@{domain}',
            '{first_initial}.{last}@{domain}',
            '{first}.{last_initial}@{domain}'
        ]
        
        return [pattern.format(domain=domain) for pattern in common_patterns]
    
    def verify_email(self, email):
        """验证邮箱有效性"""
        url = f"{self.base_url}/email-verifier"
        params = {
            'email': email,
            'api_key': self.api_key
        }
        
        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                return data.get('data', {})
        except Exception as e:
            print(f"[!] Error verifying email: {e}")
            return None

# 使用示例
finder = EmployeeFinder()
employees = finder.find_employees("targetdomain.com", "IT")
for employee in employees:
    print(f"{employee['first_name']} {employee['last_name']} - {employee['position']}")
```

### 技术栈指纹

#### 网站技术检测
```python
# tech_detector.py
import requests
import builtwith
import json

class TechStackDetector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; TechBot/1.0)'
        })
    
    def detect_website_tech(self, url):
        """检测网站技术栈"""
        try:
            # 使用builtwith库
            tech_info = builtwith.parse(url)
            
            # 自定义检测
            custom_info = self.custom_detection(url)
            
            # 合并结果
            full_info = {
                'builtwith': tech_info,
                'custom': custom_info
            }
            
            return full_info
        except Exception as e:
            print(f"[!] Error detecting tech stack: {e}")
            return None
    
    def custom_detection(self, url):
        """自定义检测"""
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            # 从headers提取信息
            server = headers.get('Server', 'Unknown')
            powered_by = headers.get('X-Powered-By', 'Unknown')
            aspnet_version = headers.get('X-AspNet-Version', 'Unknown')
            aspnetmvc_version = headers.get('X-AspNetMvc-Version', 'Unknown')
            
            # 从HTML内容提取
            content = response.text
            
            # 检测CMS
            cms = self.detect_cms(content)
            
            # 检测前端框架
            frontend = self.detect_frontend_framework(content)
            
            # 检测JavaScript库
            js_libraries = self.detect_js_libraries(content)
            
            # 检测CDN
            cdn = self.detect_cdn(content, headers)
            
            return {
                'server': server,
                'powered_by': powered_by,
                'aspnet_version': aspnet_version,
                'aspnetmvc_version': aspnetmvc_version,
                'cms': cms,
                'frontend_framework': frontend,
                'js_libraries': js_libraries,
                'cdn': cdn
            }
        except Exception as e:
            print(f"[!] Error in custom detection: {e}")
            return {}
    
    def detect_cms(self, content):
        """检测CMS"""
        cms_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Joomla': ['joomla', 'Joomla', 'com_content'],
            'Drupal': ['drupal', 'Drupal', 'sites/default'],
            'Magento': ['magento', 'Magento', 'Mage'],
            'Shopify': ['shopify', 'Shopify', 'cdn.shopify.com'],
            'Wix': ['wix', 'Wix', 'static.wixstatic.com']
        }
        
        content_lower = content.lower()
        detected_cms = []
        
        for cms, signatures in cms_signatures.items():
            for signature in signatures:
                if signature.lower() in content_lower:
                    detected_cms.append(cms)
                    break
        
        return detected_cms if detected_cms else ['Unknown']
    
    def detect_frontend_framework(self, content):
        """检测前端框架"""
        framework_signatures = {
            'React': ['react', 'React', '__REACT__'],
            'Angular': ['angular', 'Angular', 'ng-app'],
            'Vue.js': ['vue', 'Vue', 'v-if', 'v-for'],
            'Bootstrap': ['bootstrap', 'Bootstrap', 'bootstrap.min.css'],
            'jQuery': ['jquery', 'jQuery', '$.ajax'],
            'Dojo': ['dojo', 'Dojo', 'dojo.js'],
            'ExtJS': ['extjs', 'ExtJS', 'ext-all.js']
        }
        
        content_lower = content.lower()
        detected_frameworks = []
        
        for framework, signatures in framework_signatures.items():
            for signature in signatures:
                if signature.lower() in content_lower:
                    detected_frameworks.append(framework)
                    break
        
        return detected_frameworks if detected_frameworks else ['Unknown']
    
    def detect_js_libraries(self, content):
        """检测JavaScript库"""
        library_signatures = {
            'jQuery': ['jquery.min.js', 'jquery.js'],
            'Bootstrap': ['bootstrap.min.js', 'bootstrap.js'],
            'Moment.js': ['moment.min.js', 'moment.js'],
            'Lodash': ['lodash.min.js', 'lodash.js'],
            'Axios': ['axios.min.js', 'axios.js'],
            'Chart.js': ['chart.min.js', 'chart.js'],
            'D3.js': ['d3.min.js', 'd3.js']
        }
        
        content_lower = content.lower()
        detected_libraries = []
        
        for library, signatures in library_signatures.items():
            for signature in signatures:
                if signature.lower() in content_lower:
                    detected_libraries.append(library)
                    break
        
        return detected_libraries if detected_libraries else ['Unknown']
    
    def detect_cdn(self, content, headers):
        """检测CDN"""
        cdn_signatures = {
            'Cloudflare': ['cloudflare', '__cfduid', 'cf-ray'],
            'Akamai': ['akamai', 'akamai-edge'],
            'CloudFront': ['cloudfront', 'x-amz-cf-id'],
            'Fastly': ['fastly', 'x-fastly'],
            'MaxCDN': ['maxcdn', 'x-maxcdn'],
            'Incapsula': ['incapsula', 'x-iinfo']
        }
        
        detected_cdn = []
        
        # 检查headers
        for cdn, signatures in cdn_signatures.items():
            for signature in signatures:
                for header_name, header_value in headers.items():
                    if signature.lower() in header_name.lower() or signature.lower() in header_value.lower():
                        detected_cdn.append(cdn)
                        break
        
        # 检查内容
        content_lower = content.lower()
        for cdn, signatures in cdn_signatures.items():
            for signature in signatures:
                if signature.lower() in content_lower:
                    if cdn not in detected_cdn:
                        detected_cdn.append(cdn)
                    break
        
        return detected_cdn if detected_cdn else ['Unknown']

# 使用示例
detector = TechStackDetector()
tech_info = detector.detect_website_tech("https://targetdomain.com")
print(json.dumps(tech_info, indent=2))
```

---

## 代码泄露

### GitHub/GitLab搜索

#### 敏感信息搜索
```python
# github_search.py
import requests
import base64
import re
import json
from datetime import datetime, timedelta

class GitHubSearcher:
    def __init__(self, token):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'SecurityResearch/1.0'
        }
    
    def search_sensitive_data(self, target, search_type='code'):
        """搜索敏感数据"""
        search_queries = [
            f'"{target}" AND (password OR passwd OR pwd)',
            f'"{target}" AND (api_key OR apikey OR access_key)',
            f'"{target}" AND (secret_key OR secretkey)',
            f'"{target}" AND (aws_access_key_id OR aws_secret_access_key)',
            f'"{target}" AND (database_url OR db_url OR connection_string)',
            f'"{target}" AND (private_key OR rsa_private OR dsa_private)',
            f'"{target}" AND (oauth_token OR auth_token OR bearer)',
            f'"{target}" AND (smtp OR imap OR pop3)',
            f'"{target}" AND (ftp OR sftp)',
            f'"{target}" AND (ssh OR rdp OR vpn)'
        ]
        
        results = []
        
        for query in search_queries:
            try:
                search_results = self.search_code(query)
                for result in search_results:
                    if self.is_potentially_sensitive(result):
                        results.append({
                            'query': query,
                            'repository': result['repository']['full_name'],
                            'file_path': result['path'],
                            'url': result['html_url'],
                            'description': self.extract_sensitive_content(result)
                        })
                
                # 避免API限制
                time.sleep(1)
            except Exception as e:
                print(f"[!] Error searching GitHub: {e}")
        
        return results
    
    def search_code(self, query, per_page=30):
        """搜索代码"""
        url = f"{self.base_url}/search/code"
        params = {
            'q': query,
            'per_page': per_page,
            'sort': 'indexed',
            'order': 'desc'
        }
        
        response = requests.get(url, headers=self.headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            return data.get('items', [])
        else:
            print(f"[!] GitHub API error: {response.status_code}")
            return []
    
    def get_file_content(self, repo, path):
        """获取文件内容"""
        url = f"{self.base_url}/repos/{repo}/contents/{path}"
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            data = response.json()
            if 'content' in data:
                content = base64.b64decode(data['content']).decode('utf-8')
                return content
        
        return None
    
    def is_potentially_sensitive(self, result):
        """判断是否为潜在敏感信息"""
        sensitive_patterns = [
            r'password\s*=\s*["\'][^"\']{8,}["\']',
            r'api[_-]?key\s*=\s*["\'][^"\']{16,}["\']',
            r'secret[_-]?key\s*=\s*["\'][^"\']{16,}["\']',
            r'aws[_-]?access[_-]?key[_-]?id\s*=\s*["\']AKIA[0-9A-Z]{16}["\']',
            r'aws[_-]?secret[_-]?access[_-]?key\s*=\s*["\'][0-9A-Za-z/+=]{40}["\']',
            r'database[_-]?url\s*=\s*["\'][^"\']{10,}["\']',
            r'private[_-]?key\s*=\s*-+BEGIN\s+PRIVATE\s+KEY-+',
            r'ssh[_-]?key\s*=\s*-+BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-+',
            r'oauth[_-]?token\s*=\s*["\'][^"\']{20,}["\']',
            r'bearer\s+[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'
        ]
        
        repo = result['repository']['full_name']
        path = result['path']
        
        content = self.get_file_content(repo, path)
        if not content:
            return False
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def extract_sensitive_content(self, result):
        """提取敏感内容"""
        repo = result['repository']['full_name']
        path = result['path']
        
        content = self.get_file_content(repo, path)
        if not content:
            return None
        
        # 提取包含敏感信息的行
        sensitive_lines = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            if any(keyword in line.lower() for keyword in ['password', 'api_key', 'secret', 'token']):
                # 提取敏感信息周围的上下文
                start = max(0, i-2)
                end = min(len(lines), i+3)
                context = '\n'.join(lines[start:end])
                sensitive_lines.append(context)
        
        return sensitive_lines[:3]  # 只返回前3个敏感片段
    
    def search_recent_commits(self, target, days=7):
        """搜索最近的提交"""
        since_date = datetime.now() - timedelta(days=days)
        since_str = since_date.isoformat()
        
        search_queries = [
            f'"{target}" AND (password OR secret OR key) committer-date:>{since_str}',
            f'"{target}" AND (config OR settings) committer-date:>{since_str}'
        ]
        
        results = []
        
        for query in search_queries:
            try:
                url = f"{self.base_url}/search/commits"
                params = {
                    'q': query,
                    'per_page': 20
                }
                
                response = requests.get(url, headers=self.headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    commits = data.get('items', [])
                    
                    for commit in commits:
                        results.append({
                            'repository': commit['repository']['full_name'],
                            'commit_sha': commit['sha'],
                            'commit_message': commit['commit']['message'],
                            'author': commit['commit']['author']['name'],
                            'date': commit['commit']['author']['date'],
                            'url': commit['html_url']
                        })
                
                time.sleep(1)
            except Exception as e:
                print(f"[!] Error searching commits: {e}")
        
        return results

# 使用示例
searcher = GitHubSearcher("your_github_token")
results = searcher.search_sensitive_data("targetdomain.com")
print(json.dumps(results, indent=2))
```

### 泄露数据库利用

#### 社工库查询
```python
# breach_checker.py
import requests
import hashlib
import json

class BreachChecker:
    def __init__(self):
        self.haveibeenpwned_url = "https://haveibeenpwned.com/api/v3"
        self.headers = {
            'User-Agent': 'SecurityResearch-Contact-Security@targetdomain.com',
            'hibp-api-key': 'your_api_key'
        }
    
    def check_email_breaches(self, email):
        """检查邮箱泄露情况"""
        try:
            url = f"{self.haveibeenpwned_url}/breachedaccount/{email}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                breaches = response.json()
                return breaches
            elif response.status_code == 404:
                return []  # 未找到泄露记录
            else:
                print(f"[!] API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"[!] Error checking breaches: {e}")
            return None
    
    def check_password_breach(self, password):
        """检查密码泄露情况"""
        # 使用k-anonymity模型
        password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = password_hash[:5]
        suffix = password_hash[5:]
        
        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url)
            
            if response.status_code == 200:
                hashes = response.text.split('\r\n')
                for hash_line in hashes:
                    if ':' in hash_line:
                        hash_suffix, count = hash_line.split(':')
                        if hash_suffix == suffix:
                            return int(count)
                return 0  # 密码未泄露
            else:
                print(f"[!] API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"[!] Error checking password: {e}")
            return None
    
    def check_domain_breaches(self, domain):
        """检查域名泄露情况"""
        try:
            url = f"{self.haveibeenpwned_url}/breaches"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                all_breaches = response.json()
                domain_breaches = []
                
                for breach in all_breaches:
                    if domain.lower() in breach.get('Domain', '').lower():
                        domain_breaches.append({
                            'name': breach.get('Name'),
                            'title': breach.get('Title'),
                            'domain': breach.get('Domain'),
                            'breach_date': breach.get('BreachDate'),
                            'pwn_count': breach.get('PwnCount'),
                            'description': breach.get('Description'),
                            'data_classes': breach.get('DataClasses')
                        })
                
                return domain_breaches
            else:
                print(f"[!] API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"[!] Error checking domain breaches: {e}")
            return None
    
    def search_pastebin_leaks(self, domain):
        """搜索Pastebin泄露"""
        try:
            url = f"{self.haveibeenpwned_url}/pasteaccount/{domain}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                pastes = response.json()
                return pastes
            elif response.status_code == 404:
                return []
            else:
                print(f"[!] API error: {response.status_code}")
                return None
        except Exception as e:
            print(f"[!] Error searching pastebin: {e}")
            return None

# 使用示例
checker = BreachChecker()
breaches = checker.check_email_breaches("user@targetdomain.com")
print(json.dumps(breaches, indent=2))
```

---

## 历史数据

### Whois历史查询

#### 域名历史记录
```python
# whois_history.py
import whois
import json
import datetime

class WhoisHistory:
    def __init__(self):
        self.current_info = None
    
    def get_current_whois(self, domain):
        """获取当前Whois信息"""
        try:
            w = whois.whois(domain)
            self.current_info = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'zipcode': w.zipcode,
                'country': w.country
            }
            return self.current_info
        except Exception as e:
            print(f"[!] Error getting whois: {e}")
            return None
    
    def check_domain_age(self, domain):
        """检查域名年龄"""
        whois_info = self.get_current_whois(domain)
        if not whois_info:
            return None
        
        try:
            creation_date = whois_info.get('creation_date')
            if creation_date:
                creation_date = datetime.datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                current_date = datetime.datetime.now(datetime.timezone.utc)
                age_days = (current_date - creation_date).days
                age_years = age_days / 365.25
                
                return {
                    'creation_date': str(creation_date),
                    'age_days': age_days,
                    'age_years': round(age_years, 2),
                    'is_new': age_days < 365
                }
        except Exception as e:
            print(f"[!] Error calculating domain age: {e}")
            return None

# 使用示例
whois_checker = WhoisHistory()
domain_info = whois_checker.get_current_whois("targetdomain.com")
age_info = whois_checker.check_domain_age("targetdomain.com")
print(json.dumps(domain_info, indent=2))
print(json.dumps(age_info, indent=2))
```

### DNS历史记录

#### DNS变更历史
```python
# dns_history.py
import dns.resolver
import json
import datetime

class DNSHistory:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def get_current_dns_records(self, domain):
        """获取当前DNS记录"""
        records = {}
        
        # A记录
        try:
            answers = self.resolver.resolve(domain, 'A')
            records['A'] = [str(rdata) for rdata in answers]
        except:
            records['A'] = []
        
        # AAAA记录
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            records['AAAA'] = [str(rdata) for rdata in answers]
        except:
            records['AAAA'] = []
        
        # MX记录
        try:
            answers = self.resolver.resolve(domain, 'MX')
            records['MX'] = [{'preference': rdata.preference, 'exchange': str(rdata.exchange)} for rdata in answers]
        except:
            records['MX'] = []
        
        # NS记录
        try:
            answers = self.resolver.resolve(domain, 'NS')
            records['NS'] = [str(rdata) for rdata in answers]
        except:
            records['NS'] = []
        
        # TXT记录
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            records['TXT'] = [str(rdata).strip('"') for rdata in answers]
        except:
            records['TXT'] = []
        
        # CNAME记录
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            records['CNAME'] = [str(rdata) for rdata in answers]
        except:
            records['CNAME'] = []
        
        return records
    
    def get_mail_servers(self, domain):
        """获取邮件服务器信息"""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mail_servers = []
            
            for rdata in answers:
                server_info = {
                    'preference': rdata.preference,
                    'server': str(rdata.exchange),
                    'ip_addresses': []
                }
                
                # 获取邮件服务器的IP地址
                try:
                    ip_answers = self.resolver.resolve(str(rdata.exchange), 'A')
                    server_info['ip_addresses'] = [str(ip) for ip in ip_answers]
                except:
                    pass
                
                mail_servers.append(server_info)
            
            return sorted(mail_servers, key=lambda x: x['preference'])
        except Exception as e:
            print(f"[!] Error getting mail servers: {e}")
            return []
    
    def check_dns_security(self, domain):
        """检查DNS安全配置"""
        security_info = {
            'spf_record': False,
            'dkim_record': False,
            'dmarc_record': False,
            'dnssec_enabled': False
        }
        
        # 检查SPF记录
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=spf1'):
                    security_info['spf_record'] = txt_record
                    break
        except:
            pass
        
        # 检查DMARC记录
        try:
            answers = self.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=DMARC1'):
                    security_info['dmarc_record'] = txt_record
                    break
        except:
            pass
        
        # 检查DNSSEC (简化检查)
        try:
            answers = self.resolver.resolve(domain, 'DNSKEY')
            if answers:
                security_info['dnssec_enabled'] = True
        except:
            pass
        
        return security_info

# 使用示例
dns_checker = DNSHistory()
dns_records = dns_checker.get_current_dns_records("targetdomain.com")
mail_servers = dns_checker.get_mail_servers("targetdomain.com")
security_info = dns_checker.check_dns_security("targetdomain.com")

print("DNS Records:", json.dumps(dns_records, indent=2))
print("Mail Servers:", json.dumps(mail_servers, indent=2))
print("Security Info:", json.dumps(security_info, indent=2))
```

---

## 实战检查清单

### 企业画像收集
- [ ] 公司基本信息已收集
- [ ] 员工信息已整理
- [ ] 技术栈已识别
- [ ] 组织架构已绘制

### 代码泄露搜索
- [ ] GitHub敏感信息已搜索
- [ ] GitLab代码已检查
- [ ] 泄露数据库已查询
- [ ] Pastebin泄露已搜索

### 历史数据分析
- [ ] Whois历史已查询
- [ ] DNS记录已分析
- [ ] 域名年龄已确认
- [ ] DNS安全配置已检查