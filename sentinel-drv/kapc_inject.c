/*
 * sentinel-drv/kapc_inject.c
 * KAPC injection infrastructure (Ch. 2/5 — APC-based DLL injection).
 *
 * When the image-load callback detects ntdll.dll being loaded into a new
 * user-mode process, this module:
 *   1. Resolves LdrLoadDll from ntdll's export table
 *   2. Allocates user-mode memory in the target process
 *   3. Writes a minimal x64 shellcode stub that calls LdrLoadDll
 *   4. Queues a user-mode APC via KeInitializeApc / KeInsertQueueApc
 *
 * The APC fires when the target thread becomes alertable (during early
 * process initialization), causing LdrLoadDll to load sentinel-hook.dll.
 *
 * IRQL: All functions run at PASSIVE_LEVEL (called from image-load callback).
 *
 * Book reference: Chapter 2 (injection), Chapter 5 (image-load trigger).
 */

#include <fltKernel.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#include "kapc_inject.h"
#include "constants.h"

/* ── Undocumented but stable kernel APIs ────────────────────────────────── */

NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

/*
 * KeInitializeApc / KeInsertQueueApc — exported but not in public headers.
 * These are stable across all Windows versions.
 */

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
);

typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
    _In_    PKAPC           Apc,
    _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ PVOID           *NormalContext,
    _Inout_ PVOID           *SystemArgument1,
    _Inout_ PVOID           *SystemArgument2
);

typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(
    _In_ PKAPC Apc
);

NTKERNELAPI
VOID
KeInitializeApc(
    _Out_   PKAPC               Apc,
    _In_    PKTHREAD            Thread,
    _In_    KAPC_ENVIRONMENT    Environment,
    _In_    PKKERNEL_ROUTINE    KernelRoutine,
    _In_opt_ PKRUNDOWN_ROUTINE  RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE   NormalRoutine,
    _In_    KPROCESSOR_MODE     ApcMode,
    _In_opt_ PVOID              NormalContext
);

NTKERNELAPI
BOOLEAN
KeInsertQueueApc(
    _Inout_ PKAPC   Apc,
    _In_opt_ PVOID  SystemArgument1,
    _In_opt_ PVOID  SystemArgument2,
    _In_    KPRIORITY Increment
);

NTKERNELAPI
BOOLEAN
KeTestAlertThread(
    _In_ KPROCESSOR_MODE AlertMode
);

/*
 * ZwProtectVirtualMemory — exported by ntoskrnl but not in public headers.
 */

NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID   *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   NewProtect,
    _Out_   PULONG  OldProtect
);

/* ── Constants ──────────────────────────────────────────────────────────── */

/*
 * Path to sentinel-hook.dll on the target VM.
 * Must be deployed to this location before injection.
 */
#define SENTINEL_HOOK_DLL_PATH  L"C:\\SentinelPOC\\sentinel-hook.dll"

/* Maximum number of tracked injected PIDs (POC limit) */
#define MAX_INJECTED_PIDS       1024

/* KAPC structure size on x64 (undocumented but stable) */
#define KAPC_SIZE               0x58

/* Shellcode buffer layout */
#define SHELLCODE_REGION_SIZE   0x1000  /* 4KB page — plenty of room */
#define UNICODE_STRING_OFFSET   0x000   /* UNICODE_STRING at start */
#define DLL_PATH_OFFSET         0x010   /* Wide string path after UNICODE_STRING */
#define SHELLCODE_OFFSET        0x200   /* Shellcode starts here */

/* ── Forward declarations ───────────────────────────────────────────────── */

static BOOLEAN
SentinelIsExcludedProcess(
    _In_ PEPROCESS Process
);

static BOOLEAN
SentinelIsAlreadyInjected(
    _In_ HANDLE ProcessId
);

static VOID
SentinelRecordInjection(
    _In_ HANDLE ProcessId
);

static PVOID
SentinelResolveLdrLoadDll(
    _In_ PVOID NtdllBase
);

static PVOID
SentinelAllocateAndWriteShellcode(
    _In_ PVOID  LdrLoadDllAddr,
    _In_ PVOID  ShellcodeRegionBase
);

static VOID NTAPI
SentinelKapcKernelRoutine(
    _In_    PKAPC           Apc,
    _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ PVOID           *NormalContext,
    _Inout_ PVOID           *SystemArgument1,
    _Inout_ PVOID           *SystemArgument2
);

static VOID NTAPI
SentinelKapcRundownRoutine(
    _In_ PKAPC Apc
);

/* ── Section placement ──────────────────────────────────────────────────── */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SentinelKapcInjectInit)
#pragma alloc_text(PAGE, SentinelKapcInjectStop)
#endif

/* ── State ──────────────────────────────────────────────────────────────── */

static BOOLEAN  g_KapcInitialized = FALSE;
static KSPIN_LOCK g_InjectedPidsLock;
static HANDLE   g_InjectedPids[MAX_INJECTED_PIDS];
static ULONG    g_InjectedPidCount = 0;

/*
 * Ntdll base tracking: when ntdll.dll loads (Phase 1), we save the base
 * address so that when kernel32.dll loads (Phase 2) we can resolve LdrLoadDll.
 */
typedef struct _NTDLL_ENTRY {
    HANDLE  ProcessId;
    PVOID   NtdllBase;
} NTDLL_ENTRY;

static KSPIN_LOCK g_NtdllLock;
static NTDLL_ENTRY g_NtdllEntries[MAX_INJECTED_PIDS];
static ULONG       g_NtdllEntryCount = 0;

/* ── Exclusion list (ASCII — matches PsGetProcessImageFileName) ────────── */

static const CHAR* g_InjectionExclusions[] = {
    "System",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "MsMpEng.exe",
    "winlogon.exe",
    "fontdrvhost.ex",   /* PsGetProcessImageFileName truncates to 15 chars */
    "dwm.exe",
    "RuntimeBroker.",   /* truncated */
    "SearchHost.exe",
    "sihost.exe",
    "taskhostw.exe",
    "explorer.exe",
};

#define EXCLUSION_COUNT  (sizeof(g_InjectionExclusions) / sizeof(g_InjectionExclusions[0]))

/* ── Public API ─────────────────────────────────────────────────────────── */

NTSTATUS
SentinelKapcInjectInit(VOID)
{
    PAGED_CODE();

    if (g_KapcInitialized) {
        return STATUS_SUCCESS;
    }

    KeInitializeSpinLock(&g_InjectedPidsLock);
    RtlZeroMemory(g_InjectedPids, sizeof(g_InjectedPids));
    g_InjectedPidCount = 0;

    KeInitializeSpinLock(&g_NtdllLock);
    RtlZeroMemory(g_NtdllEntries, sizeof(g_NtdllEntries));
    g_NtdllEntryCount = 0;
    g_KapcInitialized = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: KAPC injection initialized (hook DLL: %ls)\n",
        SENTINEL_HOOK_DLL_PATH));

    return STATUS_SUCCESS;
}

VOID
SentinelKapcInjectStop(VOID)
{
    PAGED_CODE();

    if (!g_KapcInitialized) {
        return;
    }

    g_KapcInitialized = FALSE;
    g_InjectedPidCount = 0;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: KAPC injection stopped\n"));
}

/* ── Phase 1: Save ntdll base ──────────────────────────────────────────── */

VOID
SentinelKapcSaveNtdllBase(
    _In_ HANDLE ProcessId,
    _In_ PVOID  NtdllBase
)
{
    KIRQL oldIrql;

    if (!g_KapcInitialized) {
        return;
    }

    KeAcquireSpinLock(&g_NtdllLock, &oldIrql);

    if (g_NtdllEntryCount < MAX_INJECTED_PIDS) {
        g_NtdllEntries[g_NtdllEntryCount].ProcessId = ProcessId;
        g_NtdllEntries[g_NtdllEntryCount].NtdllBase = NtdllBase;
        g_NtdllEntryCount++;
    }

    KeReleaseSpinLock(&g_NtdllLock, oldIrql);
}

static PVOID
SentinelLookupNtdllBase(
    _In_ HANDLE ProcessId
)
{
    KIRQL oldIrql;
    PVOID base = NULL;
    ULONG i;

    KeAcquireSpinLock(&g_NtdllLock, &oldIrql);

    for (i = 0; i < g_NtdllEntryCount; i++) {
        if (g_NtdllEntries[i].ProcessId == ProcessId) {
            base = g_NtdllEntries[i].NtdllBase;
            break;
        }
    }

    KeReleaseSpinLock(&g_NtdllLock, oldIrql);
    return base;
}

/* ── Phase 2: Main injection entry point ───────────────────────────────── */

VOID
SentinelKapcTryInject(
    _In_ HANDLE ProcessId
)
{
    PEPROCESS       process = NULL;
    NTSTATUS        status;
    PVOID           ldrLoadDll = NULL;
    PVOID           shellcodeRegion = NULL;
    SIZE_T          regionSize = SHELLCODE_REGION_SIZE;
    PVOID           shellcodeEntry = NULL;
    PKAPC           kapc = NULL;

    if (!g_KapcInitialized) {
        return;
    }

    /* Look up the target process */
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status) || !process) {
        return;
    }

    __try {
        /* ── Filter: excluded processes ─────────────────────────────────── */

        if (SentinelIsExcludedProcess(process)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "SentinelPOC: KAPC skip excluded PID=%lu\n",
                (ULONG)(ULONG_PTR)ProcessId));
            __leave;
        }

        /* ── Filter: already injected ───────────────────────────────────── */

        if (SentinelIsAlreadyInjected(ProcessId)) {
            __leave;
        }

        /* ── Step 1: Resolve LdrLoadDll from ntdll export table ────────── */

        /*
         * Look up the ntdll base address saved during Phase 1 (ntdll load).
         * We're now in Phase 2 (kernel32 load), on the target process's
         * initial thread — safe to resolve exports and queue APCs.
         */
        {
            PVOID ntdllBase = SentinelLookupNtdllBase(ProcessId);
            if (!ntdllBase) {
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "SentinelPOC: No saved ntdll base for PID=%lu\n",
                    (ULONG)(ULONG_PTR)ProcessId));
                __leave;
            }

            ldrLoadDll = SentinelResolveLdrLoadDll(ntdllBase);
        }

        if (!ldrLoadDll) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "SentinelPOC: Failed to resolve LdrLoadDll PID=%lu\n",
                (ULONG)(ULONG_PTR)ProcessId));
            __leave;
        }

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "SentinelPOC: LdrLoadDll resolved at 0x%p for PID=%lu\n",
            ldrLoadDll, (ULONG)(ULONG_PTR)ProcessId));

        /* ── Step 2: Allocate user-mode memory in target process ───────── */

        /*
         * We're running in the image-load callback which fires in the
         * target process's thread context. Use NtCurrentProcess() to
         * allocate memory directly — no need to open a process handle.
         */
        shellcodeRegion = NULL;
        regionSize = SHELLCODE_REGION_SIZE;

        status = ZwAllocateVirtualMemory(
            NtCurrentProcess(),
            &shellcodeRegion,
            0,
            &regionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);

        if (!NT_SUCCESS(status)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "SentinelPOC: ZwAllocateVirtualMemory failed 0x%08X PID=%lu\n",
                status, (ULONG)(ULONG_PTR)ProcessId));
            __leave;
        }

        /* ── Step 3: Write shellcode + DLL path into allocated region ──── */

        /*
         * Since we're in the target process's address space, write
         * directly via RtlCopyMemory — no need for ZwWriteVirtualMemory.
         */
        shellcodeEntry = SentinelAllocateAndWriteShellcode(
            ldrLoadDll, shellcodeRegion);

        if (!shellcodeEntry) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "SentinelPOC: Shellcode write failed PID=%lu\n",
                (ULONG)(ULONG_PTR)ProcessId));
            /* Free the allocated region */
            regionSize = 0;
            ZwFreeVirtualMemory(NtCurrentProcess(), &shellcodeRegion, &regionSize, MEM_RELEASE);
            __leave;
        }

        /* ── Step 4: Queue KAPC ─────────────────────────────────────────── */

        kapc = (PKAPC)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, KAPC_SIZE, SENTINEL_TAG_KAPC);
        if (!kapc) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "SentinelPOC: KAPC allocation failed PID=%lu\n",
                (ULONG)(ULONG_PTR)ProcessId));
            __leave;
        }

        KeInitializeApc(
            kapc,
            KeGetCurrentThread(),           /* We're in the target's thread context */
            OriginalApcEnvironment,
            SentinelKapcKernelRoutine,      /* Frees KAPC on delivery */
            SentinelKapcRundownRoutine,     /* Frees KAPC if thread dies */
            (PKNORMAL_ROUTINE)shellcodeEntry,
            UserMode,
            NULL                            /* NormalContext */
        );

        if (!KeInsertQueueApc(kapc, NULL, NULL, 0)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "SentinelPOC: KeInsertQueueApc failed PID=%lu\n",
                (ULONG)(ULONG_PTR)ProcessId));
            ExFreePoolWithTag(kapc, SENTINEL_TAG_KAPC);
            __leave;
        }

        /*
         * Force user-mode APC delivery. We're now on the target process's
         * initial thread (kernel32.dll trigger), so this is safe.
         * KeTestAlertThread sets the UserApcPending flag, ensuring
         * delivery when the thread returns to user mode.
         */
        KeTestAlertThread(UserMode);

        /* Record successful injection */
        SentinelRecordInjection(ProcessId);

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "SentinelPOC: KAPC queued for PID=%lu (shellcode=0x%p, LdrLoadDll=0x%p)\n",
            (ULONG)(ULONG_PTR)ProcessId, shellcodeEntry, ldrLoadDll));

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: Exception 0x%08X in KAPC injection PID=%lu\n",
            GetExceptionCode(), (ULONG)(ULONG_PTR)ProcessId));
    }

    ObDereferenceObject(process);
}

/* ── Exclusion check ────────────────────────────────────────────────────── */

static BOOLEAN
SentinelIsExcludedProcess(
    _In_ PEPROCESS Process
)
{
    PCHAR   imageName;
    ULONG   i;

    imageName = PsGetProcessImageFileName(Process);
    if (!imageName || imageName[0] == '\0') {
        return TRUE;    /* Can't determine name — exclude for safety */
    }

    for (i = 0; i < EXCLUSION_COUNT; i++) {
        if (_stricmp(imageName, g_InjectionExclusions[i]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

/* ── Injection tracking ─────────────────────────────────────────────────── */

static BOOLEAN
SentinelIsAlreadyInjected(
    _In_ HANDLE ProcessId
)
{
    KIRQL   oldIrql;
    ULONG   i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_InjectedPidsLock, &oldIrql);

    for (i = 0; i < g_InjectedPidCount; i++) {
        if (g_InjectedPids[i] == ProcessId) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_InjectedPidsLock, oldIrql);
    return found;
}

static VOID
SentinelRecordInjection(
    _In_ HANDLE ProcessId
)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_InjectedPidsLock, &oldIrql);

    if (g_InjectedPidCount < MAX_INJECTED_PIDS) {
        g_InjectedPids[g_InjectedPidCount++] = ProcessId;
    }

    KeReleaseSpinLock(&g_InjectedPidsLock, oldIrql);
}

/* ── LdrLoadDll export resolution ───────────────────────────────────────── */

/*
 * Parse the PE export table of the mapped ntdll.dll to find LdrLoadDll.
 * The ntdll image is already mapped into the target process's user-mode
 * address space when the image-load callback fires.
 *
 * Since we're running in the target process's context (image-load callback
 * fires in-process), we can directly read the mapped ntdll memory.
 */
static PVOID
SentinelResolveLdrLoadDll(
    _In_ PVOID NtdllBase
)
{
    PIMAGE_DOS_HEADER       dosHeader;
    PIMAGE_NT_HEADERS64     ntHeaders;
    PIMAGE_EXPORT_DIRECTORY exportDir;
    PULONG                  addressOfFunctions;
    PULONG                  addressOfNames;
    PUSHORT                 addressOfOrdinals;
    ULONG                   exportDirRva;
    ULONG                   i;

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)NtdllBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return NULL;
        }

        ntHeaders = (PIMAGE_NT_HEADERS64)(
            (PUCHAR)NtdllBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return NULL;
        }

        /* Get export directory */
        if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
            return NULL;
        }

        exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (exportDirRva == 0) {
            return NULL;
        }

        exportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)NtdllBase + exportDirRva);

        addressOfFunctions = (PULONG)((PUCHAR)NtdllBase + exportDir->AddressOfFunctions);
        addressOfNames     = (PULONG)((PUCHAR)NtdllBase + exportDir->AddressOfNames);
        addressOfOrdinals  = (PUSHORT)((PUCHAR)NtdllBase + exportDir->AddressOfNameOrdinals);

        /* Walk export names to find "LdrLoadDll" */
        for (i = 0; i < exportDir->NumberOfNames; i++) {
            PCHAR funcName = (PCHAR)((PUCHAR)NtdllBase + addressOfNames[i]);

            if (strcmp(funcName, "LdrLoadDll") == 0) {
                USHORT ordinal = addressOfOrdinals[i];
                ULONG  funcRva = addressOfFunctions[ordinal];

                return (PVOID)((PUCHAR)NtdllBase + funcRva);
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: Exception 0x%08X resolving LdrLoadDll\n",
            GetExceptionCode()));
    }

    return NULL;
}

/* ── Shellcode generation & writing ─────────────────────────────────────── */

/*
 * Write the DLL path (UNICODE_STRING + raw path) and x64 shellcode stub
 * into the previously allocated user-mode memory region.
 *
 * Memory layout within the allocated page:
 *
 *   [0x000] UNICODE_STRING { Length, MaxLength, Buffer }
 *   [0x010] L"\\??\\C:\\SentinelPOC\\sentinel-hook.dll\0"
 *   [0x200] x64 shellcode:
 *           sub  rsp, 0x28          ; 0x28 = shadow space (0x20) + alignment
 *           xor  ecx, ecx           ; arg1: SearchPath = NULL
 *           xor  edx, edx           ; arg2: DllCharacteristics = 0
 *           lea  r8, [rip - offset] ; arg3: -> UNICODE_STRING at [0x000]
 *           lea  r9, [rsp + 0x20]   ; arg4: -> ModuleHandle (stack scratch)
 *           mov  rax, <LdrLoadDll>  ; absolute address
 *           call rax
 *           add  rsp, 0x28
 *           ret
 *
 * LdrLoadDll signature:
 *   NTSTATUS LdrLoadDll(
 *     PWSTR SearchPath,             // RCX = NULL
 *     PULONG DllCharacteristics,    // RDX = NULL
 *     PUNICODE_STRING DllName,      // R8  = -> our UNICODE_STRING
 *     PVOID *BaseAddress            // R9  = -> stack scratch
 *   );
 */
static PVOID
SentinelAllocateAndWriteShellcode(
    _In_ PVOID  LdrLoadDllAddr,
    _In_ PVOID  ShellcodeRegionBase
)
{
    NTSTATUS    status;
    SIZE_T      regionSize;
    PVOID       protectBase;
    ULONG       oldProtect;
    PVOID       shellcodeAddr;

    /* DLL path as wide string */
    static const WCHAR dllPath[] = SENTINEL_HOOK_DLL_PATH;
    USHORT pathLen = (USHORT)(wcslen(dllPath) * sizeof(WCHAR));

    /*
     * We're in the target process's address space, so write directly.
     * Zero the region first, then fill in each section.
     */
    RtlZeroMemory(ShellcodeRegionBase, SHELLCODE_REGION_SIZE);

    /*
     * UNICODE_STRING at offset 0x000:
     *   USHORT Length        (bytes, not including null)
     *   USHORT MaximumLength (bytes, including null)
     *   PVOID  Buffer        (pointer to string in target process)
     */
    {
        USHORT *pLength    = (USHORT *)((PUCHAR)ShellcodeRegionBase + UNICODE_STRING_OFFSET);
        USHORT *pMaxLength = (USHORT *)((PUCHAR)ShellcodeRegionBase + UNICODE_STRING_OFFSET + 2);
        PVOID  *pBuffer    = (PVOID  *)((PUCHAR)ShellcodeRegionBase + UNICODE_STRING_OFFSET + 8);  /* x64: offset 8 for alignment */

        *pLength    = pathLen;
        *pMaxLength = pathLen + sizeof(WCHAR);
        *pBuffer    = (PVOID)((PUCHAR)ShellcodeRegionBase + DLL_PATH_OFFSET);
    }

    /* DLL path at offset 0x010 */
    RtlCopyMemory((PUCHAR)ShellcodeRegionBase + DLL_PATH_OFFSET, dllPath, pathLen + sizeof(WCHAR));

    /*
     * x64 shellcode at offset 0x200.
     *
     * We need a RIP-relative LEA to point R8 at the UNICODE_STRING
     * at offset 0x000. The shellcode is at 0x200, so the relative
     * offset from the LEA instruction to 0x000 must be computed.
     */
    {
        UCHAR *sc = (UCHAR *)ShellcodeRegionBase + SHELLCODE_OFFSET;
        ULONG idx = 0;
        LONG  unicodeStringRipOffset;

        /* sub rsp, 0x28 */
        sc[idx++] = 0x48; sc[idx++] = 0x83; sc[idx++] = 0xEC; sc[idx++] = 0x28;

        /* xor ecx, ecx  (SearchPath = NULL) */
        sc[idx++] = 0x33; sc[idx++] = 0xC9;

        /* xor edx, edx  (DllCharacteristics = NULL) */
        sc[idx++] = 0x33; sc[idx++] = 0xD2;

        /* lea r8, [rip + offset]  -> UNICODE_STRING at base+0x000 */
        /* RIP at this point = base + 0x200 + idx + 7 (size of this instruction) */
        /* Target = base + 0x000 */
        /* Offset = target - rip = 0x000 - (0x200 + idx + 7) */
        sc[idx++] = 0x4C; sc[idx++] = 0x8D; sc[idx++] = 0x05;  /* lea r8, [rip+disp32] */
        unicodeStringRipOffset = (LONG)(UNICODE_STRING_OFFSET - (SHELLCODE_OFFSET + idx + 4));
        RtlCopyMemory(&sc[idx], &unicodeStringRipOffset, 4);
        idx += 4;

        /* lea r9, [rsp + 0x20]  (ModuleHandle — stack scratch space) */
        sc[idx++] = 0x4C; sc[idx++] = 0x8D; sc[idx++] = 0x4C; sc[idx++] = 0x24; sc[idx++] = 0x20;

        /* mov rax, <LdrLoadDll address> */
        sc[idx++] = 0x48; sc[idx++] = 0xB8;  /* movabs rax, imm64 */
        RtlCopyMemory(&sc[idx], &LdrLoadDllAddr, 8);
        idx += 8;

        /* call rax */
        sc[idx++] = 0xFF; sc[idx++] = 0xD0;

        /* add rsp, 0x28 */
        sc[idx++] = 0x48; sc[idx++] = 0x83; sc[idx++] = 0xC4; sc[idx++] = 0x28;

        /* ret */
        sc[idx++] = 0xC3;
    }

    /* Change protection to RX (no write) */
    protectBase = ShellcodeRegionBase;
    regionSize  = SHELLCODE_REGION_SIZE;

    status = ZwProtectVirtualMemory(
        NtCurrentProcess(),
        &protectBase,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect);

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "SentinelPOC: ZwProtectVirtualMemory failed 0x%08X\n", status));
        /* Continue anyway — RW memory is still executable on some configs */
    }

    /* Return pointer to shellcode entry within the allocated region */
    shellcodeAddr = (PVOID)((PUCHAR)ShellcodeRegionBase + SHELLCODE_OFFSET);
    return shellcodeAddr;
}

/* ── KAPC callback routines ─────────────────────────────────────────────── */

/*
 * KernelRoutine — called when the APC is delivered.
 * Free the pool-allocated KAPC structure.
 */
static VOID NTAPI
SentinelKapcKernelRoutine(
    _In_    PKAPC           Apc,
    _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ PVOID           *NormalContext,
    _Inout_ PVOID           *SystemArgument1,
    _Inout_ PVOID           *SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    ExFreePoolWithTag(Apc, SENTINEL_TAG_KAPC);
}

/*
 * RundownRoutine — called if the thread terminates before APC delivery.
 * Free the pool-allocated KAPC structure.
 */
static VOID NTAPI
SentinelKapcRundownRoutine(
    _In_ PKAPC Apc
)
{
    ExFreePoolWithTag(Apc, SENTINEL_TAG_KAPC);
}
