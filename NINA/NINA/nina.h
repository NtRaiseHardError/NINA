#pragma once

#include <Windows.h>

typedef LONG KPRIORITY;

typedef struct _MY_CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} MY_CLIENT_ID, * PMY_CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    MY_CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

#define ThreadBasicInformation 0
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

BOOL
InjectPayload(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE ThreadHandle,
    _In_ BOOL RestoreExecution
);