#include <stdio.h>
#include <Windows.h>

#include "nina.h"

int
main(
    _In_ int argc,
    _In_ char* argv[]
)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    BOOL ret;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    ZeroMemory(&pi, sizeof(pi));
    
    //
    // Do whatever you need to do here to get a target
    // process and thread handle.
    //
    ret = CreateProcessW(
        L"C:\\Windows\\System32\\calc.exe",
        //L"C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );
    
    InjectPayload(pi.hProcess, pi.hThread, TRUE);

    return 0;
}