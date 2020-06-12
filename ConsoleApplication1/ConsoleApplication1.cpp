// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
extern "C" {
    #include "Header1.h"
}



//typedef struct _CLIENT_ID
//{
//    HANDLE UniqueProcess;
//    HANDLE UniqueThread;
//} CLIENT_ID, * PCLIENT_ID;

void ErrorExit(const wchar_t * lpszFunction)
{
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    std::wcout << lpszFunction << TEXT(": ") << (LPCTSTR)lpMsgBuf;


    //MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    char c;
    std::cin.get(c);
    ExitProcess(dw);
}


DWORD GetServicePid(const char* name)
{
    SC_HANDLE theService, scm;
    SERVICE_STATUS m_SERVICE_STATUS;
    SERVICE_STATUS_PROCESS ssStatus;
    DWORD dwBytesNeeded;


    scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        return 0;
    }

    theService = OpenServiceA(scm, name, SERVICE_QUERY_STATUS);
    if (!theService) {
        CloseServiceHandle(scm);
        return 0;
    }

    auto result = QueryServiceStatusEx(theService, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssStatus), sizeof(SERVICE_STATUS_PROCESS),
        &dwBytesNeeded);

    CloseServiceHandle(theService);
    CloseServiceHandle(scm);

    if (result == 0) {
        return 0;
    }

    return ssStatus.dwProcessId;
}

//void GetProcessMaps(DWORD pid) {
//    auto processHandler = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, true, pid);
//    if (processHandler == NULL) {
//        std::cout << "Function failed \n";
//        ErrorExit(LPTSTR("GetProcessID"));
//    }
//   
//}

void getFilename(HANDLE hProcess, ULONG_PTR allocationBase, PUNICODE_STRING pattern)
{
    SIZE_T bufferSize;
    SIZE_T returnLength;
    PUNICODE_STRING buffer;

    bufferSize = 0x100;
    buffer = (PUNICODE_STRING)LocalAlloc(LPTR, bufferSize);
    NTSTATUS status;

    status = NtQueryVirtualMemory(
        hProcess,
        (PVOID)allocationBase,
        MemoryMappedFilenameInformation,
        buffer,
        bufferSize,
        &returnLength
    );

    if (status == STATUS_BUFFER_OVERFLOW)
    {
        LocalFree(buffer);
        bufferSize = returnLength;
        buffer = (PUNICODE_STRING)LocalAlloc(LPTR, bufferSize);

        status = NtQueryVirtualMemory(
            hProcess,
            (PVOID)allocationBase,
            MemoryMappedFilenameInformation,
            buffer,
            bufferSize,
            &returnLength
        );
    }
    if (status > 0)
    {
        LocalFree(buffer);
        ErrorExit(TEXT("NtQueryVirtualMemory Getfilename"));
    }
    if (buffer->Length != 0) {
        printf("Filename: %wZ\n", buffer);
        printf("Searched Filename: %wZ\n", pattern);

        if (RtlCompareUnicodeString(pattern, buffer, false) == 0) {
            printf("Unloading module ... ");
            if (NtUnmapViewOfSection(hProcess, (PVOID)allocationBase) < 0) {
                LocalFree(buffer);
                ErrorExit(TEXT("NtUnmapViewOfSection Getfilename"));
            }
            printf("done\n");
        }
        //compareFilenameToContain
    }
    
    LocalFree(buffer);


}

int PrintModules(DWORD processID)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    // Print the process identifier.

    printf("\nProcess ID: %u\n", processID);

    // Get a handle to the process.

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, processID);
    if (NULL == hProcess) {
        ErrorExit(TEXT("OpenProcess"));
    }

    printf("\nlisting all modules\n");
    // Get a list of all the modules in this process.
    //#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

    ULONG_PTR baseAddress(0);
    MEMORY_BASIC_INFORMATION basicInfo;

    if (NtQueryVirtualMemory(
        hProcess,
        (PVOID) baseAddress,
        MemoryBasicInformation,
        &basicInfo,
        sizeof(MEMORY_BASIC_INFORMATION),
        NULL
    ) > 0)
    {
        ErrorExit(TEXT("NtQueryVirtualMemory 1"));
    }
    BOOLEAN keepReading = TRUE;
    ULONG_PTR allocationBase;
    
    baseAddress = (ULONG_PTR)basicInfo.AllocationBase;
    std::cout << "initial baseAddress: 0x" << std::hex << baseAddress << std::endl;
    while (keepReading) {
        //char c;
        //std::cin.get(c);
        if (basicInfo.Type == MEM_MAPPED || basicInfo.Type == MEM_IMAGE) {
            //std::cout << "MEMMAPPED or IMAGE" << std::endl;
            allocationBase = (ULONG_PTR) basicInfo.AllocationBase;
            do {
                baseAddress = baseAddress + basicInfo.RegionSize;
                //std::cout << "RegionSize: 0x" << std::hex << basicInfo.RegionSize << std::endl;
                //std::cout << "baseAddress: 0x" << std::hex << baseAddress << std::endl;
                if (NtQueryVirtualMemory(
                    hProcess,
                    (PVOID) baseAddress,
                    MemoryBasicInformation,
                    &basicInfo,
                    sizeof(MEMORY_BASIC_INFORMATION),
                    NULL
                ) < 0) {
                    ErrorExit(TEXT("NtQueryVirtualMemory 2"));
                }
            } while ((ULONG_PTR)basicInfo.AllocationBase == allocationBase);
            //FIXME to get filename
            std::cout << "module_base_address: " << allocationBase << std::endl;
            UNICODE_STRING someStr;
            RtlInitUnicodeString(&someStr, L"\\Device\\HarddiskVolume3\\Windows\\System32\\gdi32.dll");
            getFilename(hProcess, allocationBase, &someStr);
        }
        else {
            //std::cout << "NOT MEMMAPPED or IMAGE" << std::endl;
            baseAddress = baseAddress + basicInfo.RegionSize;
            //std::cout << "RegionSize: 0x" << std::hex << basicInfo.RegionSize << std::endl;
            //std::cout << "baseAddress: 0x" << std::hex << baseAddress << std::endl;
            if (NtQueryVirtualMemory(
                hProcess,
                (PVOID)baseAddress,
                MemoryBasicInformation,
                &basicInfo,
                sizeof(MEMORY_BASIC_INFORMATION),
                NULL
            ) < 0) {
                ErrorExit(TEXT("NtQueryVirtualMemory 3"));
            }

        }

    }
    

    // Release the handle to the process.
    CloseHandle(hProcess);

    return 0;
}



int main()
{
    auto processID = GetServicePid("EventLog");
    if (processID != 0) {
        std::cout << "service found: Process ID " << processID << "\n";
        PrintModules(processID);
    }
    else {
        std::cout << "Service not found\n";
    }
    char c;
    std::cin.get(c);
}