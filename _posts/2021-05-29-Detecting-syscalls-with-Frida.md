---
layout: default
title: Detecting Direct Syscalls with Frida
permalink: /detecting-direct-syscalls-with-frida
---

# Detecting direct syscalls with Frida

In my last post I talked about checking the integrity of hooks placed on NTDLL with Frida. In that post I mentioned how utilizing direct syscalls is a good way of avoiding any hooks placed on NTDLL. After that I was curious if there was a good way to detect the use of direct syscalls, so I spent some more time hacking on Frida. 

In this post we'll look at:

- Brief summary of direct syscalls
- Using Frida's Stalker engine to trace code
- Alerting when we detect a suspicious syscall

I'd also like to state my thesis at the top here to potentially save people some time. This probably isn't novel and it's a pretty straightforward detection, you could do this exact same thing with really any debugger or tracer. The way I'm trying to detect the syscalls is by looking at every executed instruction, and if it's a syscall then I check if it is within the bounds of the loaded NTDLL. If it is then it's a normal syscall, if it's not then it may be suspicious.

Note: After posting this I found this blog from [winternl](https://winternl.com/detecting-manual-syscalls-from-user-mode/) which describes using the same detection parameters but with the Nirvana engine from Microsoft.

## What are direct syscalls?

There's several great resources that explain this concept much better than I can, which I'll link here.

- [Combining Direct System Calls and sRDI - Outflank](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
- [Retrieving ntdll Syscall Stubs from Disk at Run-time - ired.team](https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time?q=riv)
- [Hell's Gate - Am0nsec](https://github.com/am0nsec/HellsGate)

In case you don't feel like clicking links, I'll provide a brief synopsis. When a Windows API call needs to transition to kernel mode, it will populate the eax register with the appropriate syscall number and then use a syscall instruction. This tells the CPU that we are requesting a transition to kernel-mode. Since EDR products were largely forced out of kernel by PatchGuard and have limited callbacks provided by kernel notifications, they don't really have a lot of insight into the kernel. So once a syscall transitions into kernel-mode, any EDR that is just relying on userland hooking will be blind.

We can use these syscalls in our own code directly in a few ways. Since syscall numbers change across Windows versions, we have two options: Include a table of syscalls that correspond to the Windows version, or dynamically resolve them at runtime. Once we have the syscall number then we can declare a function prototype for an NTDLL function and point it at our syscall stub. Then we can call that function like normal, which will then populate the appropriate registers and divert execution to the syscall stub.

## Being a stalker

The Frida API that I see used most often is Interceptor, which provides an interface for hooking and instrumenting functions. This doesn't do us any good here, since direct syscalls can't be hooked in this manner. While we could try to hook the functions leading up to the syscall, like reading NTDLL from disk or making the syscall RWX with VirtualProtect, I'm more interested in locating syscalls without any hook. To that end we can make use of another Frida component: Stalker. Stalker is Frida's code tracing engine which allows us to trace all of the instructions for a given thread. 

I took a few runs at this by parsing the events and looking for syscall instructions using the provided callbacks but either the coverage is incomplete or I was instrumenting it wrong (I suspect it was the latter). I would see all of the legitimate syscalls in my program, but none of the direct ones. 

I'll take a second to walk through my detection methodology here as it is what I ended up using once I figured it out. Detecting a syscall via code tracing is pretty simple as there's certain assembly instructions that every syscall must call. This is the anatomy of a syscall.

```c
mov r10,rcx
mov eax,*SYSCALL NUMBER*
test byte ptr [someaddress]
jne [ntdll function address]
syscall
ret
```

So the most obvious target here is the syscall instruction, as every syscall must call it by definition. 

**Note**: The **int 2eh** instruction can be used instead of syscall, which is the legacy method of calling them. So if we do want to detect on syscall instructions we should also monitor for **int 2eh**.

That said, I decided to target the **mov r10,rcx** instruction for the purposes of research because it allowed me to inspect the next instruction and determine if it was the syscall number that I was expecting. I was using NtCreateFile and NtOpenProcess for testing, which correspond to 0x26 and 0x55 respectively. 

Now let's walk through the Frida script.

```jsx
var modules = Process.enumerateModules()
var ntdll = modules[1]

var ntdllBase = ntdll.base
send("[*] Ntdll base: " + ntdllBase)
var ntdllOffset = ntdllBase.add(ntdll.size)
send("[*] Ntdll end: " + ntdllOffset)
```

To start off we'll get the information for NTDLL and store the base plus the end, which is the base + the size.

```jsx
Process.enumerateThreads().map(t => {
Stalker.follow(t.id, {
  events: {
    call: false, // CALL instructions: yes please
    // Other events:
    ret: false, // RET instructions
    exec: false, // all instructions: not recommended as it's
                 //                   a lot of data
    block: false, // block executed: coarse execution trace
    compile: false // block compiled: useful for coverage
  },
  onReceive(events) {},
  transform(iterator){
      
  }
})
})
```

For each thread in the process we will assign a stalker to it. In each stalker, we don't actually need to capture any events since we're going to do the work with a transform iterator instead.

## What the hell is a transformer?

This is something I spent a while figuring out since the Frida docs can be a bit confusing if you're still new to it (which I very much am). Basically, we can specify some custom code for processing every single instruction. The problem with implementing events in one of the Stalker callbacks (onReceive or onSummary) is that they are not called synchronously: they receive a summary of events that have already occurred. When I was trying to implement this via callbacks I was getting events after the process had already terminated, which helped me to realize that wasn't the solution.

So anyways, the Frida docs specify that the default transformer is as follows. The default behavior is to do nothing.

```jsx
while (iterator.next() !== null)
       iterator.keep();
```

Iterators are kind of a weird topic that absolutely baffled me in college and my understanding is still pretty surface level. In general, an iterator provides a collection of items that we can cycle through by calling the **.next()** method to receive the next item. So in the above example, each item will be a CPU instruction. The .keep() method allows the user to specify whether or not the instruction should be dropped. If we do not call the .keep() method then the instruction will not be executed, which is useful if we want to insert our own instructions in there somewhere.

We can implement our own basic syscall finder transformer as follows.

```jsx
transform(iterator){
	let instruction = iterator.next()
	do{
		if(instruction.mnemonic == "syscall"){
			send("Found syscall!")
		}
		iterator.keep()
	} while ((instruction = iterator.next()) !== null)
}
```

This will iterate through all instructions and check if the instruction is a syscall. If it is, then we will send a message to the user that we have found a syscall and then proceed as normal.

As I mentioned earlier, I opted to alert on the **mov r10, rcx** instruction instead. This is what our final transformer will end up looking like.

```jsx
transform(iterator){
let instruction = iterator.next()
      do{
        //I think this reduces overhead
        if(instruction.mnemonic == "mov"){
            //Should provide a good filter for syscalls, might need further filtering
            if(instruction.toString() == "mov r10, rcx"){
                iterator.keep() //keep the instruction
                instruction = iterator.next() //next instruction should have the syscall number
                var addrInt = instruction.address.toInt32()
                //If the syscall is coming from somewhere outside the bounds of NTDLL
                //then it may be malicious
                if(addrInt < ntdllBase.toInt32() || addrInt > ntdllOffset.toInt32()){
                    send("[+] Found a potentially malicious syscall: " + instruction.toString())
                }
                else{
                    send("[-] Just a normal syscall: " + instruction.toString())
                }
            }
        }
        iterator.keep()
      } while ((instruction = iterator.next()) !== null)
}
```

We will check if the instruction is a mov instruction first. I think this has a lower overhead than stringifying the instruction and checking for mov r10, rcx. If it is a mov then we will perform that check. Then we'll keep the current instruction, and get the next one which will contain our syscall number. Then to check if it is potentially malicious, we will check if the address is outside the bounds of NTDLL. If it is then we will report it as such.

In this example we'll just alert and proceed to avoid messing up the execution flow. But if we wanted to then we could do something more advanced like check the syscall number and parse the registers appropriately to check the arguments. By doing this we could potentially check if a syscall to NtCreateFile is going to C:\Windows\System32\ntdll.dll.

## Testing on some syscalls

To implement syscalls, we can use some code from [ired.team](http://ired.team). You can find the original code [here](https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time).

```cpp
#include <iostream>
#include "Windows.h"
#include "winternl.h"
#pragma comment(lib, "ntdll")

int const SYSCALL_STUB_SIZE = 23;
using myNtCreateFile = NTSTATUS(NTAPI*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

PVOID RVAtoRawOffset(DWORD_PTR RVA, PIMAGE_SECTION_HEADER section)
{
	return (PVOID)(RVA - section->VirtualAddress + section->PointerToRawData);
}

BOOL GetSyscallStub(LPCSTR functionName, PIMAGE_EXPORT_DIRECTORY exportDirectory, LPVOID fileData, PIMAGE_SECTION_HEADER textSection, PIMAGE_SECTION_HEADER rdataSection, LPVOID syscallStub)
{
	PDWORD addressOfNames = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfNames), rdataSection);
	PDWORD addressOfFunctions = (PDWORD)RVAtoRawOffset((DWORD_PTR)fileData + *(&exportDirectory->AddressOfFunctions), rdataSection);
	BOOL stubFound = FALSE;

	for (size_t i = 0; i < exportDirectory->NumberOfNames; i++)
	{
		DWORD_PTR functionNameVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfNames[i], rdataSection);
		DWORD_PTR functionVA = (DWORD_PTR)RVAtoRawOffset((DWORD_PTR)fileData + addressOfFunctions[i + 1], textSection);
		LPCSTR functionNameResolved = (LPCSTR)functionNameVA;
		if (std::strcmp(functionNameResolved, functionName) == 0)
		{
			std::memcpy(syscallStub, (LPVOID)functionVA, SYSCALL_STUB_SIZE);
			stubFound = TRUE;
		}
	}
	return stubFound;
}

typedef NTSTATUS(NTAPI* _NtOpenProcess) (PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,CLIENT_ID* ClientId);

int main(int argc, char* argv[]) {
	Sleep(1000);
	char syscallStub[SYSCALL_STUB_SIZE] = {};
	SIZE_T bytesWritten = 0;
	DWORD oldProtection = 0;
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID fileData = NULL;

	// variables for NtCreateFile
	OBJECT_ATTRIBUTES oa;
	HANDLE fileHandle = NULL;
	NTSTATUS status = NULL;
	UNICODE_STRING fileName;
	RtlInitUnicodeString(&fileName, (PCWSTR)L"\\??\\c:\\temp\\temp.log");
	IO_STATUS_BLOCK osb;
	ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
	InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HMODULE hDll = LoadLibraryA("C:\\Windows\\System32\\ntdll.dll");

	// define NtCreateFile
	myNtCreateFile NtCreateFile = (myNtCreateFile)(LPVOID)syscallStub;
	VirtualProtect(syscallStub, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);

	file = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
	ReadFile(file, fileData, fileSize, &bytesRead, NULL);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileData + dosHeader->e_lfanew);
	DWORD exportDirRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageNTHeaders);
	PIMAGE_SECTION_HEADER textSection = section;
	PIMAGE_SECTION_HEADER rdataSection = section;

	for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		if (std::strcmp((CHAR*)section->Name, (CHAR*)".rdata") == 0) {
			rdataSection = section;
			break;
		}
		section++;
	}

	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVAtoRawOffset((DWORD_PTR)fileData + exportDirRVA, rdataSection);

	GetSyscallStub("NtCreateFile", exportDirectory, fileData, textSection, rdataSection, syscallStub);
	NtCreateFile(&fileHandle, FILE_GENERIC_WRITE, &oa, &osb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	char syscallStub2[SYSCALL_STUB_SIZE] = {};
	_NtOpenProcess NtOpenProcess = (_NtOpenProcess)(LPVOID)syscallStub2;
	
	VirtualProtect(syscallStub2, SYSCALL_STUB_SIZE, PAGE_EXECUTE_READWRITE, &oldProtection);
	GetSyscallStub("NtOpenProcess", exportDirectory, fileData, textSection, rdataSection, syscallStub2);

	POBJECT_ATTRIBUTES pAttributes = NULL;
	CLIENT_ID clientId;
	NtOpenProcess((PHANDLE)GetCurrentProcess(), PROCESS_ALL_ACCESS, pAttributes, &clientId);

	return 0;
}
```

The only modification I've made to the above code is to duplicate the steps needed to call NtCreateFile but for NtOpenProcess. This will give us two malicious syscalls that we can use to validate our detection.

If we compile this and start it with Frida, then we should receive the following output:

```cpp
[*] Ntdll base: 0x7ffc6c4b0000
[*] Ntdll end: 0x7ffc6c6a5000
[-] Just a normal syscall: mov eax, 0x23
[-] Just a normal syscall: mov eax, 0x18
[-] Just a normal syscall: mov eax, 0x50
[-] Just a normal syscall: mov eax, 0x55
[-] Just a normal syscall: mov eax, 0x11
[-] Just a normal syscall: mov eax, 0x1e
[-] Just a normal syscall: mov eax, 6
[+] Found a potentially malicious syscall: mov eax, 0x55
[+] Found a potentially malicious syscall: mov eax, 0x26
[-] Just a normal syscall: mov eax, 0x15a
```

Great! It looks like our detection works. To validate that we aren't getting false positives, try commenting out one of the syscalls in our executable. We should only see one malicious call instead of two.

```cpp
[*] Ntdll base: 0x7ffc6c4b0000
[*] Ntdll end: 0x7ffc6c6a5000
[-] Just a normal syscall: mov eax, 0x23
[-] Just a normal syscall: mov eax, 0x50
[-] Just a normal syscall: mov eax, 0x55
[-] Just a normal syscall: mov eax, 0x11
[-] Just a normal syscall: mov eax, 0x18
[-] Just a normal syscall: mov eax, 0x1e
[-] Just a normal syscall: mov eax, 6
[+] Found a potentially malicious syscall: mov eax, 0x55
[-] Just a normal syscall: mov eax, 0x15a
```

Looks good!

## Testing in the field

It's all well and good that we can detect malicious syscalls when we know what we're looking for, but what about in a real red team tool? To test this out I went and grabbed Dumpert from Outflank. This project uses syscalls to dump LSASS for parsing with Mimikatz.

[outflanknl/Dumpert](https://github.com/outflanknl/Dumpert)

Why Dumpert? It's a cool program and it's pretty small all-in-all, so it's easy to quickly audit the source and figure out what it's doing (read: ensure you're not executing straight up malware on your machine).

Anyway, we'll need to have Frida running in an elevated context since Dumpert needs to run as admin to access LSASS. Below is the full Frida script that I'm going to be running.

```cpp
var modules = Process.enumerateModules()
var ntdll = modules[1]

var ntdllBase = ntdll.base
send("[*] Ntdll base: " + ntdllBase)
var ntdllOffset = ntdllBase.add(ntdll.size)
send("[*] Ntdll end: " + ntdllOffset)

const mainThread = Process.enumerateThreads()[0];
Process.enumerateThreads().map(t => {
Stalker.follow(t.id, {
  events: {
    call: false, // CALL instructions: yes please
    // Other events:
    ret: false, // RET instructions
    exec: false, // all instructions: not recommended as it's
                 //                   a lot of data
    block: false, // block executed: coarse execution trace
    compile: false // block compiled: useful for coverage
  },
  onReceive(events) {    
  },
  transform(iterator){
      let instruction = iterator.next()
      do{
        
        //I think this reduces overhead
        if(instruction.mnemonic == "mov"){
            //Should provide a good filter for syscalls, might need further filtering
            if(instruction.toString() == "mov r10, rcx"){
                iterator.keep() //keep the instruction
                instruction = iterator.next() //next instruction should have the syscall number
								//This helps to clear up some false positives
                if(instruction.toString().split(',')[0] == "mov eax"){
                    var addrInt = instruction.address.toInt32()
                    //If the syscall is coming from somewhere outside the bounds of NTDLL
                    //then it may be malicious
                    if(addrInt < ntdllBase.toInt32() || addrInt > ntdllOffset.toInt32()){
                        send("[+] Found a potentially malicious syscall: " + instruction.toString())
                    }
                }
            }
        }
        
      iterator.keep()
      } while ((instruction = iterator.next()) !== null)
  }
  
 
})
})
```

If we run the program then we should see a successful run from Dumpert. I also went ahead and verified that the LSASS dump was parseable by mimikatz and didn't get messed up by Frida somehow.

```cpp
________          __    _____.__                 __
 \_____  \  __ ___/  |__/ ____\  | _____    ____ |  | __
  /   |   \|  |  \   __\   __\|  | \__  \  /    \|  |/ /
 /    |    \  |  /|  |  |  |  |  |__/ __ \|   |  \    <
 \_______  /____/ |__|  |__|  |____(____  /___|  /__|_ \
         \/                             \/     \/     \/
                                  Dumpert
                               By Cneeliz @Outflank 2019

[1] Checking OS version details:
        [+] Operating System is Windows 10 or Server 2016, build number 19041
        [+] Mapping version specific System calls.
[2] Checking Process details:
        [+] Process ID of lsass.exe is: 540
        [+] NtReadVirtualMemory function pointer at: 0x00007FFC6C54D5F0
        [+] NtReadVirtualMemory System call nr is: 0x3f
        [+] Unhooking NtReadVirtualMemory.
[3] Create memorydump file:
        [+] Open a process handle.
        [+] Dump lsass.exe memory to: \??\C:\WINDOWS\Temp\dumpert.dmp
        [+] Dump succesful.
```

And then we can verify in our Frida console if we picked up any syscalls.

```cpp
[*] Ntdll base: 0x7ffc6c4b0000
[*] Ntdll end: 0x7ffc6c6a5000
[+] Found a potentially malicious syscall: mov eax, 0x36
[+] Found a potentially malicious syscall: mov eax, 0x18
[+] Found a potentially malicious syscall: mov eax, 0x1e
[+] Found a potentially malicious syscall: mov eax, 0x50
[+] Found a potentially malicious syscall: mov eax, 0x3a
[+] Found a potentially malicious syscall: mov eax, 0x26
[+] Found a potentially malicious syscall: mov eax, 0x55
[+] Exit Reason: process-terminated
[+] Found a potentially malicious syscall: mov eax, 0xf
```

And it looks likes we found quite a few. Now let's validate that they are what we expect them to be. If you open up the Dumpert source and go to syscalls.asm at line 179 this is where the Windows 10 specific syscalls are. The list of syscall numbers is as follows:

- ZwOpenProcess - 26
- ZwClose - 0F
- ZwWriteVirtualMemory - 3A
- ZwProtectVirtualMemory - 50
- ZwQuerySystemInformation - 36
- NtAllocateVirtualMemory - 18
- NtFreeVirtualMemory - 1E
- NtCreateFile - 55

If we look in our Frida console, then we see them called in this order. This order isn't necessarily correct since the "send" call in Frida is asynchronous, but we do see them all called.

1. ZwQuerySystemInformation
2. NtAllocateVirtualMemory
3. NtFreeVirtualMemory
4. ZwProtectVirtualMemory
5. ZwWriteVirtualMemory
6. ZwOpenProcess
7. NtCreateFile
8. ZwClose

### A quirk

I have noticed that if the same direct syscall stub is called multiple times within the same program, it will only be reported once. To test this I called NtOpenProcess twice from the same syscall stub and only received one notification. However when I allocated a second syscall stub and called GetSyscallStub a second time, I received two notifications. I'm sure there is some nuanced reason for this, but I will admit that this is beyond my understanding. Anyways, for my purposes I am content with identifying that a program is using direct syscalls. 

### Bypassing this detection

One method that comes to mind for bypassing this technique is to either unhook NTDLL which will provide clean syscall stubs. I think this is a bit of a chicken-and-egg problem - in order to unhook NTDLL you need to use hooked Nt functions. Normally you could use direct syscalls to unhook NTDLL (this is what Dumpert does), but since we can detect syscalls being used in this manner then the EDR (or Frida) will see you modifying NTDLL!

### Detection robustness

One concern I had about this method of detection was how robust it is. Naturally, looking for **sysenter**, **syscall**, or **int 2eh** will be more robust, but I really wanted a way to inspect the syscall numbers. However when I tried running Dumpert but removed the mov r10,rcx instruction, the NtCreateFile call fails. So I'm hoping this isn't a trivial detection to circumvent. 

False positives is another concern. I tried a few Windows applications to check for this. Calc.exe for example yielded a few false positives, but they can quickly be dismissed as false positives.

```cpp
[+] Found a potentially malicious syscall: mov eax, dword ptr [r8 + 0x14]
```

I'm sure it would be possible to further filter out false positives, but I'm satisfied with it for now.

### Drawbacks

So naturally, running any sort of tracer is going to create overhead in the target application. I don't really view this as an issue for this use-case since we're just using Frida to analyze a suspected-bad file. If we were attempting to do this via EDR then it would be a different matter. That said, Frida does expose the CModule API to write our transform code in C, which will run a lot faster than JavaScript. I started to write a CModule implementation but it wasn't that important so I moved on. However it would be doable with some more reading of the Gumstalker source.

## Conclusion

Hopefully you learned something new from this post. To reiterate I don't think this is a novel technique or mindblowing by any means, but I think one of the best ways to learn about our tooling is by taking it apart and writing detections for it. I've had more than one instance where a client asked me how they could detect one of the techniques I used and I had to get back to them, so some work ahead of time can be a boon!

## References
[Combining Direct System Calls and sRDI - Outflank](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)

[Retrieving ntdll Syscall Stubs from Disk at Run-time - ired.team](https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time?q=riv)

[Hell's Gate - Am0nsec](https://github.com/am0nsec/HellsGate)

[Bypassing user mode hooks and direct invocation of syscalls - MDSec](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)

[OutflankNl - Dumpert](https://github.com/outflanknl/Dumpert)
