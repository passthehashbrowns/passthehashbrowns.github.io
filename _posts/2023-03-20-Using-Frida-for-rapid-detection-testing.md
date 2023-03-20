---
layout: default
title: "Using Frida for rapid detection testing"
permalink: /using-frida-for-rapid-detection-testing
---

# Using Frida for rapid detection testing
When I'm developing payloads or doing research, I frequently want to test code that I've written against common defensive capabilities. Unfortunately, most defensive capabilities are implemented in C/C++ and run in the kernel. I am not a kernel developer, and even if I were writing my own defensive capabilities from scratch would be a very cumbersome task. In this post I'll walk through how I use Frida for rapidly developing detections to simulate known EDR capabilities.

## What is Frida?
Frida is a popular dynamic instrumentation framework. Most people probably know it best as a hooking engine, which is a part of it. But Frida has a huge range of capabilities that I frequently don't see taken advantage of, such as its code tracing engine "Stalker". Frida also offers JavaScript bindings, which makes writing Frida scripts a breeze (especially if you use [Fermion](https://github.com/FuzzySecurity/Fermion)).

## What kind of defensive capabilities?
Here's the example I'll walk through in this post: I want to simulate a defensive product that is detecting thread creation targeting unbacked executable memory. In real defensive products, this is done through kernel callbacks, minifilters, Etw/EtwTi, etc. However, in the interest of rapid development, we can simulate this with userland hooking. I know what you might be thinking - "but Josh, userland hooking is so 2016!". Yes, a lot of research has been developed for defeating userland hooks and many products no longer rely on them. So we already know that we can bypass userland hooks, but I'm more interested in simulating kernel-side detections without actually writing kernel code. To that end, instead of going through the process of writing a kernel driver to register for callbacks, we can simply hook CreateThread and use that instead. In my eyes, there is a tradeoff between being realistic and not wasting time writing tons of boilerplate code. After I have validated my ideas against a quickly hacked up script, then I concern myself with more robust tests.

## Detecting thread creation 
Below is some C for allocating some executable memory and creating a local thread there. I've purposefully not included reading/copying in actual shellcode, since I just want to validate the unbacked memory detection.
``` C
LPVOID shellcode = VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
HANDLE hThread = CreateThread(NULL, 0, shellcode, NULL, 0, NULL);
```

Now here is a small Frida script for hooking the CreateThread API.
```
var pCreateThread = Module.findExportByName("kernel32.dll", "CreateThread")
Interceptor.attach(pCreateThread, {
    onEnter: function (args) {
        //The third argument is the start address
        var startAddress = args[2]; 
        //findRangeByAddress gets us the attributes of the memory range and findModuleByAddress gets us what module the address is associated with
        var addressRange = Process.findRangeByAddress(startAddress);
        var addressModule = Process.findModuleByAddress(startAddress);
        //If there is no associated module and our memory is either RX or RWX, then we have an unbacked executable region
        if(addressModule == null && (addressRange.protection == "rwx" || addressRange.protection == "r-x")){
            send("[*] Thread creation targeting unbacked executable memory")
        }
    }
})
```

Easy enough, blog post over! Except we can take this a bit further to better simulate defensive products. For example, what if we're worried about false positives? Lets do a quick memory scan of the region to check for malicious contents.

```

var pCreateThread = Module.findExportByName("kernel32.dll", "CreateThread")
const pattern = '48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00'
Interceptor.attach(pCreateThread, {
    onEnter: function (args) {
        var startAddress = args[2];
        var addressRange = Process.findRangeByAddress(startAddress);
        var addressModule = Process.findModuleByAddress(startAddress);
        if(addressModule == null && (addressRange.protection == "rwx" || addressRange.protection == "r-x")){
            send("[*] Thread creation targeting unbacked executable memory")
            var results = Memory.scanSync(addressRange.base, addressRange.size, pattern)
            if(JSON.stringify(results) != "[]"){
                send(addressRange.base + " " + addressRange.size + " " + addressRange.protection + " " + JSON.stringify(results))
            }
        }
    }
})
```

In the script above, I've hardcoded a pattern from YARA rules [published by Elastic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_CobaltStrike.yar) for detecting Cobalt Strike. We can use Frida's Memory module to scan the memory region we're concerned with and check if we have a pattern match. I've modified my C code to read in Beacon shellcode from a file into our RWX memory (omitted from code snippets for brevity). If we execute our Frida script, then we'll see that we do indeed have a pattern match. 

```
[*] Thread creation targeting unbacked executable memory
0x21913360000 278528 rwx [{"address":"0x219133795f8","size":31}]
```

For the purposes of this blog I've just hardcoded one rule, but it's pretty easy to read them in from a file and scan against many rules to implement your own mini-YARA scanner.

## Continuous development
Now that we've written a detection for our thread creation targeting unbacked memory, we can use this as a springboard for evading this detection. For example, what if we allocate our memory as RW, create our thread suspended, change the memory protection to RX, and then resume the thread? Here is what our C looks like now, and if we execute it then we'll evade the previous detection that we wrote.

```
LPVOID shellcode = VirtualAlloc(0, dwLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
HANDLE hThread = CreateThread(NULL, 0, shellcode, NULL, CREATE_SUSPENDED, NULL);
DWORD oldProtect = 0;
VirtualProtect(shellcode, dwLength, PAGE_EXECUTE_READ, &oldProtect);
ResumeThread(hThread);
```

So now how do we detect this "new" technique? From here you can get creative. Creating a suspended thread on RW memory? Seems pretty fishy... But maybe not worth alerting. We can hook ResumeThread instead and inspect the memory region then. This also detects Suspend-Inject-Resume process injection as well, since that uses SuspendThread/GetThreadContext/SetThreadContext/ResumeThread.

Looking at the ResumeThread API call, our hook can check the handle for the thread as it's the only argument. We could use this handle to check the thread information using the Windows API, but Frida has functions for getting thread information, we just need the ID for the thread. So we can use another Frida capability to get the thread ID from the handle, using the GetThreadId Windows API call. Here's a Frida hook which can call the GetThreadId API using the NativeFunction class to get the thread ID, and then use Frida's Process.enumerateThreads() method to get all of the threads in the process. Then we just check for the correct thread ID.

After we've found the correct thread ID, we'll have a thread object which also has the context for the thread. Since suspended threads will have a start address of RtlUserThreadStart, we can't simply check the RIP. Instead, we can grab the value of the RCX register from the context, which should hold our actual start address. We can verify this by printing the start address in our CreateThread hook and then checking it against the thread context. Then we'll use the same code from earlier to check if the thread is targeting unbacked executable memory and then do a memory scan. Keep in mind that this code is written specifically for this detection case, so it won't work and will probably spit out an error for threads that were already executing before they were suspended/resumed, because the RCX register will not hold a pointer (or not a pointer that we care about checking).

```
//Define the GetThreadId API call as a Native Function
var pGetThreadId = Module.findExportByName('kernel32.dll', 'GetThreadId')
var fGetThreadId = new NativeFunction(pGetThreadId, "uint",["pointer"])

var pResumeThread = Module.findExportByName("kernel32.dll", "ResumeThread")
Interceptor.attach(pResumeThread, {
    onEnter: function (args) {
        //Call GetThreadId with our handle and then enumerate all threads checking for the right thread ID
        var threadId = fGetThreadId(args[0])
        var threads = Process.enumerateThreads()
        for(var i = 0; i < threads.length; i++){
            if(threads[i].id == threadId){
                var targetThread = threads[i]
            }
        }
        //Our start address will be the first arg to RtlUserThreadStart in the RCX register
        var targetThreadStart = targetThread.context["rcx"]
        //Same code from earlier to check for unbacked executable memory and do a scan
        var addressRange = Process.findRangeByAddress(targetThreadStart);
        var addressModule = Process.findModuleByAddress(targetThreadStart);
        if(addressModule == null && (addressRange.protection == "rwx" || addressRange.protection == "r-x")){
            send("[*] Thread creation targeting unbacked executable memory")
            var results = Memory.scanSync(addressRange.base, addressRange.size, pattern)
            if(JSON.stringify(results) != "[]"){
                send(addressRange.base + " " + addressRange.size + " " + addressRange.protection + " " + JSON.stringify(results))
            }
        }

    }
})
```

## Next steps
We can continuous this process ad nauseum to keep generating detections, bypassing them, generating detections, and so on. For example, to bypass our detection above, we could do a module stomp so our code isn't unbacked. But to detect that we could check the module against the module on disk. Or instead of stomping, we could use the GetThreadContext API call to populate a register with our start address, and set the RIP to a jmp gadget with that register. 

I find this to be a very helpful process for iteratively testing ideas and pushing boundaries without getting bogged down by writing lots of boilerplate C and spending tons of time just to debug your detections, when you really want to be writing bypasses!

## Limitations
Frida gets kind of weird if you try to do too much stuff. For example, I once wanted to hook every syscall in NTDLL, so I wrote a loop to generate a hook for each that would simply print the function address when the hook was called. This went about as well as expected, the process was super unstable. Now obviously that's a pretty non-standard use case, but I mention it to say that if you mess with the process too much stuff starts to go wrong. Also, JavaScript is not the most performant language, so if we try to do anything super intense we can again cause issues. For these reasons I think the best way to utilize Frida in this way is with modular, atomic detections. As shown above, I did not write my ResumeThread hook to handle every possible detection opportunity for malicious ResumeThread usage. I just wanted some relatively simple logic to test my assumptions. Also related to performance, Frida offers ways that you can make your code much faster by combining C and JavaScript. This is very useful if you're hooking a function that is frequently called. But naturally, writing C is much more labor intensive, so there is a tradeoff.

## Conclusion
Anyways, I thought this would be a nice use of a Saturday morning to brain dump some of my thoughts on Frida. I don't see it used super often for offensive testing, and I think it's a shame. Personally, I found it incredibly helpful while I was still learning malware development (although really we never stop learning) as it helped me poke at what was happening under the hood before I was more proficient with x64dbg/Windbg. And I generally find phrases like "rapid prototyping" kinda silly, but I think they apply very nicely here. I wrote up this entire blog, including all of the Frida code, in about an hour and a half.
