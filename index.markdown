---
# Feel free to add content and custom Front Matter to this file.
# To modify the layout, see https://jekyllrb.com/docs/themes/#overriding-theme-defaults

layout: default
---

# About Me
I'm a red teamer/penetration tester by craft. I got my start in AD penetration testing, did a brief stint as a red teamer, and now I do all manners of consulting work.

This is where I post the random stuff that I research. None of it is particularly good but hopefully some of it is useful. I mainly focus on Windows/Active Directory.

# Posts

[Cobalt Strike Aliases - Kinda](https://github.com/passthehashbrowns/passthehashbrowns.github.io/blob/master/_posts/2022-06-16-Cobalt-Strike-Aliases-Kinda.md)
A short post looking at some weird Aggressor logic I wrote for handling Cobalt Strike aliases with Sleep subroutines/functions.

[Implementing Smart Inject](https://passthehashbrowns.github.io/implementing-smart-inject)
This post looks at implementing Cobalt Strike's "Smart Inject" feature to avoid shellcode-like behavior in post-exploitation processes.

[Hiding your syscalls](https://passthehashbrowns.github.io/hiding-your-syscalls)
This post looks at bypassing the direct syscall detections that I wrote in a previous post. 

[Dynamic payload compilation with mingw](https://passthehashbrowns.github.io/dynamic-payload-generation-with-mingw)
This post looks at creating a basic server, implant, and shellcode stager that we will compile on Linux using mingw to target Windows. 

[Detecting direct syscalls with Frida](https://passthehashbrowns.github.io/detecting-direct-syscalls-with-frida)
This post looks at detecting direct syscalls with Frida by using Frida's code tracing engine to find syscalls from outside NTDLL.

[Checking NTDLL hook integrity with Frida](https://passthehashbrowns.github.io/hook-integrity-checks)
This post looks at installing a hook into NTDLL with Frida, bypassing that hook, detecting the unhooking in Frida by checking the hook integrity, and finally bypassing that detection.

[Blocking remote memory forensics through API hooking](https://passthehashbrowns.github.io/blocking-remote-memory-forensics)
This post walks through how kernel driver loads, often used by forensics tools for memory captures, can be blocked from loading by userland processes and kernel drivers.

[Muting Prefetch](https://passthehashbrowns.github.io/muting-prefetch/)
This post discusses using API hooking to prevent the Windows Prefetch service from writing files to disk, which can later be used by forensic investigators.



