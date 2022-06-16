---
layout: default
title: "Calling Cobalt Strike aliases from other aliases (kinda)"
permalink: /cobalt-strike-aliases-kinda
---

# Calling Cobalt Strike aliases from other aliases (kinda)

Anyone who's tried to extend Cobalt Strike through the Aggressor scripting language knows that there are some pain points, to say the least. I was recently bashing my head against an Aggressor scripting problem and thought I would document my results here. I'm willing to bet that there is a much easier solution to this that someone who is a Sleep/Aggressor wizard will point out, and if so I'd love to hear about it.

Without getting into specifics, we were in a situation where we wanted to call an Aggressor alias in one script, from an Aggressor alias in another script. It looked roughly like this.

```
alias testing {
    println($1) #Beacon ID
    println($2) #First argument
    println($3) #Second argument
}

alias call-testing {
    testing(@_) #@_ here is our array of arguments
}
```

The problem here is that you can't call an Aggressor alias from another alias, because an alias is not considered a function. You can only call an alias via the Beacon console. So we get this error.
```
Attempted to call non-existent function &testing at testing.cna:24
```

The workaround here is that we can change the Aggressor function that we want to call to a subroutine, and then we can call it from an alias. I'm not a huge fan of this since I wanted a way to do it without modifying the Aggressor script that we want to call, but the next best thing is doing it with minimal tweaks.

```
sub testing {
    println($1)
    println($2)
    println($3)
}

alias call-testing {
    testing(@_) #@_ here is our array of arguments
}
```

But this presents a new problem. When we pass our array of arguments into our subroutine, it then gets put into another array. Then when we reference our arguments by the $1/$2/$3 convention, all of our arguments will be stored in the $1 scalar. So if we call our alias like this:
```
call-testing arg1 arg2
```
Then our function prints this:
```
@('1814067882', 'arg1', 'arg2')


```
The easy solution is that we can redefine our alias to pass in all of our arguments to our subroutine like this.
```
testing($1, $2, $3)
```
This works fine for functions with a small number of arguments. But some Aggressor aliases like [Inline-ExecuteAssembly ](https://github.com/anthemtotheego/InlineExecute-Assembly) can take any number of arguments, like in the --assemblyargs argument. So I wanted a workaround that would allow us to call our Aggressor function with any number of arguments, and allow our function to access all of the functions by the $1/$2/$3 convention like normal. This is the solution I came up with.
```
sub btesting {
    @_ = flatten(@_);
    $i = 1; #iterator
    foreach $arg (@_){ #Loop through all of our args
        eval("local('$" . $i . "')") #Declare our variable in the local scope
        eval("$$i = \"$arg\";") #Use eval to dynamically define each of our numbered args
        $i++;
    }
    println($1)
    println($2)
    println($3)
}
alias call-testing {
    testing(@_)
}
```
This function uses string interpolation and the 'eval' function to dynamically declare our numbered scalars, and should work for any number of arguments provided.

And when we run this function we get our arguments in the $1/$2/$3 scalars as expected.
```
1814067882
arg1
arg2
```

If you're curious what exactly the usecase for this is, a practical example might be that you have an Aggressor script which calls a BOF to do something, maybe spawning a process with a set of arguments. You want to create an alias for calling the BOF to spawn svchost with a set of arguments, but you want to retain the ability to call the BOF normally as well.

```
alias spawn-svchost {
    @_predefinedargs = @("svchost.exe", "-k", "Something");
    @_ = concat(@_,@_predefinedargs); #Need to concat this so our beaconId in $1 gets included
    bspawn-process(@_)
}
...
alias spawn-process {
    bspawn-process(@_)
}
...
sub bspawn-process {
    @_ = flatten(@_); 
    $i = 1; #iterator
    foreach $arg (@_){ #Loop through all of our args
        eval("local('$" . $i . "')") #Declare our variable in the local scope
        eval("$$i = \"$arg\";") #Use eval to dynamically define each of our numbered args
        $i++;
    }
    ...
}
```

This way, you can define as many aliases as you want using your function, and the function just needs those few extra lines to fix up all the arguments and it can reference them by $1/$2/$3 as normal. This example is a bit contrived, but hopefully you see what I'm getting at.

One other note is that the $0 argument that normally holds the command line will get replaced with the name of the function. If your script works like Inline-ExecuteAssembly, which splits the $0 scalar by spaces and then parses out the arguments, you can do something like this.
```
$0 = join(' ', @_)
```

Anyways, this is a pretty niche use case, but since there's not a ton of blogs about Aggressor scripting out there I thought I might put this out there.
