# NINA
NINA: No Injection, No Allocation x64 Process Injection Technique

A quick, experimental side project just for fun!

This project will not be maintained. Sorry!

## Blog

https://undev.ninja/nina-x64-process-injection/

## Tested Environments

* Windows 10 x64 version 2004
* Windows 10 x64 version 1903

## Drawbacks

* The shellcode size limitation is whatever can fit into the targeted `RX` section. Perhaps use it as a stager?
* The shellcode also has to fit within the target stack location. Perhaps enumerate all of the modules' `RW` sections too?

## Something TODO

* Fallback method to look for larger code caves within other modules if the executable image's is too small.
