# vmt-hooking
VMT hooking is a technique where you hook one (or more) VMT(Virtual Method Table) entries with a pointer to other function. Thus, when the process calls a virtual function and fetches the function pointer to be called, it will eventually execute your code. In this example, I've create a buggy application that suffers from a data leak vulnerability, if exploited correctly, leaking the target class this pointer and allow this technique to work. I use meterpreter shellcode as my hook function opcodes.

There is a technical gap in the trampoline issue that I need to solve. 
right now there is only one working thread in the target application so when I exit meterpreter (EXITFUNC process / EXITFUNC thread) the process exits as well. I'll try to figure it out, maybe use EXITFUNC none or CreateRemoteThread in the target application.
