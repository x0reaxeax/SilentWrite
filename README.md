
# SilentWrite - Arbitrary WPM via `Get/SetConsoleTitle()`

## Description
The idea behind this IPC / write-primitive is utilizing the [`SetConsoleTitleA()`](https://learn.microsoft.com/en-us/windows/console/setconsoletitle) API to expose binary data between two processes.  
This function does not need a handle to the remote process, instead, it only requires a Process ID.
While the memory can't really be written directly via this API function alone, execution-altering API functions can be utilized to redirect the execution to [`GetConsoleTitleA()`](https://learn.microsoft.com/en-us/windows/console/getconsoletitle), which fetches the data from console title to an arbitrary memory location passed as argument.
In this PoC, [`GetThreadContext()`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext) & [`SetThreadContext()`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext) are used to alter the execution.

The injection is performed by 3 consecutive combinations of "Write/Exec"s:
1. Write a pointer to a `jmp $` loop located inside the target process.
2. Write a pointer to the payload, and return to the `jmp $` loop.
3. Write the actual payload, which `RSP` will be pointing and returning to, thanks to the pointer written in the previous step.

The result is execution of a "PopCalc" shellcode.

### Perquisite summary
1. Address of a `0xeb, 0xfe` (`jmp $`) loop. The PoC utilizes a static address from `kernelbase.dll`.
2. A big enough RWX memory region to replace the stack with (1MB will do). In this PoC, the memory is allocated via `VirtualAllocEx()`, but the handle to the target process is dropped immediately after.
3. (`THREAD_SET_CONTEXT` | `THREAD_GET_CONTEXT` | `THREAD_SUSPEND_RESUME`) access rights to the thread which execution will be altered.
4. The target process needs to be executed from **`CMD.EXE`**. Windows Terminal doesn't correctly fetch binary data from console title.

### Preview
![Preview](https://i.imgur.com/R4L1cVf.png)

## Credits
PopCalc shellcode by [Bobby Cooke (boku)](https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode).  

<br />
<br />

*This project is licensed under the MIT license. Copyrights are respective of each contributor listed at the beginning of each definition file.*
> Written with [StackEdit](https://stackedit.io/).