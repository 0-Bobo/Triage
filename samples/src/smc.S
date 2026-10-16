/* Self-modifying-code fixture: an RWX region holds XOR-encoded (key 0x5a)
 * shellcode. _start is a decode loop matching the shape strat_smc.py's
 * _decoder_region() looks for ("mov eax, END; mov ecx, COUNT; loop
 * { transform [rax]; dec rax }"), which decodes the payload in place at
 * runtime, then jumps into it to print the flag via a raw write() syscall.
 *
 * Build (from WSL): see build.sh (-Wl,-N for a single RWX segment, the
 * same pattern rwx.c already uses).
 *
 * The on-disk `enc_start..enc_end` bytes are the XOR 0x5a encoding of:
 *   push %rbp ; mov %rsp, %rbp         # ordinary-looking prologue
 *   jmp get_string
 * back:
 *   pop %rsi
 *   mov $1, %rax ; mov $1, %rdi ; mov $21, %rdx ; syscall   # write(1, rsi, 21)
 *   mov $60, %rax ; xor %edi, %edi ; syscall                # exit(0)
 * get_string:
 *   call back
 *   .ascii "flag{smc_unwrapped}\n"
 * They're produced by assembling that plaintext separately, then XORing
 * just that byte range with 0x5a before linking it in here as encoded
 * bytes -- the decode loop below is the only part that ever runs as-is.
 */
.global _start
.text
_start:
    mov $enc_last, %rax
    mov $enc_len, %ecx
decode_loop:
    xorb $0x5a, (%rax)
    dec %rax
    loop decode_loop
    jmp enc_start

enc_start:
    .byte 0x0f, 0x12, 0xd3, 0xbf, 0xb1, 0x79, 0x04, 0x12, 0x9d, 0x9a, 0x5b, 0x5a
    .byte 0x5a, 0x5a, 0x12, 0x9d, 0x9d, 0x5b, 0x5a, 0x5a, 0x5a, 0x12, 0x9d, 0x98
    .byte 0x4f, 0x5a, 0x5a, 0x5a, 0x55, 0x5f, 0x12, 0x9d, 0x9a, 0x66, 0x5a, 0x5a
    .byte 0x5a, 0x6b, 0xa5, 0x55, 0x5f, 0xb2, 0x82, 0xa5, 0xa5, 0xa5, 0x3c, 0x36
    .byte 0x3b, 0x3d, 0x21, 0x29, 0x37, 0x39, 0x05, 0x2f, 0x34, 0x2d, 0x28, 0x3b
    .byte 0x2a, 0x2a, 0x3f, 0x3e, 0x27, 0x50
enc_end:

.equ enc_len, enc_end - enc_start
.equ enc_last, enc_end - 1
