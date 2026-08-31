void _start(void){ __asm__ volatile("mov $60, %rax; xor %edi, %edi; syscall"); }
