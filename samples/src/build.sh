#!/usr/bin/env bash
# Rebuild the checked-in sample binaries. Run on Linux (or WSL) with gcc.
#   cd samples/src && ./build.sh
set -euo pipefail
cd "$(dirname "$0")"
out=..

gcc -O0 -fno-stack-protector -no-pie -D_FORTIFY_SOURCE=0 \
    -o "$out/elf64_crackme" elf_crackme.c

gcc -O0 -fno-stack-protector -pie -fPIE \
    -o "$out/vuln_pie" vuln_pie.c

gcc -O0 -fstack-protector-all -no-pie \
    -o "$out/vuln_canary" vuln_canary.c

gcc -O0 -fno-stack-protector -no-pie -Wl,-z,execstack \
    -o "$out/vuln_execstack" vuln_execstack.c

gcc -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -no-pie \
    -o "$out/vuln_fortify" vuln_fortify.c

gcc -no-pie -nostdlib -O0 -Wl,-N \
    -o "$out/vuln_rwx" rwx.c

gcc -O0 -fno-stack-protector -no-pie \
    -o "$out/nostrings" nostrings.c

# Windows PE fixtures need a MinGW cross-compiler and are rebuilt manually:
#   x86_64-w64-mingw32-gcc -o ../pe64_hello.exe pe_hello.c
echo "built: vuln_pie vuln_canary vuln_execstack vuln_fortify vuln_rwx nostrings elf64_crackme"
