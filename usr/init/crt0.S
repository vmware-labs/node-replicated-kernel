.text
.globl  _start

_start:
    // Initialize stack for program
    lea (stack + (1024))(%rip), %rsp
    callq   main
halt:
    jmp     halt

    .bss
    .comm   stack, (1024)
