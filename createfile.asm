
; openat(AT_FDCWD,"VMESCAPE",O_WRONLY|O_CREAT|O_TRUNC, 0) 

global _start
_start:

    push    499				; openat
    pop     rax
    push    -100			; AT_FDCWD
    pop     rdi
    mov     rbx, 0x4550414353454d56 	; "VMESCAPE"
    push    0
    push    rbx              
    push    rsp
    pop     rsi              		
 
    push    0x601			; O_WRONLY | O_CREAT | O_TRUNC
    pop     rdx
    xor     rcx, rcx

    syscall

    add rsp, 16	
    ret
