.code
_ZwQuerySystemInformation    proc
    mov r10,rcx
    mov eax,36h
    syscall
    ret
_ZwQuerySystemInformation    endp
end