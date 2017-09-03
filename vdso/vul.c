

void vuln(){
    __asm__ __volatile__(
        "sub $8, %rsp         \r\n"
        "mov $1, %rax         \r\n"
        "mov $0, %rdi         \r\n"
        "mov %rsp, %rsi     \r\n"
        "mov $1024, %rdx     \r\n"
        "syscall    \r\n"
        "add $8, %rsp    \r\n"
        "ret    \r\n"
        );

}
int main(){
    __asm__ __volatile__(
        "call vuln      \r\n"
        "mov $60, %rax       \r\n"
        "xor %rdi, %rdi     \r\n"
        "syscall        \r\n"
        );
        
    return 0;
}


