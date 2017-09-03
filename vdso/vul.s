	.file	"vul.c"
	.text
	.globl	vuln
	.type	vuln, @function
vuln:
#APP
# 4 "vul.c" 1
	sub $8, %rsp         
mov $0, %rax         
mov $0, %rdi         
mov %rsp, %rsi     
mov $1024, %rdx     
syscall    
add $8, %rsp    
ret    

# 0 "" 2
#NO_APP
.LFE0:
	.size	vuln, .-vuln
	.globl	main
	.type	main, @function
main:
.LFB1:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
#APP
# 17 "vul.c" 1
	call vuln      
mov $60, %rax       
xor %rdi, %rdi     
syscall        

# 0 "" 2
#NO_APP
	movl	$0, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 4.8.4-2ubuntu1~14.04.3) 4.8.4"
	.section	.note.GNU-stack,"",@progbits
