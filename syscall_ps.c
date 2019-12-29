#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include "strace.h"

/* Print the string specified by address @addr
 * If the string length exceeds @n, append "..." behind the string
 */
void printSTR_PTR(pid_t pid, long long addr, int n) {
	char str[256];
	
	if(!addr) {
		printf("NULL");
		return;
	}

	struct iovec local[1], remote[1];
	local[0].iov_base = str;
	remote[0].iov_base = (void *)addr;

	local[0].iov_len = 256;
	remote[0].iov_len = 8;

	int r = process_vm_readv(pid, local, 1, remote, 1, 0);

	if(r != 8) {
		err(EXIT_FAILURE, "process_vm_readv");
		exit(EXIT_FAILURE);
	}
	printf("\"%s\"", str);
}

/* openat(CONST, STR_PTR, CONST) = NUM */
int openat_p(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance, int outputNum_forEnd) {
	int outputNum;
	char path[256];
	if(isSyscallEntrance) {
		outputNum = printSyscallName(regs->orig_rax);
		outputNum += printf("(0x%llx, ", regs->rdi);

		printSTR_PTR(pid, regs->rsi, 0);
		printf(", 0x%llx)", regs->rdx);
	} else {
		if(EQ_FORMAT >= outputNum_forEnd) printf("%-*s = 0x%llx\n", EQ_FORMAT - outputNum_forEnd, "", regs->rax);
		else printf(" = %lld\n", regs->rax);
	}
	return outputNum;
}
