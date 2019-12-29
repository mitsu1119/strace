#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include "strace.h"

/* Print the string specified by address @addr
 * If the string length exceeds @n, append "..." behind the string
 */
int printSTR_PTR(pid_t pid, long long addr, int n) {
	if(!addr) {
		printf("NULL");
		return 0;
	}

	char *str = (char *)malloc(n + 1);	

	struct iovec local[1], remote[1];
	local[0].iov_base = str;
	remote[0].iov_base = (void *)addr;
	local[0].iov_len = n;
	remote[0].iov_len = n;

	int r = process_vm_readv(pid, local, 1, remote, 1, 0);
	if(r > 0) {
		if(memchr(local[0].iov_base, '\0', r)) {
			printf("\"%s\"", str);
			return 1;
		} else {
			str[n] = '\0';
			printf("\"%s...\"", str);
			return 0;
		}
	}

	switch(errno) {
	case ENOSYS:
		err(EXIT_FAILURE, "process_vm_readv is not supported");
	case ESRCH:
		// the process is gone
		return -1;
	case EFAULT:
	case EIO:
	case EPERM:
		err(EXIT_FAILURE, "address space is inaccessible");
		return -1;
	default:
		err(EXIT_FAILURE, "process_vm_readv");
		return -1;
	}

	return 0;
}

/* openat(CONST, STR_PTR, CONST) = NUM */
int openat_p(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance, int outputNum_forEnd) {
	int outputNum;
	char path[256];
	if(isSyscallEntrance) {
		outputNum = printSyscallName(regs->orig_rax);
		outputNum += printf("(0x%llx, ", regs->rdi);

		printSTR_PTR(pid, regs->rsi, PRINT_STR_LEN);
		printf(", 0x%llx)", regs->rdx);
	} else {
		if(EQ_FORMAT >= outputNum_forEnd) printf("%-*s = 0x%llx\n", EQ_FORMAT - outputNum_forEnd, "", regs->rax);
		else printf(" = %lld\n", regs->rax);
	}
	return outputNum;
}
