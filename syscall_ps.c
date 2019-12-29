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
 * This function return number of output characters.
 */
int printSTR_PTR(pid_t pid, long long addr, int n) {
	if(!addr) {
		printf("NULL");
		return 0;
	}

	char *str = (char *)malloc(n + 1);	
	int outputNum = 0;

	struct iovec local[1], remote[1];
	local[0].iov_base = str;
	remote[0].iov_base = (void *)addr;
	local[0].iov_len = n;
	remote[0].iov_len = n;

	int r = process_vm_readv(pid, local, 1, remote, 1, 0);
	if(r > 0) {
		if(memchr(local[0].iov_base, '\0', r)) {
			outputNum = printf("\"%s\"", str);
			return outputNum;
		} else {
			str[n] = '\0';
			outputNum = printf("\"%s\"...", str);
			return outputNum;
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

/* open(STR_PTR, CONST) = NUM */
int open_p(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance, int outputNum_forEnd) {
	int outputNum = 0;
	if(isSyscallEntrance) {
		outputNum = printSyscallName(regs->orig_rax);
		outputNum += printf("(");
		outputNum += printSTR_PTR(pid, regs->rdi, PRINT_STR_LEN);
		outputNum += printf(", ");
		outputNum += printf("%lld", regs->rsi);
		outputNum += printf(")");
	} else {
		if(EQ_FORMAT >= outputNum_forEnd) outputNum = printf("%-*s = %lld\n", EQ_FORMAT - outputNum_forEnd, "", regs->rax);
		else outputNum = printf(" = %lld\n", regs->rax);
	}
	return outputNum;
}

/* openat(CONST, STR_PTR, CONST) = NUM */
int openat_p(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance, int outputNum_forEnd) {
	int outputNum = 0;
	if(isSyscallEntrance) {
		outputNum = printSyscallName(regs->orig_rax);
		outputNum += printf("(");
		outputNum += printf("%lld", regs->rdi);
		outputNum += printf(", ");
		outputNum += printSTR_PTR(pid, regs->rsi, PRINT_STR_LEN);
		outputNum += printf(", ");
		outputNum += printf("%lld", regs->rdx);
		outputNum += printf(")");
	} else {
		if(EQ_FORMAT >= outputNum_forEnd) outputNum = printf("%-*s = %lld\n", EQ_FORMAT - outputNum_forEnd, "", regs->rax);
		else outputNum = printf(" = %lld\n", regs->rax);
	}
	return outputNum;
}
