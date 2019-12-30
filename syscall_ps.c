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
#include "syscallDefs.h"

/* CONST was not implemented */

/* Print signed integer */
int printINT(int value) {
	return printf("%d", value);
}

/* Print the address on hexadecimal */
int printPTR(long long addr) {
	if(!addr) {
		return printf("NULL");
	}

	return printf("0x%llx", addr);
}

/* Print the string specified by address @addr
 * If the string length exceeds @n, append "..." behind the string
 * This function return number of output characters.
 */
int printSTR_PTR(pid_t pid, long long addr, int n) {
	if(!addr) {
		return printf("NULL");
	}

	char *str = (char *)malloc(n + 1);	
	int outputNum = 0;
	struct iovec local[1], remote[1];
	local[0].iov_base = str;
	remote[0].iov_base = (void *)addr;
	local[0].iov_len = n + 1;
	remote[0].iov_len = n + 1;

	int r = process_vm_readv(pid, local, 1, remote, 1, 0);
	if(r > 0) {
		if(memchr(local[0].iov_base, '\0', r)) {
			outputNum = printf("\"%.*s\"", n, str);
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

/* for general purpose systemcall
 * for example, systemcall that print function is not defined, unknown systemcall, and so on
 * unknown() = INT
 */
int general_p(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance, int outputNum_forEnd) {
	int outputNum = 0;
	if(isSyscallEntrance) {
		outputNum = printSyscallName(regs->orig_rax);
		outputNum += printf("(");
		outputNum += printf(")");
	} else {
		if(EQ_FORMAT >= outputNum_forEnd) outputNum = printf("%-*s = ", EQ_FORMAT - outputNum_forEnd, "");
		else outputNum = printf(" = ", regs->rax);
		outputNum += printINT(regs->rax);
		outputNum += printf("\n");
	}
	return outputNum;
}

/* open(STR_PTR, CONST) = INT */
int open_p(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance, int outputNum_forEnd) {
	int outputNum = 0;
	if(isSyscallEntrance) {
		outputNum = printSyscallName(regs->orig_rax);
		outputNum += printf("(");
		outputNum += printSTR_PTR(pid, REGS_ARG(1), PRINT_STR_LEN);
		outputNum += printf(", ");
		outputNum += printINT(REGS_ARG(2));
		outputNum += printf(")");
	} else {
		if(EQ_FORMAT >= outputNum_forEnd) outputNum = printf("%-*s = ", EQ_FORMAT - outputNum_forEnd, "");
		else outputNum = printf(" = ", regs->rax);
		outputNum += printINT(regs->rax);
		outputNum += printf("\n");
	}
	return outputNum;
}

/* brk(PTR) = INT */
int brk_p(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance, int outputNum_forEnd) {
	int outputNum = 0;
	if(isSyscallEntrance) {
		outputNum = printSyscallName(regs->orig_rax);
		outputNum += printf("(");
		outputNum += printPTR(REGS_ARG(1));
		outputNum += printf(")");
	} else {
		if(EQ_FORMAT >= outputNum_forEnd) outputNum = printf("%-*s = ", EQ_FORMAT - outputNum_forEnd, "");
		else outputNum = printf(" = ", regs->rax);
		outputNum += printINT(regs->rax);
		outputNum += printf("\n");
	}
	return outputNum;
}

/* access(STR_PTR, CONST) = INT */
int access_p(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance, int outputNum_forEnd) {
	int outputNum = 0;
	if(isSyscallEntrance) {
		outputNum = printSyscallName(regs->orig_rax);
		outputNum += printf("(");
		outputNum += printSTR_PTR(pid, REGS_ARG(1), PRINT_STR_LEN);
		outputNum += printf(", ");
		outputNum += printINT(REGS_ARG(2));
		outputNum += printf(")");
	} else {
		if(EQ_FORMAT >= outputNum_forEnd) outputNum = printf("%-*s = ", EQ_FORMAT - outputNum_forEnd, "");
		else outputNum = printf(" = ", regs->rax);
		outputNum += printINT(regs->rax);
		outputNum += printf("\n");
	}
	return outputNum;
}

/* openat(CONST, STR_PTR, CONST) = INT */
int openat_p(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance, int outputNum_forEnd) {
	int outputNum = 0;
	if(isSyscallEntrance) {
		outputNum = printSyscallName(regs->orig_rax);
		outputNum += printf("(");
		outputNum += printINT(REGS_ARG(1));
		outputNum += printf(", ");
		outputNum += printSTR_PTR(pid, REGS_ARG(2), PRINT_STR_LEN);
		outputNum += printf(", ");
		outputNum += printINT(REGS_ARG(3));
		outputNum += printf(")");
	} else {
		if(EQ_FORMAT >= outputNum_forEnd) outputNum = printf("%-*s = ", EQ_FORMAT - outputNum_forEnd, "");
		else outputNum = printf(" = ", regs->rax);
		outputNum += printINT(regs->rax);
		outputNum += printf("\n");
	}
	return outputNum;
}

/* such systemcall function table */
fptr printSuchSyscall[MYSYS_clone3 + 1];
void printSuchSyscall_init() {
	printSuchSyscall[MYSYS_open] = open_p;
	printSuchSyscall[MYSYS_brk] = brk_p;
	printSuchSyscall[MYSYS_access] = access_p;
	printSuchSyscall[MYSYS_openat] = openat_p;
	for(int i = 0; i < MYSYS_clone3 + 1; i++) {
		if(printSuchSyscall[i] == NULL) printSuchSyscall[i] = general_p;
	}
}
