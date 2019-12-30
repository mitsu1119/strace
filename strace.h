#include <unistd.h>

#define EQ_FORMAT 40
#define PRINT_STR_LEN 20

#define REGS_ARG(nth)\
	(nth == 1)?(regs->rdi):(\
	(nth == 2)?(regs->rsi):(\
	(nth == 3)?(regs->rdx):(\
	(nth == 4)?(regs->r10):(\
	(nth == 5)?(regs->r8):(\
		   (regs->r9))))))

// strace.c
int printSyscallName(const int syscallID);
int printSyscall(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance);

// syscall_ps.c
/* function table */
typedef int (*fptr)(pid_t, const struct user_regs_struct *, const char, int);
extern fptr printSuchSyscall[];

