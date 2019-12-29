#include <unistd.h>

#define EQ_FORMAT 40

// strace.c
int printSyscallName(const int syscallID);
int printSyscall(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance);


