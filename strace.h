#include <unistd.h>

#define EQ_FORMAT 40
#define PRINT_STR_LEN 20

// strace.c
int printSyscallName(const int syscallID);
int printSyscall(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance);


