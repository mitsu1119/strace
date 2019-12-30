#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include "syscallDefs.h"
#include "strace.h"

int main(int argc, char *argv[], char *argp[]) {
	if(argc < 2) return 0;

	pid_t pid = fork();

	if(pid == -1) {
		err(EXIT_FAILURE, "Could not fork.");
		exit(EXIT_FAILURE);
	} else if(pid == 0) {
		/* child process */	
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) != -1) {
			execvp((argv + 1)[0], argv + 1);
		}
		err(EXIT_FAILURE, "PTRACE_TRACEME");
		exit(EXIT_FAILURE);
	} else {
		/* parent process */
		int status = 0, outputNum;
		char isSyscallEntrance = 0;	// The first SIGTRAP means execve's end
		struct user_regs_struct regs;
		char ptracesetoptionsFlag = 0;
		
		printSuchSyscall_init();
		while(1) {
			// wait child signal
			pid_t w = waitpid(pid, &status, WUNTRACED | WCONTINUED);

			if(WIFEXITED(status)) {
				break;
			} else if(WIFSIGNALED(status)) {
				break;
			} else if(WIFSTOPPED(status)) {
				// first signal... SIGTRAP by first execve
				// setting ptrace(PTRACE_SETOPTIONS, ...) and print execve(...) = ...
				if(!ptracesetoptionsFlag) {
					ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC);
					ptracesetoptionsFlag = 1;

					ptrace(PTRACE_GETREGS, pid, 0, &regs);
					outputNum = printSyscallName(regs.orig_rax);
					outputNum += printf("(0x%lx, 0x%lx, 0x%lx)", regs.rdi, regs.rsi, regs.rdx);
					if(EQ_FORMAT >= outputNum) printf("%-*s = 0x%lx\n", EQ_FORMAT - outputNum, "", regs.rax);
					else printf(" = 0x%lx\n", regs.rax);

					isSyscallEntrance ^= 1;
					ptrace(PTRACE_SYSCALL, pid, 0, 0);
					continue;
				}

				if(WSTOPSIG(status) != (SIGTRAP | 0x80)) {
					// printf("Signal %d\n", WSTOPSIG(status));
					if(WSTOPSIG(status) == SIGTRAP) {
						printf("int3 executed\n");
						ptrace(PTRACE_SYSCALL, pid, 0, 0);
					} else {
						ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(status));
					}
				} else {
					// syscall signal SIGTRAP
					// printf("Signal %d\n", WSTOPSIG(status));
					ptrace(PTRACE_GETREGS, pid, 0, &regs);

					outputNum = printSyscall(pid, &regs, isSyscallEntrance);

					isSyscallEntrance ^= 1;
					ptrace(PTRACE_SYSCALL, pid, 0, 0);
				}
			} else {
				err(EXIT_FAILURE, "wait status");
				kill(pid, SIGKILL);
				exit(EXIT_FAILURE);
			}
		}
	}
	printf("\n");

	return 0;
}

/* Now, it is assumed that all systemcall have 3 arguments.
 * The ideal is to output all systemcall according to this.
 * 1) If the number is string pointer, print the string.
 * 2) If the number is other pointer, print the address number by hexadecimal.
 * 3) If the number is not pointer and defined as general constants, print the constants string.
 * 4) If the number is other, print the number by decimal number.
 * 5) Print the systemcall arguments correctly.
 */
int printSyscall(pid_t pid, const struct user_regs_struct *regs, const char isSyscallEntrance) {
	int outputNum;
	outputNum = (printSuchSyscall[regs->orig_rax])(pid, regs, isSyscallEntrance, outputNum);
	return outputNum;
}

/* Print systemcall name from the id. 
 * Return number is the byte number that outputed by printf */
int printSyscallName(const int syscallID) {
	int x;
	switch(syscallID) {
	case 0: x=printf("read"); break;
	case 1: x=printf("write"); break;
	case 2: x=printf("open"); break;
	case 3: x=printf("close"); break;
	case 4: x=printf("stat"); break;
	case 5: x=printf("fstat"); break;
	case 6: x=printf("lstat"); break;
	case 7: x=printf("poll"); break;
	case 8: x=printf("lseek"); break;
	case 9: x=printf("mmap"); break;
	case 10: x=printf("mprotect"); break;
	case 11: x=printf("munmap"); break;
	case 12: x=printf("brk"); break;
	case 13: x=printf("rt_sigaction"); break;
	case 14: x=printf("rt_sigprocmask"); break;
	case 15: x=printf("rt_sigreturn"); break;
	case 16: x=printf("ioctl"); break;
	case 17: x=printf("pread64"); break;
	case 18: x=printf("pwrite64"); break;
	case 19: x=printf("readv"); break;
	case 20: x=printf("writev"); break;
	case 21: x=printf("access"); break;
	case 22: x=printf("pipe"); break;
	case 23: x=printf("select"); break;
	case 24: x=printf("sched_yield"); break;
	case 25: x=printf("mremap"); break;
	case 26: x=printf("msync"); break;
	case 27: x=printf("mincore"); break;
	case 28: x=printf("madvise"); break;
	case 29: x=printf("shmget"); break;
	case 30: x=printf("shmat"); break;
	case 31: x=printf("shmctl"); break;
	case 32: x=printf("dup"); break;
	case 33: x=printf("dup2"); break;
	case 34: x=printf("pause"); break;
	case 35: x=printf("nanosleep"); break;
	case 36: x=printf("getitimer"); break;
	case 37: x=printf("alarm"); break;
	case 38: x=printf("setitimer"); break;
	case 39: x=printf("getpid"); break;
	case 40: x=printf("sendfile"); break;
	case 41: x=printf("socket"); break;
	case 42: x=printf("connect"); break;
	case 43: x=printf("accept"); break;
	case 44: x=printf("sendto"); break;
	case 45: x=printf("recvfrom"); break;
	case 46: x=printf("sendmsg"); break;
	case 47: x=printf("recvmsg"); break;
	case 48: x=printf("shutdown"); break;
	case 49: x=printf("bind"); break;
	case 50: x=printf("listen"); break;
	case 51: x=printf("getsockname"); break;
	case 52: x=printf("getpeername"); break;
	case 53: x=printf("socketpair"); break;
	case 54: x=printf("setsockopt"); break;
	case 55: x=printf("getsockopt"); break;
	case 56: x=printf("clone"); break;
	case 57: x=printf("fork"); break;
	case 58: x=printf("vfork"); break;
	case 59: x=printf("execve"); break;
	case 60: x=printf("exit"); break;
	case 61: x=printf("wait4"); break;
	case 62: x=printf("kill"); break;
	case 63: x=printf("uname"); break;
	case 64: x=printf("semget"); break;
	case 65: x=printf("semop"); break;
	case 66: x=printf("semctl"); break;
	case 67: x=printf("shmdt"); break;
	case 68: x=printf("msgget"); break;
	case 69: x=printf("msgsnd"); break;
	case 70: x=printf("msgrcv"); break;
	case 71: x=printf("msgctl"); break;
	case 72: x=printf("fcntl"); break;
	case 73: x=printf("flock"); break;
	case 74: x=printf("fsync"); break;
	case 75: x=printf("fdatasync"); break;
	case 76: x=printf("truncate"); break;
	case 77: x=printf("ftruncate"); break;
	case 78: x=printf("getdents"); break;
	case 79: x=printf("getcwd"); break;
	case 80: x=printf("chdir"); break;
	case 81: x=printf("fchdir"); break;
	case 82: x=printf("rename"); break;
	case 83: x=printf("mkdir"); break;
	case 84: x=printf("rmdir"); break;
	case 85: x=printf("creat"); break;
	case 86: x=printf("link"); break;
	case 87: x=printf("unlink"); break;
	case 88: x=printf("symlink"); break;
	case 89: x=printf("readlink"); break;
	case 90: x=printf("chmod"); break;
	case 91: x=printf("fchmod"); break;
	case 92: x=printf("chown"); break;
	case 93: x=printf("fchown"); break;
	case 94: x=printf("lchown"); break;
	case 95: x=printf("umask"); break;
	case 96: x=printf("gettimeofday"); break;
	case 97: x=printf("getrlimit"); break;
	case 98: x=printf("getrusage"); break;
	case 99: x=printf("sysinfo"); break;
	case 100: x=printf("times"); break;
	case 101: x=printf("ptrace"); break;
	case 102: x=printf("getuid"); break;
	case 103: x=printf("syslog"); break;
	case 104: x=printf("getgid"); break;
	case 105: x=printf("setuid"); break;
	case 106: x=printf("setgid"); break;
	case 107: x=printf("geteuid"); break;
	case 108: x=printf("getegid"); break;
	case 109: x=printf("setpgid"); break;
	case 110: x=printf("getppid"); break;
	case 111: x=printf("getpgrp"); break;
	case 112: x=printf("setsid"); break;
	case 113: x=printf("setreuid"); break;
	case 114: x=printf("setregid"); break;
	case 115: x=printf("getgroups"); break;
	case 116: x=printf("setgroups"); break;
	case 117: x=printf("setresuid"); break;
	case 118: x=printf("getresuid"); break;
	case 119: x=printf("setresgid"); break;
	case 120: x=printf("getresgid"); break;
	case 121: x=printf("getpgid"); break;
	case 122: x=printf("setfsuid"); break;
	case 123: x=printf("setfsgid"); break;
	case 124: x=printf("getsid"); break;
	case 125: x=printf("capget"); break;
	case 126: x=printf("capset"); break;
	case 127: x=printf("rt_sigpending"); break;
	case 128: x=printf("rt_sigtimedwait"); break;
	case 129: x=printf("rt_sigqueueinfo"); break;
	case 130: x=printf("rt_sigsuspend"); break;
	case 131: x=printf("sigaltstack"); break;
	case 132: x=printf("utime"); break;
	case 133: x=printf("mknod"); break;
	case 134: x=printf("uselib"); break;
	case 135: x=printf("personality"); break;
	case 136: x=printf("ustat"); break;
	case 137: x=printf("statfs"); break;
	case 138: x=printf("fstatfs"); break;
	case 139: x=printf("sysfs"); break;
	case 140: x=printf("getpriority"); break;
	case 141: x=printf("setpriority"); break;
	case 142: x=printf("sched_setparam"); break;
	case 143: x=printf("sched_getparam"); break;
	case 144: x=printf("sched_setscheduler"); break;
	case 145: x=printf("sched_getscheduler"); break;
	case 146: x=printf("sched_get_priority_max"); break;
	case 147: x=printf("sched_get_priority_min"); break;
	case 148: x=printf("sched_rr_get_interval"); break;
	case 149: x=printf("mlock"); break;
	case 150: x=printf("munlock"); break;
	case 151: x=printf("mlockall"); break;
	case 152: x=printf("munlockall"); break;
	case 153: x=printf("vhangup"); break;
	case 154: x=printf("modify_ldt"); break;
	case 155: x=printf("pivot_root"); break;
	case 156: x=printf("_sysctl"); break;
	case 157: x=printf("prctl"); break;
	case 158: x=printf("arch_prctl"); break;
	case 159: x=printf("adjtimex"); break;
	case 160: x=printf("setrlimit"); break;
	case 161: x=printf("chroot"); break;
	case 162: x=printf("sync"); break;
	case 163: x=printf("acct"); break;
	case 164: x=printf("settimeofday"); break;
	case 165: x=printf("mount"); break;
	case 166: x=printf("umount2"); break;
	case 167: x=printf("swapon"); break;
	case 168: x=printf("swapoff"); break;
	case 169: x=printf("reboot"); break;
	case 170: x=printf("sethostname"); break;
	case 171: x=printf("setdomainname"); break;
	case 172: x=printf("iopl"); break;
	case 173: x=printf("ioperm"); break;
	case 174: x=printf("create_module"); break;
	case 175: x=printf("init_module"); break;
	case 176: x=printf("delete_module"); break;
	case 177: x=printf("get_kernel_syms"); break;
	case 178: x=printf("query_module"); break;
	case 179: x=printf("quotactl"); break;
	case 180: x=printf("nfsservctl"); break;
	case 181: x=printf("getpmsg"); break;
	case 182: x=printf("putpmsg"); break;
	case 183: x=printf("afs_syscall"); break;
	case 184: x=printf("tuxcall"); break;
	case 185: x=printf("security"); break;
	case 186: x=printf("gettid"); break;
	case 187: x=printf("readahead"); break;
	case 188: x=printf("setxattr"); break;
	case 189: x=printf("lsetxattr"); break;
	case 190: x=printf("fsetxattr"); break;
	case 191: x=printf("getxattr"); break;
	case 192: x=printf("lgetxattr"); break;
	case 193: x=printf("fgetxattr"); break;
	case 194: x=printf("listxattr"); break;
	case 195: x=printf("llistxattr"); break;
	case 196: x=printf("flistxattr"); break;
	case 197: x=printf("removexattr"); break;
	case 198: x=printf("lremovexattr"); break;
	case 199: x=printf("fremovexattr"); break;
	case 200: x=printf("tkill"); break;
	case 201: x=printf("time"); break;
	case 202: x=printf("futex"); break;
	case 203: x=printf("sched_setaffinity"); break;
	case 204: x=printf("sched_getaffinity"); break;
	case 205: x=printf("set_thread_area"); break;
	case 206: x=printf("io_setup"); break;
	case 207: x=printf("io_destroy"); break;
	case 208: x=printf("io_getevents"); break;
	case 209: x=printf("io_submit"); break;
	case 210: x=printf("io_cancel"); break;
	case 211: x=printf("get_thread_area"); break;
	case 212: x=printf("lookup_dcookie"); break;
	case 213: x=printf("epoll_create"); break;
	case 214: x=printf("epoll_ctl_old"); break;
	case 215: x=printf("epoll_wait_old"); break;
	case 216: x=printf("remap_file_pages"); break;
	case 217: x=printf("getdents64"); break;
	case 218: x=printf("set_tid_address"); break;
	case 219: x=printf("restart_syscall"); break;
	case 220: x=printf("semtimedop"); break;
	case 221: x=printf("fadvise64"); break;
	case 222: x=printf("timer_create"); break;
	case 223: x=printf("timer_settime"); break;
	case 224: x=printf("timer_gettime"); break;
	case 225: x=printf("timer_getoverrun"); break;
	case 226: x=printf("timer_delete"); break;
	case 227: x=printf("clock_settime"); break;
	case 228: x=printf("clock_gettime"); break;
	case 229: x=printf("clock_getres"); break;
	case 230: x=printf("clock_nanosleep"); break;
	case 231: x=printf("exit_group"); break;
	case 232: x=printf("epoll_wait"); break;
	case 233: x=printf("epoll_ctl"); break;
	case 234: x=printf("tgkill"); break;
	case 235: x=printf("utimes"); break;
	case 236: x=printf("vserver"); break;
	case 237: x=printf("mbind"); break;
	case 238: x=printf("set_mempolicy"); break;
	case 239: x=printf("get_mempolicy"); break;
	case 240: x=printf("mq_open"); break;
	case 241: x=printf("mq_unlink"); break;
	case 242: x=printf("mq_timedsend"); break;
	case 243: x=printf("mq_timedreceive"); break;
	case 244: x=printf("mq_notify"); break;
	case 245: x=printf("mq_getsetattr"); break;
	case 246: x=printf("kexec_load"); break;
	case 247: x=printf("waitid"); break;
	case 248: x=printf("add_key"); break;
	case 249: x=printf("request_key"); break;
	case 250: x=printf("keyctl"); break;
	case 251: x=printf("ioprio_set"); break;
	case 252: x=printf("ioprio_get"); break;
	case 253: x=printf("inotify_init"); break;
	case 254: x=printf("inotify_add_watch"); break;
	case 255: x=printf("inotify_rm_watch"); break;
	case 256: x=printf("migrate_pages"); break;
	case 257: x=printf("openat"); break;
	case 258: x=printf("mkdirat"); break;
	case 259: x=printf("mknodat"); break;
	case 260: x=printf("fchownat"); break;
	case 261: x=printf("futimesat"); break;
	case 262: x=printf("newfstatat"); break;
	case 263: x=printf("unlinkat"); break;
	case 264: x=printf("renameat"); break;
	case 265: x=printf("linkat"); break;
	case 266: x=printf("symlinkat"); break;
	case 267: x=printf("readlinkat"); break;
	case 268: x=printf("fchmodat"); break;
	case 269: x=printf("faccessat"); break;
	case 270: x=printf("pselect6"); break;
	case 271: x=printf("ppoll"); break;
	case 272: x=printf("unshare"); break;
	case 273: x=printf("set_robust_list"); break;
	case 274: x=printf("get_robust_list"); break;
	case 275: x=printf("splice"); break;
	case 276: x=printf("tee"); break;
	case 277: x=printf("sync_file_range"); break;
	case 278: x=printf("vmsplice"); break;
	case 279: x=printf("move_pages"); break;
	case 280: x=printf("utimensat"); break;
	case 281: x=printf("epoll_pwait"); break;
	case 282: x=printf("signalfd"); break;
	case 283: x=printf("timerfd_create"); break;
	case 284: x=printf("eventfd"); break;
	case 285: x=printf("fallocate"); break;
	case 286: x=printf("timerfd_settime"); break;
	case 287: x=printf("timerfd_gettime"); break;
	case 288: x=printf("accept4"); break;
	case 289: x=printf("signalfd4"); break;
	case 290: x=printf("eventfd2"); break;
	case 291: x=printf("epoll_create1"); break;
	case 292: x=printf("dup3"); break;
	case 293: x=printf("pipe2"); break;
	case 294: x=printf("inotify_init1"); break;
	case 295: x=printf("preadv"); break;
	case 296: x=printf("pwritev"); break;
	case 297: x=printf("rt_tgsigqueueinfo"); break;
	case 298: x=printf("perf_event_open"); break;
	case 299: x=printf("recvmmsg"); break;
	case 300: x=printf("fanotify_init"); break;
	case 301: x=printf("fanotify_mark"); break;
	case 302: x=printf("prlimit64"); break;
	case 303: x=printf("name_to_handle_at"); break;
	case 304: x=printf("open_by_handle_at"); break;
	case 305: x=printf("clock_adjtime"); break;
	case 306: x=printf("syncfs"); break;
	case 307: x=printf("sendmmsg"); break;
	case 308: x=printf("setns"); break;
	case 309: x=printf("getcpu"); break;
	case 310: x=printf("process_vm_readv"); break;
	case 311: x=printf("process_vm_writev"); break;
	case 312: x=printf("kcmp"); break;
	case 313: x=printf("finit_module"); break;
	case 314: x=printf("sched_setattr"); break;
	case 315: x=printf("sched_getattr"); break;
	case 316: x=printf("renameat2"); break;
	case 317: x=printf("seccomp"); break;
	case 318: x=printf("getrandom"); break;
	case 319: x=printf("memfd_create"); break;
	case 320: x=printf("kexec_file_load"); break;
	case 321: x=printf("bpf"); break;
	case 322: x=printf("execveat"); break;
	case 323: x=printf("userfaultfd"); break;
	case 324: x=printf("membarrier"); break;
	case 325: x=printf("mlock2"); break;
	case 326: x=printf("copy_file_range"); break;
	case 327: x=printf("preadv2"); break;
	case 328: x=printf("pwritev2"); break;
	case 329: x=printf("pkey_mprotect"); break;
	case 330: x=printf("pkey_alloc"); break;
	case 331: x=printf("pkey_free"); break;
	case 332: x=printf("statx"); break;
	case 333: x=printf("io_pgetevents"); break;
	case 334: x=printf("rseq"); break;
	case 424: x=printf("pidfd_send_signal"); break;
	case 425: x=printf("io_uring_setup"); break;
	case 426: x=printf("io_uring_enter"); break;
	case 427: x=printf("io_uring_register"); break;
	case 428: x=printf("open_tree"); break;
	case 429: x=printf("move_mount"); break;
	case 430: x=printf("fsopen"); break;
	case 431: x=printf("fsconfig"); break;
	case 432: x=printf("fsmount"); break;
	case 433: x=printf("fspick"); break;
	case 434: x=printf("pidfd_open"); break;
	case 435: x=printf("clone3"); break;
	default: x=printf("unknown"); break;
	}
	return x;
}
