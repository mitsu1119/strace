#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

void printSyscallName(int syscallID);

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
		int status = 0;
		char isSyscallEntrance = 0;	// The first SIGTRAP means execve's end
		struct user_regs_struct regs;
		char ptracesetoptionsFlag = 0;
		
		while(1) {
			// wait child signal
			pid_t w = waitpid(pid, &status, WUNTRACED | WCONTINUED);

			if(WIFEXITED(status)) {
				break;
			} else if(WIFSIGNALED(status)) {
				break;
			} else if(WIFSTOPPED(status)) {
				// first signal... SIGSTOP
				// setting ptrace(PTRACE_SETOPTIONS, ...)
				if(!ptracesetoptionsFlag) {
					ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC);
					ptracesetoptionsFlag = 1;
				}

				if(WSTOPSIG(status) != (SIGTRAP | 0x80) && WSTOPSIG(status) != SIGTRAP) {
					printf("Signal %d\n", WSTOPSIG(status));
					ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(status));
				} else {
					// syscall signal SIGTRAP
					printf("Signal %d\n", WSTOPSIG(status));
					ptrace(PTRACE_GETREGS, pid, 0, &regs);

					if(isSyscallEntrance) printf("Syscall start ");
					else printf("Syscall end ");
					printSyscallName(regs.orig_rax);
					putchar('\n');

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

	return 0;
}

// Print systemcall name from the id. */
void printSyscallName(int syscallID) {
	switch(syscallID) {
	case 0: printf("read"); break;
	case 1: printf("write"); break;
	case 2: printf("open"); break;
	case 3: printf("close"); break;
	case 4: printf("stat"); break;
	case 5: printf("fstat"); break;
	case 6: printf("lstat"); break;
	case 7: printf("poll"); break;
	case 8: printf("lseek"); break;
	case 9: printf("mmap"); break;
	case 10: printf("mprotect"); break;
	case 11: printf("munmap"); break;
	case 12: printf("brk"); break;
	case 13: printf("rt_sigaction"); break;
	case 14: printf("rt_sigprocmask"); break;
	case 15: printf("rt_sigreturn"); break;
	case 16: printf("ioctl"); break;
	case 17: printf("pread64"); break;
	case 18: printf("pwrite64"); break;
	case 19: printf("readv"); break;
	case 20: printf("writev"); break;
	case 21: printf("access"); break;
	case 22: printf("pipe"); break;
	case 23: printf("select"); break;
	case 24: printf("sched_yield"); break;
	case 25: printf("mremap"); break;
	case 26: printf("msync"); break;
	case 27: printf("mincore"); break;
	case 28: printf("madvise"); break;
	case 29: printf("shmget"); break;
	case 30: printf("shmat"); break;
	case 31: printf("shmctl"); break;
	case 32: printf("dup"); break;
	case 33: printf("dup2"); break;
	case 34: printf("pause"); break;
	case 35: printf("nanosleep"); break;
	case 36: printf("getitimer"); break;
	case 37: printf("alarm"); break;
	case 38: printf("setitimer"); break;
	case 39: printf("getpid"); break;
	case 40: printf("sendfile"); break;
	case 41: printf("socket"); break;
	case 42: printf("connect"); break;
	case 43: printf("accept"); break;
	case 44: printf("sendto"); break;
	case 45: printf("recvfrom"); break;
	case 46: printf("sendmsg"); break;
	case 47: printf("recvmsg"); break;
	case 48: printf("shutdown"); break;
	case 49: printf("bind"); break;
	case 50: printf("listen"); break;
	case 51: printf("getsockname"); break;
	case 52: printf("getpeername"); break;
	case 53: printf("socketpair"); break;
	case 54: printf("setsockopt"); break;
	case 55: printf("getsockopt"); break;
	case 56: printf("clone"); break;
	case 57: printf("fork"); break;
	case 58: printf("vfork"); break;
	case 59: printf("execve"); break;
	case 60: printf("exit"); break;
	case 61: printf("wait4"); break;
	case 62: printf("kill"); break;
	case 63: printf("uname"); break;
	case 64: printf("semget"); break;
	case 65: printf("semop"); break;
	case 66: printf("semctl"); break;
	case 67: printf("shmdt"); break;
	case 68: printf("msgget"); break;
	case 69: printf("msgsnd"); break;
	case 70: printf("msgrcv"); break;
	case 71: printf("msgctl"); break;
	case 72: printf("fcntl"); break;
	case 73: printf("flock"); break;
	case 74: printf("fsync"); break;
	case 75: printf("fdatasync"); break;
	case 76: printf("truncate"); break;
	case 77: printf("ftruncate"); break;
	case 78: printf("getdents"); break;
	case 79: printf("getcwd"); break;
	case 80: printf("chdir"); break;
	case 81: printf("fchdir"); break;
	case 82: printf("rename"); break;
	case 83: printf("mkdir"); break;
	case 84: printf("rmdir"); break;
	case 85: printf("creat"); break;
	case 86: printf("link"); break;
	case 87: printf("unlink"); break;
	case 88: printf("symlink"); break;
	case 89: printf("readlink"); break;
	case 90: printf("chmod"); break;
	case 91: printf("fchmod"); break;
	case 92: printf("chown"); break;
	case 93: printf("fchown"); break;
	case 94: printf("lchown"); break;
	case 95: printf("umask"); break;
	case 96: printf("gettimeofday"); break;
	case 97: printf("getrlimit"); break;
	case 98: printf("getrusage"); break;
	case 99: printf("sysinfo"); break;
	case 100: printf("times"); break;
	case 101: printf("ptrace"); break;
	case 102: printf("getuid"); break;
	case 103: printf("syslog"); break;
	case 104: printf("getgid"); break;
	case 105: printf("setuid"); break;
	case 106: printf("setgid"); break;
	case 107: printf("geteuid"); break;
	case 108: printf("getegid"); break;
	case 109: printf("setpgid"); break;
	case 110: printf("getppid"); break;
	case 111: printf("getpgrp"); break;
	case 112: printf("setsid"); break;
	case 113: printf("setreuid"); break;
	case 114: printf("setregid"); break;
	case 115: printf("getgroups"); break;
	case 116: printf("setgroups"); break;
	case 117: printf("setresuid"); break;
	case 118: printf("getresuid"); break;
	case 119: printf("setresgid"); break;
	case 120: printf("getresgid"); break;
	case 121: printf("getpgid"); break;
	case 122: printf("setfsuid"); break;
	case 123: printf("setfsgid"); break;
	case 124: printf("getsid"); break;
	case 125: printf("capget"); break;
	case 126: printf("capset"); break;
	case 127: printf("rt_sigpending"); break;
	case 128: printf("rt_sigtimedwait"); break;
	case 129: printf("rt_sigqueueinfo"); break;
	case 130: printf("rt_sigsuspend"); break;
	case 131: printf("sigaltstack"); break;
	case 132: printf("utime"); break;
	case 133: printf("mknod"); break;
	case 134: printf("uselib"); break;
	case 135: printf("personality"); break;
	case 136: printf("ustat"); break;
	case 137: printf("statfs"); break;
	case 138: printf("fstatfs"); break;
	case 139: printf("sysfs"); break;
	case 140: printf("getpriority"); break;
	case 141: printf("setpriority"); break;
	case 142: printf("sched_setparam"); break;
	case 143: printf("sched_getparam"); break;
	case 144: printf("sched_setscheduler"); break;
	case 145: printf("sched_getscheduler"); break;
	case 146: printf("sched_get_priority_max"); break;
	case 147: printf("sched_get_priority_min"); break;
	case 148: printf("sched_rr_get_interval"); break;
	case 149: printf("mlock"); break;
	case 150: printf("munlock"); break;
	case 151: printf("mlockall"); break;
	case 152: printf("munlockall"); break;
	case 153: printf("vhangup"); break;
	case 154: printf("modify_ldt"); break;
	case 155: printf("pivot_root"); break;
	case 156: printf("_sysctl"); break;
	case 157: printf("prctl"); break;
	case 158: printf("arch_prctl"); break;
	case 159: printf("adjtimex"); break;
	case 160: printf("setrlimit"); break;
	case 161: printf("chroot"); break;
	case 162: printf("sync"); break;
	case 163: printf("acct"); break;
	case 164: printf("settimeofday"); break;
	case 165: printf("mount"); break;
	case 166: printf("umount2"); break;
	case 167: printf("swapon"); break;
	case 168: printf("swapoff"); break;
	case 169: printf("reboot"); break;
	case 170: printf("sethostname"); break;
	case 171: printf("setdomainname"); break;
	case 172: printf("iopl"); break;
	case 173: printf("ioperm"); break;
	case 174: printf("create_module"); break;
	case 175: printf("init_module"); break;
	case 176: printf("delete_module"); break;
	case 177: printf("get_kernel_syms"); break;
	case 178: printf("query_module"); break;
	case 179: printf("quotactl"); break;
	case 180: printf("nfsservctl"); break;
	case 181: printf("getpmsg"); break;
	case 182: printf("putpmsg"); break;
	case 183: printf("afs_syscall"); break;
	case 184: printf("tuxcall"); break;
	case 185: printf("security"); break;
	case 186: printf("gettid"); break;
	case 187: printf("readahead"); break;
	case 188: printf("setxattr"); break;
	case 189: printf("lsetxattr"); break;
	case 190: printf("fsetxattr"); break;
	case 191: printf("getxattr"); break;
	case 192: printf("lgetxattr"); break;
	case 193: printf("fgetxattr"); break;
	case 194: printf("listxattr"); break;
	case 195: printf("llistxattr"); break;
	case 196: printf("flistxattr"); break;
	case 197: printf("removexattr"); break;
	case 198: printf("lremovexattr"); break;
	case 199: printf("fremovexattr"); break;
	case 200: printf("tkill"); break;
	case 201: printf("time"); break;
	case 202: printf("futex"); break;
	case 203: printf("sched_setaffinity"); break;
	case 204: printf("sched_getaffinity"); break;
	case 205: printf("set_thread_area"); break;
	case 206: printf("io_setup"); break;
	case 207: printf("io_destroy"); break;
	case 208: printf("io_getevents"); break;
	case 209: printf("io_submit"); break;
	case 210: printf("io_cancel"); break;
	case 211: printf("get_thread_area"); break;
	case 212: printf("lookup_dcookie"); break;
	case 213: printf("epoll_create"); break;
	case 214: printf("epoll_ctl_old"); break;
	case 215: printf("epoll_wait_old"); break;
	case 216: printf("remap_file_pages"); break;
	case 217: printf("getdents64"); break;
	case 218: printf("set_tid_address"); break;
	case 219: printf("restart_syscall"); break;
	case 220: printf("semtimedop"); break;
	case 221: printf("fadvise64"); break;
	case 222: printf("timer_create"); break;
	case 223: printf("timer_settime"); break;
	case 224: printf("timer_gettime"); break;
	case 225: printf("timer_getoverrun"); break;
	case 226: printf("timer_delete"); break;
	case 227: printf("clock_settime"); break;
	case 228: printf("clock_gettime"); break;
	case 229: printf("clock_getres"); break;
	case 230: printf("clock_nanosleep"); break;
	case 231: printf("exit_group"); break;
	case 232: printf("epoll_wait"); break;
	case 233: printf("epoll_ctl"); break;
	case 234: printf("tgkill"); break;
	case 235: printf("utimes"); break;
	case 236: printf("vserver"); break;
	case 237: printf("mbind"); break;
	case 238: printf("set_mempolicy"); break;
	case 239: printf("get_mempolicy"); break;
	case 240: printf("mq_open"); break;
	case 241: printf("mq_unlink"); break;
	case 242: printf("mq_timedsend"); break;
	case 243: printf("mq_timedreceive"); break;
	case 244: printf("mq_notify"); break;
	case 245: printf("mq_getsetattr"); break;
	case 246: printf("kexec_load"); break;
	case 247: printf("waitid"); break;
	case 248: printf("add_key"); break;
	case 249: printf("request_key"); break;
	case 250: printf("keyctl"); break;
	case 251: printf("ioprio_set"); break;
	case 252: printf("ioprio_get"); break;
	case 253: printf("inotify_init"); break;
	case 254: printf("inotify_add_watch"); break;
	case 255: printf("inotify_rm_watch"); break;
	case 256: printf("migrate_pages"); break;
	case 257: printf("openat"); break;
	case 258: printf("mkdirat"); break;
	case 259: printf("mknodat"); break;
	case 260: printf("fchownat"); break;
	case 261: printf("futimesat"); break;
	case 262: printf("newfstatat"); break;
	case 263: printf("unlinkat"); break;
	case 264: printf("renameat"); break;
	case 265: printf("linkat"); break;
	case 266: printf("symlinkat"); break;
	case 267: printf("readlinkat"); break;
	case 268: printf("fchmodat"); break;
	case 269: printf("faccessat"); break;
	case 270: printf("pselect6"); break;
	case 271: printf("ppoll"); break;
	case 272: printf("unshare"); break;
	case 273: printf("set_robust_list"); break;
	case 274: printf("get_robust_list"); break;
	case 275: printf("splice"); break;
	case 276: printf("tee"); break;
	case 277: printf("sync_file_range"); break;
	case 278: printf("vmsplice"); break;
	case 279: printf("move_pages"); break;
	case 280: printf("utimensat"); break;
	case 281: printf("epoll_pwait"); break;
	case 282: printf("signalfd"); break;
	case 283: printf("timerfd_create"); break;
	case 284: printf("eventfd"); break;
	case 285: printf("fallocate"); break;
	case 286: printf("timerfd_settime"); break;
	case 287: printf("timerfd_gettime"); break;
	case 288: printf("accept4"); break;
	case 289: printf("signalfd4"); break;
	case 290: printf("eventfd2"); break;
	case 291: printf("epoll_create1"); break;
	case 292: printf("dup3"); break;
	case 293: printf("pipe2"); break;
	case 294: printf("inotify_init1"); break;
	case 295: printf("preadv"); break;
	case 296: printf("pwritev"); break;
	case 297: printf("rt_tgsigqueueinfo"); break;
	case 298: printf("perf_event_open"); break;
	case 299: printf("recvmmsg"); break;
	case 300: printf("fanotify_init"); break;
	case 301: printf("fanotify_mark"); break;
	case 302: printf("prlimit64"); break;
	case 303: printf("name_to_handle_at"); break;
	case 304: printf("open_by_handle_at"); break;
	case 305: printf("clock_adjtime"); break;
	case 306: printf("syncfs"); break;
	case 307: printf("sendmmsg"); break;
	case 308: printf("setns"); break;
	case 309: printf("getcpu"); break;
	case 310: printf("process_vm_readv"); break;
	case 311: printf("process_vm_writev"); break;
	case 312: printf("kcmp"); break;
	case 313: printf("finit_module"); break;
	case 314: printf("sched_setattr"); break;
	case 315: printf("sched_getattr"); break;
	case 316: printf("renameat2"); break;
	case 317: printf("seccomp"); break;
	case 318: printf("getrandom"); break;
	case 319: printf("memfd_create"); break;
	case 320: printf("kexec_file_load"); break;
	case 321: printf("bpf"); break;
	case 322: printf("execveat"); break;
	case 323: printf("userfaultfd"); break;
	case 324: printf("membarrier"); break;
	case 325: printf("mlock2"); break;
	case 326: printf("copy_file_range"); break;
	case 327: printf("preadv2"); break;
	case 328: printf("pwritev2"); break;
	case 329: printf("pkey_mprotect"); break;
	case 330: printf("pkey_alloc"); break;
	case 331: printf("pkey_free"); break;
	case 332: printf("statx"); break;
	case 333: printf("io_pgetevents"); break;
	case 334: printf("rseq"); break;
	case 424: printf("pidfd_send_signal"); break;
	case 425: printf("io_uring_setup"); break;
	case 426: printf("io_uring_enter"); break;
	case 427: printf("io_uring_register"); break;
	case 428: printf("open_tree"); break;
	case 429: printf("move_mount"); break;
	case 430: printf("fsopen"); break;
	case 431: printf("fsconfig"); break;
	case 432: printf("fsmount"); break;
	case 433: printf("fspick"); break;
	case 434: printf("pidfd_open"); break;
	case 435: printf("clone3"); break;
	default: printf("unknown"); break;
	}
}
