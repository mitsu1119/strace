.PHONY: all
all: strace.c strace.h syscallDefs.h syscall_ps.c
	gcc strace.c syscall_ps.c -o run
