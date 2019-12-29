import sys
import re

# Usage: cat /.../unistd_XX.h | python genTable.py

# print defines
if len(sys.argv) >= 2 and sys.argv[1] == "-d":
    for line in iter(sys.stdin.readline, ""):
        r = re.match('^#define __NR_(\S+)\s+(\d+)$', line)
        if r:
            print("#define MYSYS_{} {}".format(r.group(1), r.group(2)))
else:
    print("/* Print systemcall name from the id.")
    print(" * Return number is the length of name. */")
    print("int printSyscallName(int syscallID) {")
    print("\tint x;");
    print("\tswitch(syscallID) {")

    for line in iter(sys.stdin.readline, ""):
        r = re.match('^#define __NR_(\S+)\s+(\d+)$', line)
        if r:
            print("\tcase {}: x=printf(\"{}\"); break;".format(r.group(2), r.group(1)))

    print("\tdefault: x=printf(\"unknown\"); break;")
    print("\t}")
    print("\treturn x")
    print("}")
