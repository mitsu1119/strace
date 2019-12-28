import sys
import re

# Usage: cat /.../unistd_XX.h | python genTable.py

for line in iter(sys.stdin.readline, ""):
    r = re.match('^#define __NR_(\S+)\s+(\d+)$', line)
    if r:
        print("\tcase {}: printf(\"{}\"); break;".format(r.group(2), r.group(1)))
