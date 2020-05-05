#!/usr/local/bin/python3

# print a line that is converted a address to a assembly.
# prerequisite: exist a file that has a table for the conversion.
#               The table's name is `table_addr2asm`

import sys
import re

src_file = "table_addr2asm"
addr = sys.argv[1]
asm_line = []

table_file = open(src_file, 'r')
for line in table_file:
    m = re.match('^(\d+):(.*)', line)

    if m:
        if addr == m.group(1):
            asm_line.append(m)

if len(asm_line) > 0:
    m = asm_line[0]
    print("%s %s" % (m.group(1), m.group(2)))
else:
    print("Assembly code is Unknown (%s)" % (addr))
