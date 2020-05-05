#!/usr/local/bin/python3

# output a table that convert address to assembly line.

# prerequsite: only accepts a disassembled file by `objdump -D [target executable]`
# usage: gen_asm_table.py [disassembled filename]

import sys
import re

src_file = sys.argv[1]

desc_filename= 'table_addr2asm' 
desc_file= open(desc_filename, 'w')

disassembled_file = open(src_file, 'r')
for line in disassembled_file:
    m = re.match('^(\ +)(.*)', line)

    if m:
        desc_file.write("%s\n" % m.group(2))
