#!/bin/bash

objdump -D /bin/ls > test/dumped_ls

./gen_asm_table.py test/dumped_ls

./porder /bin/ls | ./conv_addr2asm.py
