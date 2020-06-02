#!/usr/local/bin/python3

# output a table that convert address to assembly line.

# prerequsite: could disassemble a object file with `objdump -D [target executable]`
# usage: gen_asm_table.py [pid]

import sys
import re
import os
import subprocess

def conv_table(pid):
    desc_file = '/tmp/table_addr2asm'
    tmp_tables = {}
    obj_addr_pairs= read_child_proc_file(pid)
    for obj_path, base_addr in obj_addr_pairs.items():
        dumped_file = obj_dump(pid, obj_path)
        tmp_tables[dumped_file] = base_addr
    write_tables(desc_file, tmp_tables)
    cleanup(tmp_tables)

def read_child_proc_file(pid):
    obj_addr_pairs= {}
    child_proc_file = "/proc/%s/maps" % pid
    with open(child_proc_file, "r") as proc_file:
        re_pat = re.compile('^(\w+)-.+:\w+\ \w+\ +(/.+)')
        for line in proc_file:
            m = re_pat.match(line)
            if m:
                if not (m.group(2) in obj_addr_pairs):
                    obj_addr_pairs[m.group(2)] = m.group(1)
    return obj_addr_pairs

def obj_dump(pid, obj_path):
    tmp_table_name = "tmp_table_addr2asm_" + pid + obj_path.replace('/', '_').replace('.', '_')
    with open(tmp_table_name, "w") as conv_file:
        p = subprocess.Popen(["/usr/bin/objdump", "-D", obj_path], stdout=conv_file)
        p.wait()
    return tmp_table_name

def write_tables(desc_filename, tmp_tables):
    with open(desc_filename, 'a') as desc_file:
        for tmp_filename, base_addr in tmp_tables.items():
            write_table(desc_file, tmp_filename, base_addr)

def write_table(desc_file, disassembled_file, base_addr):
    base_addr = int(base_addr, 16)
    with open(disassembled_file, 'r') as disasm_file:
        for line in disasm_file:
            m = re.match('^\ +(\w+):(.*)', line)
            if m:
                offset_addr = int(m.group(1), 16)
                offset_addr += base_addr
                desc_file.write("%x:%s\n" % (offset_addr, m.group(2)))

def cleanup(tmp_tables):
    for fname in tmp_tables.keys():
        os.remove(fname)


def script_main():
    arglen = len(sys.argv)
    if arglen != 2:
        print("usage: gen_asm_table.py [pid]")
        sys.exit(1)
    else:
        pid = sys.argv[1]
        conv_table(pid)

# Execute as command
if __name__ == "__main__":
    script_main()
