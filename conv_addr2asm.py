#!/usr/local/bin/python3

# print a line that is converted a address to a assembly.
# prerequisite: exist a file that has a table for the conversion.
#               The table's name is `table_addr2asm`

import sys
import re

# Convertion table object
class Addr2Asm:
    src_file = "table_addr2asm"
    regex_pat = []
    table_file = []

    def __init__(self):
        f = open(self.src_file, 'r')
        self.table_file.append(f)
        self.regex_pat.append(re.compile('^(\w+):(.*)'))

    def drop_self(self):
        self.table_file[0].close()

    def print(self, addr):
        for line in self.table_file[0]:
            m = self.regex_pat[0].match(line)
            if m:
                if addr == m.group(1):
                    print("%s %s" % (m.group(1), m.group(2)))
                    self.table_file[0].seek(0)
                    return
        self.table_file[0].seek(0)
        print("%s unknown" % (addr))


# Accept 1 address, print conveted assemply line at once.
def print_at_once(addr):
    conv = Addr2Asm()
    conv.print(addr)


# Accept addresses from stdin stream, print assembly lines inititely.
def print_stream():
    conv = Addr2Asm()
    while True:
        try:
            addr = input()
            conv.print(addr)
        except EOFError:
            break
        except:
            print("unexpected error:", sys.exec_info())
            raise

# Entry point
def script_main():
    arglen = len(sys.argv)
    if arglen == 1:
        print_stream()

    elif arglen == 2:
        addr = sys.argv[1]
        print_at_once(addr)
    else:
        print("failed to get a address")
        print("usage: conv_addr2asm.py [address string]")
        sys.exit(1)


# Execute as command
if __name__ == "__main__":
    script_main()
