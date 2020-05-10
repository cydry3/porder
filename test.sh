#!/bin/bash

#./porder -d /bin/ls

gcc -o ./test/execve_on_child ./test/test_execve.c
./porder -d ./test/execve_on_child
