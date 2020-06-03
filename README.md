# porder

[![Build Status](https://travis-ci.com/cydry3/porder.svg?branch=master)](https://travis-ci.com/cydry3/porder)

**porder** is a system call tracer. Prints system calls and instructions of a Linux command.

## usage

### Running
`porder [-s][-i][-v] command [args]`

#### options
- ` -s print system calls`
- ` -i print instructions`
- ` -v print verbosely`

#### example
![porder-example](https://user-images.githubusercontent.com/50176101/83503611-4dac3000-a4fe-11ea-9a92-d28c4aa62e17.gif)

#### limitation
- build target : Ubuntu 18.04 LTS (Bionic Beaver)
