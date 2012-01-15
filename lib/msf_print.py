#!/usr/bin/env python

def print_status(message):
    print("\033[1;34m[*]\033[1;m {0}".format(message))

def print_good(message):
    print("\033[1;32m[*]\033[1;m {0}".format(message))

def print_error(message):
    print("\033[1;31m[-]\033[1;m {0}".format(message))
    
def print_line(message):
    print("{0}".format(message))
          

print_status("Hello world")
print_error("This is an error")
print_good("Nice!!!")