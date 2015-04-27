#!/usr/bin/env python
import sys
import platform

# -*- coding: utf-8 -*-

#    Copyright (C) 2012  Carlos Perez
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; Applies version 2 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


def print_status(message=""):
    if sys.stdout.isatty() and platform.system() != "Windows":
        print("\033[1;34m[*]\033[1;m {0}".format(message))
    else:
        print("[*] {0}".format(message))


def print_good(message=""):
    if sys.stdout.isatty() and platform.system() != "Windows":
        print("\033[1;32m[+]\033[1;m {0}".format(message))
    else:
        print("[+] {0}".format(message))


def print_error(message=""):
    if sys.stdout.isatty() and platform.system() != "Windows":
        print("\033[1;31m[-]\033[1;m {0}".format(message))
    else:
        print("[-] {0}".format(message))


def print_debug(message=""):
    if sys.stdout.isatty() and platform.system() != "Windows":
        print("\033[1;31m[!]\033[1;m {0}".format(message))
    else:
        print("[!] {0}".format(message))


def print_line(message=""):
    print("{0}".format(message))
