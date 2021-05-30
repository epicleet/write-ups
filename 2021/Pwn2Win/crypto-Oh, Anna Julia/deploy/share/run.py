#!/usr/bin/python3 -u
import subprocess

try:
    subprocess.call(["julia", "/home/pwn/chall.jl"], stderr=subprocess.DEVNULL, timeout=3600*2)
except:
    pass
