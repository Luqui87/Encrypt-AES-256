#!/usr/bin/env python3
import sys
import argparse
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

from Crypto.Cipher import AES

def generate_key():
    
    key = get_random_bytes(32)

    file_out = open("./my_key.bin", "wb")
    file_out.write(key)
    file_out.close()


def get_key():
    with open("./my_key.bin", "rb") as k:
        key = k.read()
        k.close

    return key

def encrypt(filename):

    if not (os.path.isfile("./my_key.bin")):
        generate_key()

    key = get_key()

    with open(filename, 'rb') as f:
        file = f.read()
        f.close()

    cipher = AES.new(key, AES.MODE_CBC)
    ciphered_data = cipher.encrypt(pad(file, AES.block_size))

    file_out = open("./encrypted.bin", "wb")
    file_out.write(cipher.iv)
    file_out.write(ciphered_data)
    file_out.close()



def decrypt(filename):

    file_in = open(filename, 'rb')
    iv = file_in.read(16)
    ciphered_data = file_in.read()
    file_in.close()

    key = get_key()
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    original_data = unpad (cipher.decrypt(ciphered_data), AES.block_size)

    original_file = open("./decrypted.bin", "wb")
    original_file.write(original_data)
    original_file.close


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Encriptar archivo en AES-256")
    

    parser.add_argument('filename', help="un archivo para encriptar")
    parser.add_argument("-e", "--encrypt", action="store_true", default=False)
    parser.add_argument("-d", "--decrypt", action="store_true", default=False)

    args = parser.parse_args()

    if (args.encrypt):
        encrypt(args.filename)

    elif (args.decrypt):
        decrypt(args.filename)
