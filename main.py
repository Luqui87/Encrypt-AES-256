# -*- encoding: utf-8 -*-
#!/usr/bin/env python3}

import argparse
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_512
from Crypto.Cipher import AES


def encrypt(filepath, outfile, password):

    salt = get_random_bytes(32)
    
    key = scrypt(password, salt, 32, N=2**20, r=8, p=1 )

    hashed_pwd = SHA3_512.new(data=password.encode("utf-8"))
    hashed_pwd.update(salt)
    hashed_pwd = hashed_pwd.digest()

    cipher = AES.new(key, AES.MODE_CFB)

    with open(filepath, 'rb') as f:
        file = f.read()
        f.close()

    file_out = open(outfile + ".bin", "wb")
    file_out.write(salt) # 32 bytes
    file_out.write(cipher.iv) # 16 bytes
    file_out.write(hashed_pwd) # 64 bytes

    ciphered_data = cipher.encrypt(file)

    file_out.write(ciphered_data)
    file_out.close()


def check_password(hashpwd, password, salt):
    new_hash = SHA3_512.new(data=password.encode("utf-8"))
    new_hash.update(salt)
    new_hash = new_hash.digest()

    return new_hash == hashpwd


def decrypt(filepath, outfile, password):

    input_file = open(filepath, "rb")

    bytes_temp = input_file.read(112)
    hashed_pwd = bytes_temp[48:112]
    salt = bytes_temp[:32]
    iv = bytes_temp[32:48]


    if not check_password(hashed_pwd, password, salt) :
        raise Exception("Contraseña incorrecta")

    key = scrypt(password, salt, 32, N=2**20, r=8, p=1 )

    cipher_data = input_file.read()
    output_file = open(outfile, "wb")

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)

    original_data = cipher.decrypt(cipher_data)

    output_file.write(original_data)
    output_file.close()



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Encriptar archivo en AES-256")
    

    # parser.add_argument('filepath', help="Un archivo para encriptar")
    # parser.add_argument('outfile', help='Nombre del archivo encriptado')
    # parser.add_argument('password', help="Contraseña para encriptar el archivo")
    # parser.add_argument("-e", "--encrypt", action="store_true", default=False)
    # parser.add_argument("-d", "--decrypt", action="store_true", default=False)

    # args = parser.parse_args()

    mode = input("Ingresar mode [E/D]: ")
    file_path = input("Ingresar dirección del archivo de entrada: ")
    outfile = input("Ingresar el nombre del archivo de salida: ")
    password = input("Ingresar contraseña: ")

    if (mode == "E"):
        encrypt(file_path, outfile, password)

    elif (mode == "D"):
        decrypt(file_path, outfile, password)
