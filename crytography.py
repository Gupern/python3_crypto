# -*- coding: utf-8 -*-
import argparse
from pyDes import *
import sys 
from Cryptodome.Cipher import AES, ARC4
from binascii import b2a_hex, a2b_hex, hexlify
import sys,os,hashlib,time,base64
import rc4
import random, base64
from hashlib import sha1
from Crypto.Cipher import ARC4 as rc4cipher
import rsa
import sys,os,hashlib,time,base64

class aes_prpcrypt():
    def __init__(self, key):
        
        # self.key = key
        self.key = bytes(key, encoding='utf-8')
        self.mode = AES.MODE_CBC
     
    #加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数
    def encrypt(self, text):
        print(type(text))
        cryptor = AES.new(self.key, self.mode, self.key)
        print(type(text))

        #这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.目前AES-128足够用
        length = 16
        count = len(text)
        add = length - (count % length)
        text = text + (bytes('\0',encoding="utf-8") * add)
        self.ciphertext = cryptor.encrypt(text)
        #因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        #所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)
     
    #解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip(bytes('\0', encoding="utf-8"))

#rsa加密  
def rsaEncrypt(data, pubkey):  

    #明文编码格式  
    content = data
    #公钥加密  
    crypto = rsa.encrypt(content,pubkey)  
    return crypto
  
#rsa解密  
def rsaDecrypt(data,pk):  
    #私钥解密  
    content = rsa.decrypt(data,pk)  
    con=content 
    return con  

def des_algorithm(encrypt_or_decrypt, data, key1, key2):
    '''des de/encrypt algorithm'''
    k = des(key1, CBC, key2, pad=None, padmode=PAD_PKCS5)

    if encrypt_or_decrypt=="encrypt":
        res = k.encrypt(data)
        return True, res
    elif encrypt_or_decrypt=="decrypt":
        res = k.decrypt(data)
        return True, res
    else:
        print("methods is wrong")
        return False, ''

def aes_algorithm(encrypt_or_decrypt, data, key1, key2):
    '''des de/encrypt algorithm'''
    k = aes_prpcrypt(key1)

    if encrypt_or_decrypt=="encrypt":
        res = k.encrypt(data)
        return True, res
    elif encrypt_or_decrypt=="decrypt":
        res = k.decrypt(data)
        return True, res
    else:
        print("methods is wrong")
        return False, ''

def rc4_algorithm(encrypt_or_decrypt, data, key1, key2):
    '''des de/encrypt algorithm'''
    if encrypt_or_decrypt=="encrypt":
        key = bytes(key1, encoding='utf-8')
        enc = rc4cipher.new(key)
        res = enc.encrypt(data)
        return True, res
    elif encrypt_or_decrypt=="decrypt":
        key = bytes(key1, encoding='utf-8')
        enc = rc4cipher.new(key)
        res = enc.decrypt(data)
        return True, res
    else:
        print("methods is wrong")
        return False, ''

def rsa_algorithm(encrypt_or_decrypt, data, key1, key2):
    '''rsa de/encrypt algorithm'''
    if encrypt_or_decrypt=="encrypt":
        #生成公钥、私钥  1024位
        (pubkey, privkey) = rsa.newkeys(1024)  
        # print("public key is: ", pubkey)
        # print("private key is: ", privkey)
        with open('./public.pem','w+') as f:
            f.write(pubkey.save_pkcs1().decode())
        with open('./private.pem','w+') as f:
            f.write(privkey.save_pkcs1().decode())

        res = b''
        dataLen = len(data) # 分块加密
        while dataLen>0:
            # print(dataLen)
            dataLen -= 117
            crypto = rsaEncrypt(data[:117], pubkey)
            data = data[117:]
            res += crypto
            print(len(res))
        return True, res
    elif encrypt_or_decrypt=="decrypt":
        dataLen = len(data)
        res = b''
        with open('./private.pem','r') as f:
            privkey = rsa.PrivateKey.load_pkcs1(f.read().encode())
        key2 = privkey
        # 分组解密，公钥为1024时，加密时117位一组，解密时128位一组
        while dataLen>0:
            print(dataLen)
            dataLen -= 128
            crypto = rsaDecrypt(data[:128], key2)
            data = data[128:]
            res += crypto
        return True, res
    else:
        print("methods is wrong")
        return False, ''


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file_location", help="Input the file location you want to process")
    parser.add_argument("encrypt_or_decrypt", help="you want to encrypt or decrypt?")
    parser.add_argument("key1", help="key1, for des")
    parser.add_argument("key2", help="key2, can be none")
    parser.add_argument("output_file_location", help="the location you want to output")
    parser.add_argument("methods", help="input the algorithm you wanna, des/aes/rc4/rsa")


    args = parser.parse_args()

    input_file_location = sys.argv[1]
    encrypt_or_decrypt = sys.argv[2]
    key1 = sys.argv[3]
    key2 = sys.argv[4]
    output_file_location = sys.argv[5]
    methods = sys.argv[6]
    data = open(input_file_location, 'rb').read()

    print(type(data))
    # print('data:', data, '\n')

    if methods=='des':
        success, res = des_algorithm(encrypt_or_decrypt, data, key1, key2)
    elif methods=='aes':
        success, res = aes_algorithm(encrypt_or_decrypt, data, key1, key2)
    elif methods=='rc4':
        success, res = rc4_algorithm(encrypt_or_decrypt, data, key1, key2)
    elif methods=='rsa':
        success, res = rsa_algorithm(encrypt_or_decrypt, data, key1, key2)


    # print('res:', res, '\n', type(res))
    # 加密时
    if encrypt_or_decrypt=='encrypt':
        with open(output_file_location, 'wb') as f:
            f.write(res)

    # 解密时
    elif encrypt_or_decrypt=='decrypt':
        with open(output_file_location, 'wb') as f:
            f.write(res)