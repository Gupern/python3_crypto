# python3_crypto
a tool for encrypt and decrypt with different cryptography algorithim using *python3.6*

## supported cryptography algorithim

- DES 
- AES 
- RC4 
- RSA


# 安装模块

	`pip3 install pyDes`
	`pip3 install pycryptodome` | `pip3 install pycrypt`
	`pip3 install rc4-python3`
	`pip3 install rsa`

# 命令demo

	python cryptography.py <inputfile> <encrypt/decrypt> <key1> <key2> <outputfile> <des/aes/rc4/rsa>

### des的key1需要8个字符，key2也要8个字符

	python3 crytography.py ./1.jpg encrypt 12345678 12345678 ./endes.txt des
	python3 crytography.py ./endes.txt decrypt 12345678 12345678 ./dedes.jpg des

### aes的key1需要16个字符， 不需要key2，但是程序入口需要加，所以默认12345678即可

	python3 crytography.py ./1.jpg encrypt 1234567890123456 12345678 ./enaes.txt aes
	python3 crytography.py ./enaes.txt decrypt 1234567890123456 12345678 ./deaes.jpg aes

### rc4 key1为密钥至少5位，key2无用，但需要输入

	python3 crytography.py ./1.jpg encrypt 12345678 12345678 ./enrc4.txt rc4
	python3 crytography.py ./enrc4.txt decrypt 12345678 12345678 ./derc4.jpg rc4

### rsa 命令，key1和key2无用，将公密钥public.pem/private.pem放在当前目录下即可

	python3 crytography.py ./1.jpg encrypt 12345678 12345678 ./enrsa.txt rsa
	python3 crytography.py ./enrsa.txt decrypt 12345678 12345678 ./dersa.jpg rsa
