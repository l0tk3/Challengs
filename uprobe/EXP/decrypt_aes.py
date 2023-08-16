from Crypto.Cipher import AES
from pwn import *
key=b"bz{BV1FX4y1g7u8}"
value=[0xa26093e1,0x77f489f3,0x71c06cdf,0xff546f95]
en_data=p32(value[0])+p32(value[1])+p32(value[2])+p32(value[3])
aes=AES.new(key,AES.MODE_ECB)
data=aes.decrypt(en_data)
print(data)