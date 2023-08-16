f1=open("./main","rb+")
data=f1.read()
f1.close()
funcdata=data[0x67bf:0x67bf+0x3bc]
funcdata=list(funcdata)
print(funcdata)

###ida###
# start=0x67bf
# for i in range(0x3bc):
#     patch_byte(start+i,funcdata[i]^(i%256))