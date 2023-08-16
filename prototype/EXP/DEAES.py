from Crypto.Cipher import AES
def xtime(a):
    temp=a<<1
    temp=temp%256
    # print(temp)
    if ((a >> 7) & 0x01)==1:
        temp=temp^27
    # print(temp)
    # print("--------")
    return temp
def MixColumns(state):
    state=list(state)
    # print(state)
    for i in range(4):
        s0=state[4*i]
        s1=state[1+4*i]
        s2=state[2+4*i]
        s3=state[3+4*i]
        state[4*i]=xtime(s0) ^ (xtime(s1)^s1) ^ s2 ^ s3
        state[1+4*i]=s0 ^ xtime(s1) ^ (xtime(s2)^s2) ^ s3
        state[2+4*i]=s0 ^ s1 ^ xtime(s2) ^ (xtime(s3)^s3)
        state[3+4*i]=(xtime(s0)^s0) ^ s1 ^ s2 ^ xtime(s3)
    # print(state)
    return bytes(bytearray(state))
def bytesxor(b1,b2):
    b1=list(b1)
    b2=list(b2)
    for i in range(len(b1)):
        b1[i]=b1[i]^b2[i]
    return bytes(bytearray(b1))
key=b"1145141919810aaa"
iv=b"qweasdzxcrtyfghv"
data=[182,198,38,90,48,141,222,167,61,118,110,95,29,98,233,182,148,116,9,38,247,87,237,211,150,127,169,80,74,201,93,71]
data=bytes(bytearray(data))
keyarray=[]
ivarray=[]
keyarray.append(key)
ivarray.append(iv)
for i in range(16):
    key=bytesxor(key, iv)
    key=MixColumns(key)
    iv=bytesxor(key, iv)
    keyarray.append(key)
    ivarray.append(iv)
keyarray.reverse()
ivarray.reverse()
for i in range(len(keyarray)):
    key=keyarray[i]
    iv=ivarray[i]
    aes=AES.new(key,AES.MODE_CBC,iv)
    data=aes.decrypt(data)

print(data)