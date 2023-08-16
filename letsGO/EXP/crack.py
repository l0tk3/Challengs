from Crypto.Cipher import ARC4

enc = [6, 116, 180, 226, 73, 13, 145, 54, 149, 157, 122, 254, 199, 169, 164, 161, 240, 246, 3, 86, 144, 250, 26, 50, 167, 109, 57, 238]
key = 0
for i in range(16777215):
    key = i.to_bytes(3, "little")
    rc4 = ARC4.new(key)
    m = rc4.decrypt(bytes(enc))
    # print(key)
    if m[-3:] == key:
        print(b"target is : "+key)
        print(b"after decrypt: "+m)