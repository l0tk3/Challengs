import struct
def ip2int(ip):
    ip = ip.split('.')
    result = 0
    result = result + int(ip[3])
    result = result + (int(ip[2]) << 8)
    result = result + (int(ip[1]) << 16)
    result = result + (int(ip[0]) << 24)
    return result

def int2ip(i):
    i = hex(i)[2:]
    i = i.rjust(len(i) + (len(i) % 2), '0')
    result = ''
    result = result + str(int(i[:2], 16)) + '.'
    result = result + str(int(i[2:4], 16)) + '.'
    result = result + str(int(i[4:6], 16)) + '.'
    result = result + str(int(i[6:8], 16))
    return result

def pack_tcp_pseudo_header(data, laddr, raddr):
    pseudo = struct.pack(
        '!IIBBH',
        laddr,
        raddr,
        0,
        6,
        len(data)
    ) + data
    if len(pseudo)%2 !=0:
        pseudo += b'\x00'
    return pseudo
def calculate_checksum(tcp):
    highs = tcp[0::2]
    lows = tcp[1::2]
    checksum = ((sum(highs) << 8) + sum(lows))
    while True:
        carry = checksum >> 16
        if carry:
            checksum = (checksum & 0xffff) + carry
        else:
            break
    checksum = ~checksum & 0xffff
    return checksum
def pack_tcp_request(data):
    lport = 99
    rport = 233
    seqnum = 0xdeadbeef
    acknum = 0
    flag = 0x8002
    window = 0xffff
    checksum = 0
    urgentpointer = 0
    option = [0x02, 0x04, 0x05, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x00 ,0x00 ,0x00 ,0x00]
    tcp_pack = struct.pack(
        "!HHIIHHHH",
        lport,
        rport,
        seqnum,
        acknum,
        flag,
        window,
        checksum,
        urgentpointer
    ) + bytes(option)
    laddr = ip2int("127.0.0.1")
    raddr = ip2int("127.0.0.1")
    tcp_pack +=data
    checksum = calculate_checksum(pack_tcp_pseudo_header(tcp_pack,laddr,raddr))
    print(checksum)
    tcp_pack = struct.pack(
        "!HHIIHHHH",
        lport,
        rport,
        seqnum,
        acknum,
        flag,
        window,
        checksum,
        urgentpointer
    ) + bytes(option) + data
    return tcp_pack
if __name__ == "__main__":
    data = b"flag{Go_1an9_1s_n07_s0_Ha"
    key = b"rd}"
    payload = pack_tcp_request(data+key)
    print(payload)
    from pwn import *
    context.log_level = "debug"
    sh = remote("127.0.0.1", 8092)
    sh.sendline(payload)
    sh.interactive()