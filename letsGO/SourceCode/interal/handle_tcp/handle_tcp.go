package handle_tcp

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

type TCPPack struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNum        uint32
	AckNum        uint32
	Flags         uint16
	Window        uint16
	ChkSum        uint16
	UrgentPointer uint16
}

func Unpack_tcp_reply(tcpBytes []byte) TCPPack {
	var tcp_pack TCPPack
	buffer := bytes.NewBuffer(tcpBytes)
	binary.Read(buffer, binary.BigEndian, &tcp_pack)
	return tcp_pack
}

func bytes_sum(b []byte) int {
	var sum int
	for _, value := range b {
		sum += int(value)
	}
	return sum
}

func Pack_tcp_pseudo_header(data []byte, laddr, raddr int32) []byte {
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, laddr)
	binary.Write(&buffer, binary.BigEndian, raddr)
	binary.Write(&buffer, binary.BigEndian, []byte{0, 6, 0}) // zeros、protocol
	binary.Write(&buffer, binary.BigEndian, byte(len(data)))
	pseudoHeader := buffer.Bytes()
	length := len(pseudoHeader) + len(data)
	if length%2 != 0 { // 不是2的倍数
		length++
	}
	target := make([]byte, 0, length)
	target = append(target, pseudoHeader...)
	target = append(target, data...)
	return target
}

func Calculate_checksum(pack []byte) uint16 {
	var high []byte
	var low []byte
	for idx, value := range pack {
		if idx&1 == 1 {
			low = append(low, value)
		} else {
			high = append(high, value)
		}
	}
	checksum := ((bytes_sum(high) << 8) + bytes_sum(low))

	for rest := checksum >> 16; rest != 0; {
		checksum = checksum&0xffff + rest
		rest = checksum >> 16
	}

	final_checksum := uint16(^checksum & 0xffff)
	return final_checksum
}

func Ip2int(ip string) int32 {
	tmp := strings.Split(ip, ".")
	var sum int32
	for idx, value := range tmp {
		num, _ := strconv.Atoi(value)
		sum += int32(num) << ((3 - idx) * 8)
	}

	return sum
}

func Int2ip(ip int32) string {
	part1 := strconv.Itoa(int(ip) & 0xff)
	part2 := strconv.Itoa((int(ip) & 0xff00) >> 8)
	part3 := strconv.Itoa((int(ip) & 0xff0000) >> 16)
	part4 := strconv.Itoa((int(ip) & 0xff000000) >> 24)
	ret_value := part4 + "." + part3 + "." + part2 + "." + part1
	return ret_value
}
