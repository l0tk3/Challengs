package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"letsGO/interal/handle_enc"
	"letsGO/interal/handle_tcp"
	"net"
)

func handle_input(input []byte) {
	final_data := []byte{6, 116, 180, 226, 73, 13, 145, 54, 149, 157, 122, 254, 199, 169, 164, 161, 240, 246, 3, 86, 144, 250, 26, 50, 167, 109, 57, 238}
	final_data_length := len(final_data)
	tcp_pack := handle_tcp.Unpack_tcp_reply(input)
	checksum_recv := tcp_pack.ChkSum
	tcp_pack.ChkSum = uint16(0)
	flag := tcp_pack.Flags
	size := (flag >> 12) * 4 //头部的长度
	option := input[20:size]
	length := len(input)
	raw_data := input[size : length-1]
	raw_data_length := len(raw_data)
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, tcp_pack)
	binary.Write(&buffer, binary.BigEndian, option)
	binary.Write(&buffer, binary.BigEndian, raw_data)
	f_raw := buffer.Bytes()
	laddr := "127.0.0.1"
	raddr := "127.0.0.1"
	//checksum里的长度是全部的长度
	checksum_calculate := handle_tcp.Calculate_checksum(handle_tcp.Pack_tcp_pseudo_header(f_raw, handle_tcp.Ip2int(laddr), handle_tcp.Ip2int(raddr)))
	if checksum_calculate != checksum_recv {
		panic("checksum err!")
	}
	if tcp_pack.SrcPort != 99 || tcp_pack.DstPort != 233 {
		panic("port err!")
	}
	if tcp_pack.SeqNum != 0xdeadbeef || tcp_pack.AckNum != 0 {
		panic("num err!")
	}
	if ((tcp_pack.Flags << 10) >> 10) != 0x2 {
		panic("flag err!")
	}
	if raw_data_length < 4 {
		panic("data too short!")
	}
	sbox := make([]byte, 256)
	key := raw_data[raw_data_length-3:]
	p_text := raw_data
	for _, e := range p_text {
		if e < 32 || e > 126 {
			panic("?")
		}
	}
	// fmt.Println("received checksum: ", checksum_recv)
	// fmt.Println("calculate checksum: ", checksum_calculate)
	// fmt.Println("raw data: ", raw_data)
	// fmt.Println("key:", key)
	// fmt.Println("p_text:", p_text)
	handle_enc.Enc1(&sbox, &key, len(key))
	handle_enc.Enc2(&sbox, &p_text, len(p_text))
	// fmt.Println("after encrypt:", p_text)
	if len(p_text) != final_data_length {
		panic("[*] length err!")
	}
	for i := 0; i < final_data_length; i++ {
		if p_text[i] != final_data[i] {
			panic("You failed!")
		}
	}
}

func handle_connection(conn net.Conn) {
	br := bufio.NewReader(conn)
	for {
		data, err := br.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		// fmt.Println(data)
		handle_input(data)
		fmt.Fprintf(conn, "You win\n")
	}
	conn.Close()
}

func main() {
	ln, err := net.Listen("tcp", ":8092")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go handle_connection(conn)
	}

}
