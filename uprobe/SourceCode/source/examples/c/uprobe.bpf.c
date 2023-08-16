// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdio.h>
#include <stdlib.h>
// 全局变量换成加密之后的sbox和rcon 异或key: "bengbengbengbeng"
// unsigned char s_box[256] = {
// 	// 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
// 	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
// 	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
// 	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
// 	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
// 	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
// 	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
// 	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
// 	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
// 	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
// 	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
// 	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
// 	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
// 	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
// 	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
// 	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
// 	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};// f
unsigned char s[256]={0x1,0x19,0x19,0x1c,0x90,0xa,0x1,0xa2,0x52,0x6e,0x9,0x4c,0x9c,0xb2,0xc5,0x11,0xa8,0xe7,0xa7,0x1a,0x98,0x38,0x29,0x97,0xcf,0xbb,0xcc,0xc8,0xfe,0xc1,0x1c,0xa7,0xd5,0x98,0xfd,0x41,0x54,0x5e,0x99,0xab,0x56,0xca,0x8b,0x96,0x13,0xbd,0x5f,0x72,0x66,0xa2,0x4d,0xa4,0x7a,0xf7,0x6b,0xfd,0x65,0x7d,0xee,0x85,0x89,0x42,0xdc,0x12,0x6b,0xe6,0x42,0x7d,0x79,0xf,0x34,0xc7,0x30,0x54,0xb8,0xd4,0x4b,0x86,0x41,0xe3,0x31,0xb4,0x6e,0x8a,0x42,0x9d,0xdf,0x3c,0x8,0xa4,0xd0,0x5e,0x28,0x29,0x36,0xa8,0xb2,0x8a,0xc4,0x9c,0x21,0x2c,0x5d,0xe2,0x27,0x96,0x6c,0x18,0x32,0x59,0xf1,0xcf,0x33,0xc6,0x2e,0xe8,0xf0,0xfc,0x56,0x92,0xde,0xd9,0xb4,0x46,0x72,0x9a,0x9d,0xb5,0xaf,0x69,0x7d,0x8b,0x3d,0xf6,0x2a,0x70,0xa6,0xc8,0x10,0x5a,0x6,0x38,0x77,0x14,0x2,0xe4,0x21,0xbb,0x40,0x4b,0xfe,0xef,0x24,0x81,0xd6,0x73,0xbc,0x3b,0x65,0xbc,0x82,0x57,0x54,0x6d,0x2b,0x67,0x4a,0x3b,0xa0,0xbc,0xc2,0x5,0xf3,0xf0,0x8a,0x1e,0x85,0xad,0x59,0xa,0xef,0xb4,0x20,0xce,0xe,0x39,0x9a,0x8d,0x7,0x1f,0xc0,0x6f,0xd8,0x1d,0x4b,0x49,0x7e,0xc7,0xda,0xa1,0x8a,0xb2,0x1a,0x78,0x29,0xd8,0xe5,0xed,0x12,0x5b,0xdb,0x1,0x2a,0x62,0x98,0x69,0x3,0x5a,0x39,0xde,0xe4,0xa4,0x73,0xf9,0x83,0x9d,0xf6,0x76,0xb,0xb8,0xe0,0xf3,0xf9,0x71,0xe9,0x8e,0xac,0x30,0x46,0xb8,0xee,0xc4,0xe7,0x6a,0xdd,0x87,0x2c,0xf,0x23,0xf6,0x43,0x68,0xd2,0x31,0xd5,0x71};
// unsigned int rcon[10]={
// 	0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
unsigned int r[10]={0x63,0x67,0x6a,0x6f,0x72,0x41,0x2e,0xe7,0x79,0x59};
unsigned char key[16]={0,0x1f,0x15,0x25,0x34,0x50,0x28,0x3f,0x56,0x16,0x5f,0,0x55,0x10,0x56,0x1a};
unsigned char exkey[44*4]={0};
unsigned char k[17]="bengbangbongbeng";
void func2(unsigned char *state);
void loop(unsigned char *array,unsigned int step);
void func3(unsigned char *state);
unsigned char func5(unsigned char a);
void func4(unsigned char *state);
void func1(unsigned char *state,unsigned char *key);
unsigned int exFunc(unsigned int a,int round);
void Gt(); // 异或解密s_box、rcon和key 
void func2(unsigned char *state){
    for(int i=0;i<16;i++){
		state[i]=s[state[i]];
	}
}
void loop(unsigned char *array,unsigned int step){
	unsigned char tmp[4];
	for(int i=0;i<4;i++){
		tmp[i]=array[i];
	}
	unsigned int index=step%4;
	for(int i=0;i<4;i++){
		array[i]=tmp[index];
		index++;
		index=index%4;
	}
}
void func3(unsigned char *state){
	unsigned char row2[4],row3[4],row4[4];
	for(int i=0;i<4;i++){
		row2[i]=state[1+4*i];
		row3[i]=state[2+4*i];
		row4[i]=state[3+4*i];
	}
	loop(row2,1);
	loop(row3,2);
	loop(row4,3);
	for(int i=0;i<4;i++){
		state[1+4*i]=row2[i];
		state[2+4*i]=row3[i];
		state[3+4*i]=row4[i];
	}
}
unsigned char func5(unsigned char a){
	unsigned char temp = a << 1;
	if ((a >> 7) & 0x01)
		temp = temp ^ 27;
	return temp;
}
void func4(unsigned char *state){
	unsigned char s0,s1,s2,s3;
	for(int i=0;i<4;i++){
		s0=state[4*i];
		s1=state[1+4*i];
		s2=state[2+4*i];
		s3=state[3+4*i];
		state[4*i]=func5(s0) ^ (func5(s1)^s1) ^ s2 ^ s3;
		state[1+4*i]=s0 ^ func5(s1) ^ (func5(s2)^s2) ^ s3;
		state[2+4*i]=s0 ^ s1 ^ func5(s2) ^ (func5(s3)^s3);
		state[3+4*i]=(func5(s0)^s0) ^ s1 ^ s2 ^ func5(s3);
	}
}
void func1(unsigned char *state,unsigned char *key){
	for(int i=0;i<16;i++){
		state[i]=state[i]^key[i];
	}
}
unsigned int exFunc(unsigned int a,int round){
	unsigned char *b=(unsigned char*)&a;
	loop(b,1);
	for(int i=0;i<4;i++){
		b[i]=s[b[i]];
	}
	a=a^r[round];
	return a;
}
void Gt(){
	for(int i=0;i<256;i++){
    	s[i]=s[i]^k[i%16];
	}
	for(int i=0;i<10;i++){
		r[i]=r[i]^k[i];
	}
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/func")
int BPF_KPROBE(uprobe,unsigned int value1,unsigned int value2,unsigned int value3,unsigned int value4,unsigned int length) //好了
{
	// iamth3_rea1_f1ag
	// unsigned char key[17]="bz{BV1FX4y1g7u8}";
	unsigned int v[4]={value1,value2,value3,value4};
	unsigned char *state=(unsigned char*)v;	
	Gt();
	for(int i=0;i<16;i++){
		key[i]=key[i]^k[i];
	}
	for(int i=0;i<16;i++){
		exkey[i]=key[i];
	}
	unsigned int *dwkey=(unsigned int*)exkey;
	for(int i=0;i<10;i++){
		dwkey[4+i*4]=dwkey[(4+i*4)-4]^exFunc(dwkey[(4+i*4)-1],i);
		dwkey[5+i*4]=dwkey[(5+i*4)-4]^dwkey[(5+i*4)-1];
		dwkey[6+i*4]=dwkey[(6+i*4)-4]^dwkey[(6+i*4)-1];
		dwkey[7+i*4]=dwkey[(7+i*4)-4]^dwkey[(7+i*4)-1];
	}
	func1((unsigned char*)state,key);
	for(int i=0;i<9;i++){
		func2((unsigned char*)state);
		func3((unsigned char*)state);
		func4((unsigned char*)state);
		func1((unsigned char*)state,&exkey[16*(i+1)]);
	}
	func2((unsigned char*)state);
	func3((unsigned char*)state);
	func1((unsigned char*)state,&exkey[16*10]);
	// bpf_printk("%x %x %x %x",v[0],v[1],v[2],v[3]);
	if((v[0]==0xa26093e1)&&(v[1]==0x77f489f3)&&(v[2]==0x71c06cdf)&&(v[3]==0xff546f95)){
		bpf_printk("success!");
	}
	else{
		bpf_printk("wrong answer!");
	}
	return 0;
}

SEC("uretprobe/func")
int BPF_KRETPROBE(uretprobe, int ret)
{
	return 0;
}
