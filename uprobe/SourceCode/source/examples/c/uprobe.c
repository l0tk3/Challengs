// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"
#define DELTA 0x9e3779b9
// unsigned char k[17]="it1sn0tthek3yyyy";
unsigned char k[16]={0x1e,0x1c,0x54,0x1,0xb,0x59,0x7,0,0,0,0,0x56,0,0,0,0};
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return 0;
	// return vfprintf(stderr, format, args);
}

/* Find process's base load address. We use /proc/self/maps for that,
 * searching for the first executable (r-xp) memory mapping:
 *
 * 5574fd254000-5574fd258000 r-xp 00002000 fd:01 668759                     /usr/bin/cat
 * ^^^^^^^^^^^^                   ^^^^^^^^
 *
 * Subtracting that region's offset (4th column) from its absolute start
 * memory address (1st column) gives us the process's base load address.
 */
static long get_base_addr() {
	size_t start, offset;
	char buf[256];
	FILE *f;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%zx-%*x %s %zx %*[^\n]\n", &start, buf, &offset) == 3) {
		if (strcmp(buf, "r-xp") == 0) {
			fclose(f);
			return start - offset;
		}
	}

	fclose(f);
	return -1;
}

/* It's a global function to make sure compiler doesn't inline it. */
int uprobed_function(unsigned int value1,unsigned int value2,unsigned int value3,unsigned int value4,unsigned int length)/* uprobe_function(unsigned int* v,unsigned int length) <-xxtea length=16 unsigned char key[17]="it1sn0tthek3yyyy"*/
{	
	unsigned int v[4]={value1,value2,value3,value4};
	if(length!=16) return 0;
	unsigned int n=4;							 
	unsigned int y, z, sum;
    unsigned p, rounds, e;
	unsigned int *key=(unsigned int*)k;
      /* Coding Part */
    rounds = 6 + 52/n;
    sum = 0;
    z = v[n-1];
    do
    {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (p=0; p<n-1; p++)
        {
            y = v[p+1];
            z = v[p] += (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)));
        }
        y = v[0];
        z = v[n-1] += (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)));
    }
    while (--rounds);
	if((v[0]==0x3b466a30) && (v[1]==0x6212aea8) && (v[2]=0x2ff25334) && (v[3]==0x4f88a242)){
		return 1;
	}
	else return 0;

}
void genkey(){
	for(int i=0x65;i<0x80;i++){
    switch (i)
    {
    case 0x77:
        k[0]^=i;
        break;
    case 0x68:
        k[1]^=i;
        k[8]^=i;
        break;   
    case 0x65:
        k[2]^=i;
        k[4]^=i;
        k[9]^=i;
        k[0xb]^=i;
        break; 
    case 0x72:
        k[3]^=i;
        break; 
    case 0x69:
        k[5]^=i;
        break;
    case 0x73:
        k[6]^=i;
        break;   
    case 0x74:
        k[7]^=i;
        break; 
    case 0x6b:
        k[0xa]^=i;
        break; 
    case 0x79:
        k[0xc]^=i;
        k[0xd]^=i;
        k[0xe]^=i;
        k[0xf]^=i;
        break;
    default:
        break;
    }
}
} /* 加密密钥的全局变量，此函数用来异或解密密钥 异或的key="whereisthekeyyyy" */
int main(int argc, char **argv)/* 去掉log 读取输入 */
{
	struct uprobe_bpf *skel;
	long base_addr, uprobe_offset;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "try sudo?\n");
		return 1;
	}

	base_addr = get_base_addr();
	if (base_addr < 0) {
		fprintf(stderr, "Failed to determine process's load address\n");
		err = base_addr;
		goto cleanup;
	}

	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. This offset is relateve to the process's base load address. So
	 * easy way to do this is to take an absolute address of the desired
	 * function and substract base load address from it.  If we were to
	 * parse ELF to calculate this function, we'd need to add .text
	 * section offset and function's offset within .text ELF section.
	 */
	uprobe_offset = (long)&uprobed_function - base_addr;

	/* Attach tracepoint handler */
	skel->links.uprobe = bpf_program__attach_uprobe(skel->progs.uprobe,
							false /* not uretprobe */,
							0 /* self pid */,
							"/proc/self/exe",
							uprobe_offset);
	if (!skel->links.uprobe) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	skel->links.uretprobe = bpf_program__attach_uprobe(skel->progs.uretprobe,
							   true /* uretprobe */,
							   -1 /* any pid */,
							   "/proc/self/exe",
							   uprobe_offset);
	if (!skel->links.uretprobe) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	// printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	//        "to see output of the BPF programs.\n");

	/* trigger our BPF programs */
	genkey();
	// unsigned char testvalue[17]="bz{BV1FX4y1g7u8}";
	unsigned char value[30];
	puts("input your lucky words:");
	unsigned int len=read(0,value,30);
	value[len-1]=0;
	len=len-1; //去掉回车
	int ret=uprobed_function(((unsigned int*)value)[0],((unsigned int*)value)[1],((unsigned int*)value)[2],((unsigned int*)value)[3],len);
	if(ret!=1){
		puts("wrong answer");
	}
	else{
		puts("congratulation?");
	}
// bz{BV1FX4y1g7u8}
cleanup:
	uprobe_bpf__destroy(skel);
	return -err;
}
