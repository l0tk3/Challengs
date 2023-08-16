#include <iostream>
#include <string>
#include <cstring>
#include <openssl/aes.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#define DELTA 0x9e3779b9
using namespace std;
unsigned char k[17]="itisabeautyfulda";
string aes_256_cbc_encode(const string& password, const string& data,unsigned char* iv){
    
	AES_KEY aes_key;

	if (AES_set_encrypt_key((const unsigned char*)password.c_str(), password.length() * 8, &aes_key) < 0)
	{
		return "";
	}
	string strRet;
	string data_bak = data;
	unsigned int data_length = data_bak.length();

	int padding = 0;
	if (data_bak.length() % (AES_BLOCK_SIZE) > 0)
	{
		padding = AES_BLOCK_SIZE - data_bak.length() % (AES_BLOCK_SIZE);
	}
	data_length += padding;
	while (padding > 0)
	{
		data_bak += '\0';
		padding--;
	}

	for (unsigned int i = 0; i < data_length / (AES_BLOCK_SIZE); i++)
	{
		string str16 = data_bak.substr(i*AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		unsigned char out[AES_BLOCK_SIZE];
		memset(out, 0, AES_BLOCK_SIZE);
		AES_cbc_encrypt((const unsigned char*)str16.c_str(), out, AES_BLOCK_SIZE, &aes_key, iv, AES_ENCRYPT);
		strRet += string((const char*)out, AES_BLOCK_SIZE);
	}
	return strRet;
}
uint32_t * btea(uint32_t *v, int n)
{
    if(n==0){
        throw "[1]Fatal error!";
    }
    unsigned char *value=(unsigned char*)v;
    if(strlen((const char*)value)<n*4){
        uint32_t *v1=(uint32_t*)malloc(n*4);
        memset(v1,0,n*4);
        memcpy(v1,v,strlen((const char*)value));
        v=v1;
    }
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    unsigned int *key=(unsigned int *)k;
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
    return v;
}
string str_to_bin(char *str)
{
    string res;
    char len = strlen(str);
    // printf("len:%d\n",len);
    char tmp;
    for(int i=0;i<len;i++){
        tmp = str[i];
        for(int i=0;i<8;i++){
            if(tmp & 0x80) { //1000,0000
                res+="1";
            }
            else{
                res+="0";
            }
            tmp = tmp << 1 ;
        }
    }
    return res;
}
int main() {
    string key="12345678901234561234567890123456";
    unsigned char msgkey[16]="114514191981011";
    unsigned char iv[AES_BLOCK_SIZE] = { '0','0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0' };
    uint64_t intres[]={0x840aff76f4f1ccbe,0x1b083d71a351ac45,0x69cf04c27d1399da,0xb6be2817d3d5ef90,0x7f3abd64feb9c098,0x840aff76f4f1cdef,0x840aff76f4f1ccbf,0x3e73e9fd8980088f,0x172027bb1c2bc602,0x8f90bc5d9eb292df,0xf1b278478fa40bd9,0xcef7e011f14c1f16,0xb624a77659d338ee,0xdba645049979e494,0x733f2a4fc68a41d8,0xaa1af3f874687d6f,0xe94dd34d794eb328,0x67660c4d5c776b7d,0x62cc0bc98430941d,0x8e5b2123b36eaf6d,0x8c278cd7cdb53f46,0x4a72cb62b39ca3f7,0x8119d366e317e644,0xc79d8779fdbea99a,0x64d46dd5c7cd2ef5,0x8c0e6750c44282b1,0xe0f88a1cc54df68a,0xb69bd60f0d5ac4d9};
    int num;
    string input;
    cout << "input a string:" << endl;
    cin >> input;
    cout <<"input a number:" <<endl;
    cin >> num;
    string hf_input;
    hf_input=str_to_bin((char *)input.c_str());
    pid_t child_pid=fork();
    if(child_pid!=0){
        try
        {
            unsigned char *c_input=(unsigned char*)hf_input.c_str();
            uint32_t *v=(uint32_t*)c_input;
            int status;
            waitpid(child_pid,&status,0);
            v=btea(v,num);//假flag flag{never_gonna_give_you_up}
            ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_EXITKILL);
            if(hf_input.length()==232){
                uint32_t tmp[58]={0x6ac68723,0xbc7123a7,0x64f3d87d,0x3e8c216,0x737dd747,0xb010868f,0x33030511,0x83453d34,0x508e9921,0x2bfa017a,0x824aba3e,0xb426bc88,0xe2b6bfbc,0x10e2caf7,0x4fc41d21,0x67c588f0,0xdbd13516,0x67cb17db,0x54e01fbd,0xc5b682d5,0xdccbe585,0xc51ec321,0xbb7cc296,0x158cb0e8,0x6946bfd7,0xa70879ac,0x6b1b0108,0x6996f44e,0x37b754e7,0xb3a7607,0x62c425d4,0x34f5f409,0xc2c0d008,0xe8ed6971,0xa7c57884,0x8563eaa5,0x825dea33,0xb0605bb3,0x63319346,0x2177147b,0x689899a1,0x7ba4a9cd,0x803c46d2,0xcffedda6,0xefb452d4,0x74e3dde,0xfb146cf2,0x1c01440b,0xd3f5bccc,0x6f8a379e,0x7e46972d,0x64749b9b,0xeceacb7e,0x780fe61b,0xbcaf308e,0x641f40b,0x8f0897bd,0xd5b3c7db};
                for(int i=0;i<58;i++){
                    if(v[i]!=tmp[i]){
                        printf("index:%d\ntmp:%#x\nv:%#x\n",i,tmp[i],v[i]);
                        puts(":(");
                        exit(0);
                    }
                }
                puts(":)");
                exit(0);
            }
            else
            puts(":(");
            exit(0);
        }
        catch(...)
        {
            ptrace(PTRACE_POKEDATA, child_pid, &iv, 0x1145141919810000);
            ptrace(PTRACE_POKEDATA, child_pid, &key[0], 0x6572617364726962);
            ptrace(PTRACE_POKEDATA, child_pid, &intres[0], 0x5e873cdc9ebe8011);
            ptrace(PTRACE_POKEDATA, child_pid, &intres[5], 0xbc74073357e6a5db);
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            return 0;
        }
    }
    else{
        ptrace(PTRACE_TRACEME,0,0,0);
        raise(SIGCHLD);
    }
    // hf_input="01100110011011000110000101100111011110110110001100110000011011100100011101110010011000010101010001110101001100010110000101110100011010010011000001101110011100110101111101110100011011110101111101011001001100000111010101111101";
    string aes_hf_input=aes_256_cbc_encode(key,hf_input,iv);
    uint64_t *tmp=(uint64_t*)aes_hf_input.c_str();
    // for(int i=0;i<14;i++){
    //     for(int j=0;j<16;j++){
    //         printf("\\x%02x",((unsigned char *)tmp)[i*16+j]);
    //     }
    //     printf("\n");
    // }
    unsigned char msg1[]={0x72,0x5e,0x5a,0x52,0x43,0x55,0x45,0x4c,0x5d,0x58,0x4c,0x58,0x5f,0x5f,0x10};
    unsigned char msg2[]={0x57,0x50,0x5d,0x59,0x55};
    for(int i=0;i<28;i++){
        if(tmp[i]!=intres[i]){
            // printf("tmp[%d]:%#x\nintres[%d]:%#x\n",i,tmp[i],i,intres[i]);
            for(int o=0;o<4;o++){
                printf("%c",msgkey[o]^msg2[o]);
            }
            cout << endl;
            exit(0);
        }
    }
    for(int i=0;i<14;i++){
        printf("%c",msgkey[i]^msg1[i]);
    }
    cout << endl;
    return 0;
}
// flag{c0nGraTu1ati0ns_to_Y0u}