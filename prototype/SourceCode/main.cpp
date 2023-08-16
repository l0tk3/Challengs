#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <sys/mman.h>
#include "pkg.loginfo.pb.h"
#include "pkg.loginfo.pb.cc"
#define SERV_PORT 8848
#define SIZE 100
using namespace std;
unsigned char s_box[]={0xd,0x1d,0xe,0x15,0x93,0x12,0x1,0xa4,0x49,0x6f,0x6,0x52,0x90,0xb6,0xd2,0x18,0xa4,0xe3,0xb0,0x13,0x9b,0x20,0x29,0x91,0xd4,0xba,0xc3,0xd6,0xf2,0xc5,0xb,0xae,0xd9,0x9c,0xea,0x48,0x57,0x46,0x99,0xad,0x4d,0xcb,0x84,0x88,0x1f,0xb9,0x48,0x7b,0x6a,0xa6,0x5a,0xad,0x79,0xef,0x6b,0xfb,0x7e,0x7c,0xe1,0x9b,0x85,0x46,0xcb,0x1b,0x67,0xe2,0x55,0x74,0x7a,0x17,0x34,0xc1,0x2b,0x55,0xb7,0xca,0x47,0x82,0x56,0xea,0x3d,0xb0,0x79,0x83,0x41,0x85,0xdf,0x3a,0x13,0xa5,0xdf,0x40,0x24,0x2d,0x21,0xa1,0xbe,0x8e,0xd3,0x95,0x22,0x34,0x5d,0xe4,0x3c,0x97,0x63,0x6,0x3e,0x5d,0xe6,0xc6,0x3f,0xc2,0x39,0xe1,0xf3,0xe4,0x56,0x94,0xc5,0xd8,0xbb,0x58,0x7e,0x9e,0x8a,0xbc,0xa3,0x6d,0x6a,0x82,0x3e,0xee,0x2a,0x76,0xbd,0xc9,0x1f,0x44,0xa,0x3c,0x60,0x1d,0xe,0xe0,0x36,0xb2,0x43,0x53,0xfe,0xe9,0x3f,0x80,0xd9,0x6d,0xb0,0x3f,0x72,0xb5,0x8e,0x53,0x43,0x64,0x28,0x7f,0x4a,0x3d,0xbb,0xbd,0xcd,0x1b,0xff,0xf4,0x9d,0x17,0x89,0xa9,0x4e,0x3,0xec,0xac,0x20,0xc8,0x15,0x38,0x95,0x93,0xb,0x1b,0xd7,0x66,0xd4,0x19,0x5c,0x40,0x7d,0xdf,0xda,0xa7,0x91,0xb3,0x15,0x66,0x25,0xdc,0xf2,0xe4,0x1e,0x5f,0xcc,0x8,0x29,0x7a,0x98,0x6f,0x18,0x5b,0x36,0xc0,0xe8,0xa0,0x64,0xf0,0x8f,0x99,0xe1,0x7f,0x8,0xa0,0xe0,0xf5,0xe2,0x70,0xe6,0x90,0xa0,0x34,0x51,0xb1,0xe2,0xc0,0xf0,0x63,0xde,0x9f,0x2c,0x9,0x38,0xf7,0x4c,0x76,0xde,0x35,0xc2,0x78};
unsigned int rcon[10]={0x6f,0x63,0x7d,0x66,0x71,0x59,0x2e,0xe1,0x62,0x58};
// unsigned char akey[]="1145141919810aaa";
unsigned char akey[]={0x5f,0x50,0x4d,0x5b,0x50,0x4d,0x5f,0x58,0x48,0x57,0x59,0x48,0x5e,0x0,0x18,0xf};
// unsigned char aiv[]="qweasdzxcrtyfghv";
unsigned char aiv[]={0x1f,0x16,0x1c,0xf,0x12,0x1d,0x14,0x19,0x1a,0x1c,0x15,0x0,0x8,0x6,0x11,0x18};
unsigned char exkey[44*4];
bool isemailvalid(string email);
void main_logic(char *data);
void SubBytes(unsigned char *state);
void leftloop(unsigned char *array,int step);
void ShiftRows(unsigned char *state);
unsigned char xtime(unsigned char a);
void MixColumns(unsigned char *state);
void AddRoundkey(unsigned char *state,unsigned char *key);
unsigned int exFunc(unsigned int a,int round);
void KeyExpansion(unsigned char *key,unsigned char *exkey);
void xoriv(unsigned char *iv,unsigned char *state);
void gentable();
void AES_CBC(unsigned char *key,unsigned char *iv,unsigned char *state,int length);
void True_judge(string str);
int main(){
    struct sockaddr_in servaddr,ciladdr;
    socklen_t ciladdr_len;
    int listenfd,connfd;
    char buf[SIZE];
    listenfd=socket(AF_INET,SOCK_STREAM,0);
    bzero(&servaddr,sizeof(servaddr));
    servaddr.sin_family=AF_INET;
    servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
    servaddr.sin_port=htons(SERV_PORT);
    bind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
    listen(listenfd,20);
    printf("waiting......\n");
    ciladdr_len=sizeof(ciladdr);
    connfd=accept(listenfd,(struct sockaddr*)&ciladdr,&ciladdr_len);
    memset(buf,0,sizeof(buf));
    int n=read(connfd,buf,SIZE);
    // cout << n <<endl;
    while(1){
        if(n!=0){
            main_logic(buf);
        }
        else{
            printf("closed..\n");
            break;
        }
        memset(buf,0,sizeof(buf));
        n=read(connfd,buf,SIZE);
    }
    close(connfd);
}
bool isemailvalid(string email){
    string t1="@";
    string t2=".";
    string t3="114";
    string::size_type idx1=email.find(t1);
    string::size_type idx2=email.find(t2);
    string::size_type idx3=email.find(t3);
    if(idx1==string::npos){
        if(idx2==string::npos){
            if(idx3!=string::npos){
                throw "something wrong";
            }
        }
        return false;
    }
    if(idx2!=string::npos){
        return true;
    }
    return false;
}
void main_logic(char *data){
    string str=data;
    // cout << str << endl;
    pkg::loginfo msg;
    if(!msg.ParseFromString(str)){
        cerr << "input format error!" << endl;
        return ;
    }
    try{
        if(!isemailvalid(msg.email())){
            cerr << "email format error!" <<endl;
            return;
        }
        string name=msg.name();
        string passwd=msg.passwd();
        name=name+passwd;
        const char *finaldata=name.c_str();
        unsigned char md5[MD5_DIGEST_LENGTH]; //{0xfb,0xa8,0x67,0x33,0xfa,0xa1,0x7f,0xa7,0xe1,0xe9,0x1f,0x16,0x1,0xd4,0x11,0x12}
        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx,finaldata,strlen(finaldata));
        MD5_Final(md5,&ctx);
        unsigned char ans[]={0xfb,0xa8,0x67,0x33,0xfa,0xa1,0x7f,0xa7,0xe1,0xe9,0x1f,0x16,0x1,0xd4,0x11,0x12};
        for(int i=0;i<16;i++){
            if(md5[i]!=ans[i]){
                cerr << "faild!" <<endl;
                return;
            }
        }
        cout << "congratulations!"<<endl;
    }
    catch(...){
        string name=msg.name();
        string passwd=msg.passwd();
        name=name+passwd;
        // True_judge(name);
        unsigned char *ptr=(unsigned char *)&True_judge;
        mprotect((void*)((unsigned long)&True_judge&(~0xffful)),0x1000,7);
        for(int i=0;i<0x3bc;i++){
            ptr[i]^=(i%256);
        }
        mprotect((void*)((unsigned long)&True_judge&(~0xffful)),0x1000,5);
        // puts("hha");
        True_judge(name);
    }
}
void SubBytes(unsigned char *state){
    for(int i=0;i<16;i++){
		state[i]=s_box[state[i]];
	}
}
void leftloop(unsigned char *array,int step){
	unsigned char tmp[4];
	for(int i=0;i<4;i++){
		tmp[i]=array[i];
	}
	int index=step%4;
	for(int i=0;i<4;i++){
		array[i]=tmp[index];
		index++;
		index=index%4;
	}
}
void ShiftRows(unsigned char *state){
	unsigned char row2[4],row3[4],row4[4];
	for(int i=0;i<4;i++){
		row2[i]=state[1+4*i];
		row3[i]=state[2+4*i];
		row4[i]=state[3+4*i];
	}
	leftloop(row2,1);
	leftloop(row3,2);
	leftloop(row4,3);
	for(int i=0;i<4;i++){
		state[1+4*i]=row2[i];
		state[2+4*i]=row3[i];
		state[3+4*i]=row4[i];
	}
}
unsigned char xtime(unsigned char a){
	unsigned char temp = a << 1;
    // printf("%d\n",temp);
	if ((a >> 7) & 0x01)
		temp = temp ^ 27;
    // printf("%d\n",temp);
    // printf("--------\n");
	return temp;
}
void MixColumns(unsigned char *state){
	unsigned char s0,s1,s2,s3;
	for(int i=0;i<4;i++){
		s0=state[4*i];
		s1=state[1+4*i];
		s2=state[2+4*i];
		s3=state[3+4*i];
		state[4*i]=xtime(s0) ^ (xtime(s1)^s1) ^ s2 ^ s3;
		state[1+4*i]=s0 ^ xtime(s1) ^ (xtime(s2)^s2) ^ s3;
		state[2+4*i]=s0 ^ s1 ^ xtime(s2) ^ (xtime(s3)^s3);
		state[3+4*i]=(xtime(s0)^s0) ^ s1 ^ s2 ^ xtime(s3);
	}
}
void AddRoundkey(unsigned char *state,unsigned char *key){
	for(int i=0;i<16;i++){
		state[i]=state[i]^key[i];
	}
}
unsigned int exFunc(unsigned int a,int round){
	unsigned char *b=(unsigned char*)&a;
	leftloop(b,1);
	for(int i=0;i<4;i++){
		b[i]=s_box[b[i]];
	}
	a=a^rcon[round];
	return a;
}
void KeyExpansion(unsigned char *key,unsigned char *exkey){
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
}
void gentable(){
	unsigned char xorkey[17]="naynaynaynaynayn";
	for(int i=0;i<256;i++){
    	s_box[i]=s_box[i]^xorkey[i%16];
	}
	for(int i=0;i<10;i++){
		rcon[i]=rcon[i]^xorkey[i];
	}
    for(int i=0;i<16;i++){
        akey[i]=akey[i]^xorkey[i];
        aiv[i]=aiv[i]^xorkey[i];
    }
}
void xoriv(unsigned char *iv,unsigned char *state){
    for(int i=0;i<16;i++){
        state[i]^=iv[i];
    }
}
void AES_CBC(unsigned char *key,unsigned char *iv,unsigned char *state,int length){ //0x138
        // int len=strlen((const char *)state);
        if(length%16!=0){
            printf("length error!!!");
            exit(0);
        }
        int part=length/16;
        KeyExpansion(key,exkey);
        for(int r=0;r<part;r++){
            xoriv(iv,state);
            AddRoundkey(state,key);
            for(int i=0;i<9;i++){
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundkey(state,&exkey[16*(i+1)]);
            }
            SubBytes(state);
            ShiftRows(state);
            AddRoundkey(state,&exkey[16*10]);
            iv=state;
            state=state+16;
        }

}
void True_judge(string str){ //0x3bc
    unsigned char *state=(unsigned char *)str.c_str();
    int length=strlen((const char *)state);
    int round=16;
    unsigned char s0,s1,s2,s3;
    gentable();
    do{
        AES_CBC(akey,aiv,state,length);
        for(int j=0;j<16;j++){
            akey[j]^=aiv[j];
        }
        for(int i=0;i<4;i++){
		s0=akey[4*i];
		s1=akey[1+4*i];
		s2=akey[2+4*i];
		s3=akey[3+4*i];
		akey[4*i]=xtime(s0) ^ (xtime(s1)^s1) ^ s2 ^ s3;
		akey[1+4*i]=s0 ^ xtime(s1) ^ (xtime(s2)^s2) ^ s3;
		akey[2+4*i]=s0 ^ s1 ^ xtime(s2) ^ (xtime(s3)^s3);
		akey[3+4*i]=(xtime(s0)^s0) ^ s1 ^ s2 ^ xtime(s3);
	}
        for(int j=0;j<16;j++){
            aiv[j]^=akey[j];
        }                 
        round-=1;
    }
    while(round);
    AES_CBC(akey,aiv,state,length);
    unsigned char res[]={182,198,38,90,48,141,222,167,61,118,110,95,29,98,233,182,148,116,9,38,247,87,237,211,150,127,169,80,74,201,93,71};
    int i=0;
    for(i=0;i<length;i++){
        if(state[i]!=res[i]){
            cerr <<"faild!!" <<endl;
            exit(1);
        }
    }
    if(i!=32){
        cerr <<"faild!!" <<endl;
        exit(1);
    }
    cout <<"congratulation!"<<endl;
}