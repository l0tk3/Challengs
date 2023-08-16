#include <stdio.h>
#include <stdint.h>
#define DELTA 0x9e3779b9
unsigned char k[17]="itisabeautyfulda";
void btea(uint32_t *v, int n)
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    unsigned int *key=(unsigned int *)k;
    if (n > 1)            /* Coding Part */
    {
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
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52/n;
        sum = rounds*DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p=n-1; p>0; p--)
            {
                z = v[p-1];
                y = v[p] -= (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)));
            }
            z = v[n-1];
            y = v[0] -= (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)));
            sum -= DELTA;
        }
        while (--rounds);
    }
}
 
 
int main()
{
    int n= 58;
    uint32_t v[]={0x6ac68723,0xbc7123a7,0x64f3d87d,0x3e8c216,0x737dd747,0xb010868f,0x33030511,0x83453d34,0x508e9921,0x2bfa017a,0x824aba3e,0xb426bc88,0xe2b6bfbc,0x10e2caf7,0x4fc41d21,0x67c588f0,0xdbd13516,0x67cb17db,0x54e01fbd,0xc5b682d5,0xdccbe585,0xc51ec321,0xbb7cc296,0x158cb0e8,0x6946bfd7,0xa70879ac,0x6b1b0108,0x6996f44e,0x37b754e7,0xb3a7607,0x62c425d4,0x34f5f409,0xc2c0d008,0xe8ed6971,0xa7c57884,0x8563eaa5,0x825dea33,0xb0605bb3,0x63319346,0x2177147b,0x689899a1,0x7ba4a9cd,0x803c46d2,0xcffedda6,0xefb452d4,0x74e3dde,0xfb146cf2,0x1c01440b,0xd3f5bccc,0x6f8a379e,0x7e46972d,0x64749b9b,0xeceacb7e,0x780fe61b,0xbcaf308e,0x641f40b,0x8f0897bd,0xd5b3c7db};
    btea(v, -n);
    printf("\ndecrypted:\n");
    for(int i=0;i<232;i++){
        printf("%c",((char*)v)[i]);
    }
    return 0;
}