
#include <stdio.h>
#include <stdint.h>
#define DELTA 0x9e3779b9
unsigned char k[17]="it1sn0tthek3yyyy";
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
    int n= 4;
    uint32_t v[4]={0x3B466A30,0x6212AEA8,0x2FF25334,0x4F88A242};
    btea(v, -n);
    for(int i=0;i<16;i++){
        printf("%c",((char*)v)[i]);
    }
    return 0;
}