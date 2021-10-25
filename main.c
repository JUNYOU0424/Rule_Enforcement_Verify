#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hashfunction/aes.h"
#include "hashfunction/aes.c"
#include "hashfunction/sha1.h"
#include "hashfunction/sha1.c"

static void phex(uint8_t *str);
uint8_t Hash_CTR(uint8_t *in, uint8_t *key);//PRNG
uint8_t Hash_CBC(uint8_t *in, uint8_t *key);//PRF
uint8_t SHA1_H(char *test);
int main(void)
{
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t in[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    uint8_t session_key, VID,PktHash;
    char *vid_test = "01 00 5E 00 00 6B 00 80 63 00 09 BA 08 00 45 00 00 52 45 A5 00 00 01 11 D0 DC C0 A8 02 06 E0 00 00 6B 01 3F 01 3F 00 3E 00 00 12 02 00 36 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 63 FF FF 00 09 BA 00 01 9E 4E 05 0F 00 00 45 B1 11 55 2E 1E 67 24 00 00 00 00 00 00 00 00 00 00";
    char *packet = "00 0e 39 e3 34 00 00 16 9c 7c b0 00 08 00 45 00 00 6c 00 00 40 00 36 11 62 3a 16 74 07 41 c9 ae fa e3 26 aa 9e 43 00 58 60 98";
    //header:ip.src||ip.dst||srcport||dstport||proto
    char *header = "22.116.7.65201.174.250.22798984051517";
    //time_relative
    char *timestamp = "0.000000000";
    //eth.src
    char *inport = "00:16:9c:7c:b0:00";
    char *res = malloc(strlen(header)+strlen(timestamp)+strlen(inport)+1);
    strcpy(res,inport);
    strcat(res,header);
    strcat(res,timestamp);
    session_key = Hash_CBC(in, key);
    VID = SHA1_H(res);
    PktHash = SHA1_H(packet);
}

//turn uint8_t to string
static void phex(uint8_t *str)
{
    uint8_t len = 16;

    unsigned char i;
    printf("\t");
    for (i = 0; i < len; ++i)
    {
        printf("%.2X ", str[i]);
    }
    printf("\n");
}

uint8_t Hash_CTR(uint8_t *in, uint8_t *key)
{
    uint8_t iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, in, 64);
    printf("\t-----session key-----\n");
    phex(in);
    return *in;
}


uint8_t Hash_CBC(uint8_t *in, uint8_t *key)
{
    uint8_t iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 64);
    printf("\t-----session key-----\n");
    phex(in);
    return *in;
}

uint8_t SHA1_H(char *in)
{
    //printf((const unsigned char *)test);
    //printf("\n");
    SHA1Context sha;
    int i, j, err;
    uint8_t Message_Digest[20];
    err = SHA1Reset(&sha);
    err = SHA1Input(&sha,
                    (const unsigned char *)in,
                    strlen(in));
    if (err)
        fprintf(stderr, "SHA1Input Error %d.\n", err);
    err = SHA1Result(&sha, Message_Digest);
    if (err)
        fprintf(stderr, "SHA1Result Error %d, could not compute message digest.\n", err);
    else
    {
        printf("\t-----hashresult-----\n\t");
        for (i = 0; i < 20; ++i)
        {
            printf("%02X ", Message_Digest[i]);
        }
        printf("\n");
    }
    return *Message_Digest;
}

