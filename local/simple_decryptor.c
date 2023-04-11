#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include "aes.h"

#define DEFAULT_KEY "00112233445566778899aabbccddeeff"
#define DEFAULT_IV  "ffeeddccbbaa99887766554433221100"

static void my_assert(int x)
{
    if (x != 0) {
        fprintf(stderr,"got %d\n",x);
    }
    assert(x == 0);
}

static int parse_hexstr(uint8_t *key, const char *keystr, size_t keylen)
{
    if ((strlen(keystr) >> 1) != AES_KEYLEN) {
        return -1;
    }
    while (keylen-- > 0) {
        char tmp[3];
        tmp[2] = '\0';
        memcpy(tmp,keystr,2);
        uint8_t byte;
        *key++ = (uint8_t)strtol(tmp,NULL,16);
        keystr += 2;
    }
    return 0;
}

// keylen is the number of bytes in the string or one half the string length
static void maybe_parse_hexstr(const char *envname, uint8_t *output, size_t keylen, const char *default_hexstr)
{
    const char *hexstr = getenv(envname);
    if (!hexstr) {
        hexstr = default_hexstr;
    }
    my_assert(parse_hexstr(output,hexstr,keylen));
}

static void print_as_hex(FILE *fd, const uint8_t *x, size_t len)
{
    while (len-- > 0) {
        fprintf(fd,"%.2x ",*x++);
    }
}

int main (void)
{
    uint8_t key[AES_KEYLEN];
    uint8_t iv[AES_BLOCKLEN];
    memset(key,0,sizeof(key));
    memset(iv,0,sizeof(iv));
    maybe_parse_hexstr("KEY",key,AES_KEYLEN,DEFAULT_KEY);
    maybe_parse_hexstr("IV",iv,AES_BLOCKLEN,DEFAULT_IV);
    fprintf(stderr,"key is: ");
    print_as_hex(stderr,key,AES_KEYLEN);
    fprintf(stderr,"\n");
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx,key,iv);
    uint8_t block[AES_BLOCKLEN];
    while (fread(memset(block,0,AES_BLOCKLEN),sizeof(uint8_t),AES_BLOCKLEN,stdin) > 0) {
        fprintf(stderr,"decrypting ");
        print_as_hex(stderr,block,AES_BLOCKLEN);
        fprintf(stderr,"\n");
        if (strcmp(getenv("STYLE"),"ECB") == 0) {
            AES_ECB_decrypt(&ctx,block);
        } else if (strcmp(getenv("STYLE"),"CBC") == 0) {
            AES_CBC_decrypt_buffer(&ctx,block,AES_BLOCKLEN);
        } else if (strcmp(getenv("STYLE"),"CTR") == 0) {
            AES_CTR_xcrypt_buffer(&ctx,block,AES_BLOCKLEN);
        } else {
            fprintf(stderr,"STYLE %s not known\n",getenv("STYLE"));
        }
        fwrite(block,sizeof(uint8_t),AES_BLOCKLEN,stdout);
    }
    return 0;
}
