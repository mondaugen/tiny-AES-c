#include <stdlib.h>
#include <stdio.h>
#include "ctr_block_cipher.h"
#include "aes_128_ctr.h"
#include "aes.h"
#include "_common.h"

#define DEFAULT_KEY "1234123412341234"
#define DEFAULT_IV  "4321432143214321"

int main (void)
{
    uint8_t key[AES_KEYLEN], iv[AES_BLOCKLEN];
    maybe_parse_hexstr("KEY",key,AES_KEYLEN,DEFAULT_KEY);
    maybe_parse_hexstr("IV",iv,AES_BLOCKLEN,DEFAULT_IV);
    size_t len;
    uint8_t inbuf[AES_BLOCKLEN], outbuf[AES_BLOCKLEN];
    struct AES_ctx ctx;
    ctr_block_cipher_t coder;
    AES_init_ctx(&ctx,key);
    ctr_block_cipher_aes_128_init(&coder,&ctx);
    while ((len = fread(inbuf,AES_BLOCKLEN,sizeof(uint8_t),stdin)) > 0) {
        ctr_block_cipher_enc_block(&coder,inbuf,outbuf,len);
        fwrite(outbuf,len,sizeof(uint8_t),stdout);
    }
    return 0;
}

