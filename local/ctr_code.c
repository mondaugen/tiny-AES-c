#include "_common.h"
#include "aes.h"
#include "aes_128_ctr.h"
#include "ctr_block_cipher.h"
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_KEY "12341234123412341234123412341234"
#define DEFAULT_IV "43214321432143214321432143214321"

int main(void)
{
    uint8_t key[AES_KEYLEN], iv[AES_BLOCKLEN];
    maybe_parse_hexstr("KEY", key, AES_KEYLEN, DEFAULT_KEY);
    maybe_parse_hexstr("IV", iv, AES_BLOCKLEN, DEFAULT_IV);
    size_t len;
    struct AES_ctx ctx;
    ctr_block_cipher_t coder;
    AES_init_ctx(&ctx, key);
    ctr_block_cipher_aes_128_init(&coder, &ctx);
    coder.iv = iv;
    if (nonnull_strcmp(getenv("BLOCKWISE"), "1") == 0) {
        uint8_t inbuf[AES_BLOCKLEN], outbuf[AES_BLOCKLEN];
        fprintf(stderr, "starting encoding by blocks...\n");
        print_as_hex(stderr, coder.iv, coder.block_size);
        fprintf(stderr, "\n");
        while ((len = fread(inbuf, sizeof(uint8_t), AES_BLOCKLEN, stdin)) > 0) {
            fprintf(stderr, "read %lu bytes\n", len);
            ctr_block_cipher_enc_block(&coder, inbuf, outbuf, len);
            print_as_hex(stderr, coder.iv, coder.block_size);
            fprintf(stderr, "\n");
            fwrite(outbuf, sizeof(uint8_t), len, stdout);
        }
    } else {
        fprintf(stderr, "starting encoding in batch...\n");
        uint8_t tmp[AES_BLOCKLEN], *inbuf = NULL, *outbuf = NULL;
        size_t totlen = 0;
        while ((len = fread(tmp, sizeof(uint8_t), AES_BLOCKLEN, stdin)) > 0) {
            inbuf = realloc(inbuf, totlen + len);
            memcpy(inbuf + totlen, tmp, len);
            totlen += len;
        }
        outbuf = malloc(totlen);
        if (!outbuf) {
            goto fail;
        }
        ctr_block_cipher_enc(&coder, inbuf, outbuf, totlen);
        fwrite(outbuf, sizeof(uint8_t), totlen, stdout);
    fail:
        if (outbuf) {
            free(outbuf);
        }
        if (inbuf) {
            free(inbuf);
        }
    }
    return 0;
}
